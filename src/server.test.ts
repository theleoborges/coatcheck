import { describe, it, expect, beforeAll, afterEach, vi } from 'vitest';
import fs from 'node:fs';
import http from 'node:http';
import https from 'node:https';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import tls from 'node:tls';
import { X509Certificate } from 'node:crypto';
import type { AddressInfo } from 'node:net';
import { TokenStore } from './token-store.js';
import { CertAuthority } from './ca.js';
import { CdpSessionStore } from './cdp-session-store.js';
import { createCoatcheck, type Coatcheck, type CoatcheckDeps } from './server.js';

interface Echo { url: string; headers: http.IncomingHttpHeaders }

let proxyCa: CertAuthority;
let upstreamCa: CertAuthority;
const cleanups: Array<() => Promise<void> | void> = [];

beforeAll(async () => {
  proxyCa = await CertAuthority.create({ subject: 'CN=proxy test CA' });
  upstreamCa = await CertAuthority.create({ subject: 'CN=upstream test CA' });
});

afterEach(async () => {
  for (const fn of cleanups.splice(0).reverse()) await fn();
});

async function startProxy(overrides: Partial<CoatcheckDeps> = {}) {
  const tokenStore = new TokenStore();
  const cdpSessionStore = new CdpSessionStore();
  const coatcheck: Coatcheck = createCoatcheck({
    tokenStore,
    secretFetcher: {} as CoatcheckDeps['secretFetcher'],
    ca: proxyCa,
    cdpSessionStore,
    upstreamCa: upstreamCa.caCertPem,
    ...overrides,
  });
  const { port } = await coatcheck.listen(0, '127.0.0.1');
  cleanups.push(() => { tokenStore.destroy(); cdpSessionStore.destroy(); }, () => coatcheck.close());
  return { tokenStore, cdpSessionStore, port };
}

/** HTTPS upstream on 127.0.0.1 with a cert from `upstreamCa`. Echoes the request, or serves `body`. */
async function startHttpsUpstream(body?: string) {
  const leaf = await upstreamCa.getCertForHost('127.0.0.1');
  const received: Echo[] = [];
  let tlsConnections = 0;
  const server = https.createServer({ key: leaf.key, cert: leaf.cert }, (req, res) => {
    received.push({ url: req.url ?? '', headers: req.headers });
    res.setHeader('content-type', 'application/json');
    res.end(body ?? JSON.stringify({ url: req.url, headers: req.headers }));
  });
  server.on('secureConnection', () => { tlsConnections++; });
  await new Promise<void>(r => server.listen(0, '127.0.0.1', r));
  cleanups.push(() => new Promise<void>(r => { server.closeAllConnections(); server.close(() => r()); }));
  return { port: (server.address() as AddressInfo).port, received, connections: () => tlsConnections };
}

/** Send CONNECT to the proxy; resolve with the status line and the raw socket. */
function connect(proxyPort: number, target: string): Promise<{ status: string; socket: net.Socket }> {
  return new Promise((resolve, reject) => {
    const socket = net.connect(proxyPort, '127.0.0.1', () => {
      socket.write(`CONNECT ${target} HTTP/1.1\r\nHost: ${target}\r\n\r\n`);
    });
    cleanups.push(() => { socket.destroy(); });
    socket.once('data', d => resolve({ status: d.toString().split('\r\n')[0], socket }));
    socket.once('error', reject);
  });
}

function startTls(socket: net.Socket, ca: string): Promise<tls.TLSSocket> {
  return new Promise((resolve, reject) => {
    const t = tls.connect({ socket, ca, host: '127.0.0.1' }, () => resolve(t));
    t.once('error', reject);
  });
}

/** Read `n` Content-Length-framed HTTP responses from a stream. */
function readResponses(stream: NodeJS.ReadableStream, n: number): Promise<Array<{ head: string; body: string }>> {
  return new Promise((resolve, reject) => {
    let buf = Buffer.alloc(0);
    const out: Array<{ head: string; body: string }> = [];
    const onData = (chunk: Buffer) => {
      buf = Buffer.concat([buf, chunk]);
      for (;;) {
        const end = buf.indexOf('\r\n\r\n');
        if (end === -1) return;
        const head = buf.subarray(0, end).toString();
        const len = parseInt(/content-length:\s*(\d+)/i.exec(head)?.[1] ?? '0', 10);
        if (buf.length < end + 4 + len) return;
        out.push({ head, body: buf.subarray(end + 4, end + 4 + len).toString() });
        buf = buf.subarray(end + 4 + len);
        if (out.length === n) {
          stream.off('data', onData);
          resolve(out);
          return;
        }
      }
    };
    stream.on('data', onData);
    stream.once('error', reject);
    stream.once('end', () => { if (out.length < n) reject(new Error(`stream ended after ${out.length} responses`)); });
  });
}

const issuerCn = (sock: tls.TLSSocket) => new X509Certificate(sock.getPeerX509Certificate()!.raw).issuer;

describe('coatcheck server: CONNECT', () => {
  it('rejects CONNECT targets carrying shell metacharacters with 400 and runs nothing', async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'coatcheck-attack-'));
    cleanups.push(() => fs.rmSync(dir, { recursive: true, force: true }));
    const marker = path.join(dir, 'pwned');
    const { tokenStore, port } = await startProxy();
    tokenStore.issue('k', 'v'); // non-empty store: the old code path would have reached openssl

    for (const target of [`$(touch ${marker}).com:443`, `\`touch ${marker}\`.com:443`, '../../tmp/x:443']) {
      const { status } = await connect(port, target);
      expect(status, target).toBe('HTTP/1.1 400 Bad Request');
    }
    expect(fs.existsSync(marker)).toBe(false);
  });

  it('tunnels without MITM when no tickets are live', async () => {
    const upstream = await startHttpsUpstream();
    const { port } = await startProxy();

    const { status, socket } = await connect(port, `127.0.0.1:${upstream.port}`);
    expect(status).toBe('HTTP/1.1 200 Connection Established');
    const t = await startTls(socket, upstreamCa.caCertPem); // trusts only the upstream CA
    expect(issuerCn(t)).toContain('CN=upstream test CA');

    t.write('GET /x HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer tok_literal\r\n\r\n');
    const [res] = await readResponses(t, 1);
    expect((JSON.parse(res.body) as Echo).headers.authorization).toBe('Bearer tok_literal');
  });

  it('MITMs when tickets are live and swaps tickets on every keep-alive request', async () => {
    const upstream = await startHttpsUpstream();
    const { tokenStore, port } = await startProxy();
    const t1 = tokenStore.issue('api-key', 'real-api-key').id;
    const t2 = tokenStore.issue('other', 'real-other').id;

    const { status, socket } = await connect(port, `127.0.0.1:${upstream.port}`);
    expect(status).toBe('HTTP/1.1 200 Connection Established');
    const t = await startTls(socket, proxyCa.caCertPem); // trusts only coatcheck's CA
    expect(issuerCn(t)).toContain('CN=proxy test CA');

    const responses = readResponses(t, 2);
    t.write(`GET /a?key=${t1} HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer ${t1}\r\n\r\n`);
    t.write(`POST /b HTTP/1.1\r\nHost: 127.0.0.1\r\nX-Api-Key: ${t2}\r\nContent-Length: 5\r\n\r\nhello`);
    const [r1, r2] = await responses;

    const e1 = JSON.parse(r1.body) as Echo;
    expect(e1.url).toBe('/a?key=real-api-key');
    expect(e1.headers.authorization).toBe('Bearer real-api-key');
    expect((JSON.parse(r2.body) as Echo).headers['x-api-key']).toBe('real-other');
    expect(upstream.received).toHaveLength(2);
    expect(upstream.connections()).toBe(1);
  });

  it('does not deliver a swapped request to an upstream whose certificate is untrusted', async () => {
    const upstream = await startHttpsUpstream();
    const { tokenStore, port } = await startProxy({ upstreamCa: undefined }); // Node root store only
    const tok = tokenStore.issue('api-key', 'real-api-key').id;
    const errors = vi.spyOn(console, 'error').mockImplementation(() => {});
    cleanups.push(() => errors.mockRestore());

    const { socket } = await connect(port, `127.0.0.1:${upstream.port}`);
    const t = await startTls(socket, proxyCa.caCertPem);
    t.write(`GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer ${tok}\r\n\r\n`);
    await new Promise(r => t.once('close', r));
    expect(upstream.received).toHaveLength(0);
  });

  it('rewrites the browser connectUrl to the local CDP proxy when CDP is enabled', async () => {
    const upstream = await startHttpsUpstream(JSON.stringify({ id: 's1', connectUrl: 'wss://connect.example.test/s1?signingKey=secret' }));
    const { tokenStore, cdpSessionStore, port } = await startProxy({
      cdp: { port: 8444, advertiseHost: '127.0.0.1' },
      browserbaseApiHost: '127.0.0.1',
    });
    const tok = tokenStore.issue('browser-api-key', 'real-key').id;

    const { socket } = await connect(port, `127.0.0.1:${upstream.port}`);
    const t = await startTls(socket, proxyCa.caCertPem);
    t.write(`POST /v1/sessions HTTP/1.1\r\nHost: 127.0.0.1\r\nX-BB-API-Key: ${tok}\r\nContent-Length: 0\r\n\r\n`);
    const [res] = await readResponses(t, 1);

    const body = JSON.parse(res.body) as { id: string; connectUrl: string };
    expect(body.id).toBe('s1');
    const m = /^ws:\/\/127\.0\.0\.1:8444\/cdp\/([a-f0-9]+)$/.exec(body.connectUrl);
    expect(m).not.toBeNull();
    expect(cdpSessionStore.get(m![1])).toBe('wss://connect.example.test/s1?signingKey=secret');
    expect(res.body).not.toContain('signingKey');
  });

  it('leaves the connectUrl alone when CDP is disabled', async () => {
    const real = JSON.stringify({ connectUrl: 'wss://connect.example.test/s1' });
    const upstream = await startHttpsUpstream(real);
    const { tokenStore, port } = await startProxy({ browserbaseApiHost: '127.0.0.1' });
    tokenStore.issue('k', 'v');

    const { socket } = await connect(port, `127.0.0.1:${upstream.port}`);
    const t = await startTls(socket, proxyCa.caCertPem);
    t.write('GET / HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n');
    const [res] = await readResponses(t, 1);
    expect(res.body).toBe(real);
  });
});

describe('coatcheck server: plain HTTP', () => {
  it('forwards requests and swaps tickets in the URL and headers', async () => {
    const received: Echo[] = [];
    const upstream = http.createServer((req, res) => {
      received.push({ url: req.url ?? '', headers: req.headers });
      res.end('ok');
    });
    await new Promise<void>(r => upstream.listen(0, '127.0.0.1', r));
    cleanups.push(() => new Promise<void>(r => upstream.close(() => r())));
    const upPort = (upstream.address() as AddressInfo).port;

    const { tokenStore, port } = await startProxy();
    const tok = tokenStore.issue('api-key', 'real-api-key').id;

    const status = await new Promise<number>((resolve, reject) => {
      const req = http.request({
        host: '127.0.0.1', port, method: 'GET',
        path: `http://127.0.0.1:${upPort}/p?key=${tok}`,
        headers: { authorization: `Bearer ${tok}` },
      }, res => { res.resume(); res.on('end', () => resolve(res.statusCode ?? 0)); });
      req.on('error', reject);
      req.end();
    });

    expect(status).toBe(200);
    expect(received[0].url).toBe('/p?key=real-api-key');
    expect(received[0].headers.authorization).toBe('Bearer real-api-key');
  });

  it('serves the vault API on the same listener', async () => {
    const { port } = await startProxy();
    const res = await fetch(`http://127.0.0.1:${port}/_health`);
    expect(await res.json()).toEqual({ status: 'ok', tokens_active: 0 });
    const ca = await (await fetch(`http://127.0.0.1:${port}/_ca`)).text();
    expect(ca).toBe(proxyCa.caCertPem);
  });
});
