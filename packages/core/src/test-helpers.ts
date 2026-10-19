/**
 * Proxy integration-test helpers (shared by `signing.server.test.ts`; the
 * same helpers live inline in `server.test.ts`, which is left as it is).
 * Test-only: excluded from the published package.
 */
import http from 'node:http';
import https from 'node:https';
import net from 'node:net';
import tls from 'node:tls';
import type { AddressInfo } from 'node:net';
import { createHash, createHmac, type Hash, type Hmac } from 'node:crypto';
import { vi } from 'vitest';
import { TokenStore } from './token-store.js';
import { CertAuthority } from './ca.js';
import { CdpSessionStore } from './cdp-session-store.js';
import { createCoatcheck, type Coatcheck, type CoatcheckDeps } from './server.js';
import { createMemoryProvider } from './memory-provider.js';
import { parseHostPattern, type HostPattern } from './host-matcher.js';

export const hosts = (...entries: string[]) => entries.map(e => parseHostPattern(e) as HostPattern);

/** Run after each test (register with `afterEach(runCleanups)`). */
export const cleanups: Array<() => Promise<void> | void> = [];
export async function runCleanups(): Promise<void> {
  for (const fn of cleanups.splice(0).reverse()) await fn();
}

let cas: { proxyCa: CertAuthority; upstreamCa: CertAuthority } | undefined;
/** The proxy's CA and the test upstreams' CA, created once per test file. */
export async function testCas(): Promise<{ proxyCa: CertAuthority; upstreamCa: CertAuthority }> {
  cas ??= {
    proxyCa: await CertAuthority.create({ subject: 'CN=proxy test CA' }),
    upstreamCa: await CertAuthority.create({ subject: 'CN=upstream test CA' }),
  };
  return cas;
}

/** Capture console output (to assert on log lines and that values never appear). */
export function captureLogs(): string[] {
  const lines: string[] = [];
  const spies = (['log', 'warn', 'error'] as const).map(m =>
    vi.spyOn(console, m).mockImplementation((...args: unknown[]) => { lines.push(args.map(String).join(' ')); }));
  cleanups.push(() => spies.forEach(sp => sp.mockRestore()));
  return lines;
}

export interface Echo { method?: string; url: string; headers: http.IncomingHttpHeaders; body?: string; rawBody?: Buffer }

/** Plain-HTTP request through the proxy (absolute-form URL). */
export function viaProxy(proxyPort: number, url: string, headers: http.OutgoingHttpHeaders = {}, method = 'GET', body?: Buffer | string) {
  return new Promise<{ status: number; headers: http.IncomingHttpHeaders; body: string }>((resolve, reject) => {
    const req = http.request({ host: '127.0.0.1', port: proxyPort, method, path: url, headers }, res => {
      let out = '';
      res.on('data', d => { out += d; });
      res.on('end', () => resolve({ status: res.statusCode ?? 0, headers: res.headers, body: out }));
    });
    req.on('error', reject);
    req.end(body);
  });
}

/** Plain-HTTP listener on loopback that records what it receives. */
export async function startHttpUpstream() {
  const received: Echo[] = [];
  const server = http.createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on('data', (d: Buffer) => chunks.push(d));
    req.on('end', () => {
      const rawBody = Buffer.concat(chunks);
      received.push({ method: req.method, url: req.url ?? '', headers: req.headers, body: rawBody.toString(), rawBody });
      res.end('ok');
    });
  });
  await new Promise<void>(r => server.listen(0, '127.0.0.1', r));
  cleanups.push(() => new Promise<void>(r => { server.closeAllConnections(); server.close(() => r()); }));
  return { port: (server.address() as AddressInfo).port, received };
}

export async function startProxy(overrides: Partial<CoatcheckDeps> = {}) {
  const { proxyCa, upstreamCa } = await testCas();
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

export type Responder = (req: http.IncomingMessage, body: Buffer, res: http.ServerResponse) => void;

/**
 * HTTPS upstream with a cert from the upstream CA for `host` (default
 * 127.0.0.1). Echoes the request as JSON, or answers with `respond`.
 * `raw` holds every byte received on its TLS connections.
 */
export async function startHttpsUpstream(respond?: Responder, host = '127.0.0.1', listenHost = '127.0.0.1') {
  const { upstreamCa } = await testCas();
  const leaf = await upstreamCa.getCertForHost(host);
  const received: Echo[] = [];
  const raw: Buffer[] = [];
  const server = https.createServer({ key: leaf.key, cert: leaf.cert }, (req, res) => {
    const chunks: Buffer[] = [];
    req.on('data', (d: Buffer) => chunks.push(d));
    req.on('end', () => {
      const rawBody = Buffer.concat(chunks);
      received.push({ method: req.method, url: req.url ?? '', headers: req.headers, body: rawBody.toString(), rawBody });
      if (respond) return respond(req, rawBody, res);
      res.setHeader('content-type', 'application/json');
      res.end(JSON.stringify({ url: req.url, headers: req.headers }));
    });
  });
  server.on('secureConnection', (s: tls.TLSSocket) => s.on('data', (d: Buffer) => raw.push(d)));
  await new Promise<void>(r => server.listen(0, listenHost, r));
  cleanups.push(() => new Promise<void>(r => { server.closeAllConnections(); server.close(() => r()); }));
  return { port: (server.address() as AddressInfo).port, received, raw };
}

/** Send CONNECT to the proxy; resolve with the status line and the raw socket. */
export function connect(proxyPort: number, target: string): Promise<{ status: string; socket: net.Socket }> {
  return new Promise((resolve, reject) => {
    const socket = net.connect(proxyPort, '127.0.0.1', () => {
      socket.write(`CONNECT ${target} HTTP/1.1\r\nHost: ${target}\r\n\r\n`);
    });
    cleanups.push(() => { socket.destroy(); });
    socket.once('data', d => resolve({ status: d.toString().split('\r\n')[0], socket }));
    socket.once('error', reject);
  });
}

export function startTls(socket: net.Socket, ca: string, servername = '127.0.0.1'): Promise<tls.TLSSocket> {
  return new Promise((resolve, reject) => {
    const t = tls.connect({ socket, ca, host: servername, ...(net.isIP(servername) ? {} : { servername }) }, () => resolve(t));
    t.once('error', reject);
  });
}

/** Read `n` Content-Length-framed HTTP responses from a stream. */
export function readResponses(stream: NodeJS.ReadableStream, n: number): Promise<Array<{ head: string; body: string }>> {
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

/** Resolve when `stream` ends or closes. */
export function closed(stream: NodeJS.EventEmitter): Promise<void> {
  return new Promise(resolve => { stream.once('close', () => resolve()); stream.once('end', () => resolve()); });
}

/** `@smithy/signature-v4`'s hash constructor over node:crypto (the independent signer's hashing). */
export class Sha256 {
  private h: Hash | Hmac;
  constructor(secret?: string | ArrayBuffer | ArrayBufferView) {
    this.h = secret === undefined ? createHash('sha256') : createHmac('sha256', toBuf(secret));
  }
  update(data: string | ArrayBuffer | ArrayBufferView) { this.h.update(toBuf(data)); }
  digest() { return Promise.resolve(new Uint8Array(this.h.digest())); }
  reset() { /* single use */ }
}
function toBuf(d: string | ArrayBuffer | ArrayBufferView): Buffer {
  if (typeof d === 'string') return Buffer.from(d, 'utf8');
  if (ArrayBuffer.isView(d)) return Buffer.from(d.buffer, d.byteOffset, d.byteLength);
  return Buffer.from(d);
}
