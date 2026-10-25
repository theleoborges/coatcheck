import { describe, it, expect, afterEach } from 'vitest';
import tls from 'node:tls';
import { gzipSync } from 'node:zlib';
import type { AddressInfo } from 'node:net';
import { captureLogs, cleanups, closed, connect, readResponses, runCleanups, startProxy, startTls, testCas } from './test-helpers.js';

/**
 * Browser-adapter response rewriting through the MITM path, against an
 * upstream that answers with exact bytes: every response on a keep-alive
 * tunnel to the adapter host is rewritten, whatever came before it, and one
 * the rewriter can't inspect closes the tunnel instead of passing through.
 */

afterEach(runCleanups);

const REAL = 'wss://connect.browserbase.com/debug/s1/devtools/browser/B1';
const debugBody = JSON.stringify({ wsUrl: REAL, signingKey: 'SK', seleniumRemoteUrl: 'http://connect.browserbase.com/webdriver' });
const cdp = { cdp: { port: 8444, advertiseHost: '127.0.0.1' }, browserbaseApiHost: '127.0.0.1' };

function cl(body: string | Buffer, extra = ''): Buffer {
  const b = Buffer.from(body);
  return Buffer.concat([Buffer.from(`HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n${extra}Content-Length: ${b.length}\r\n\r\n`), b]);
}

/**
 * Raw TLS upstream: reads bodiless requests off each connection and answers
 * each with `respond(requestLine, headers)`; `close` ends the connection after it.
 */
async function startRawUpstream(respond: (requestLine: string, head: string) => { bytes: Buffer; close?: boolean }) {
  const { upstreamCa } = await testCas();
  const leaf = await upstreamCa.getCertForHost('127.0.0.1');
  const server = tls.createServer({ key: leaf.key, cert: leaf.cert }, sock => {
    let buf = Buffer.alloc(0);
    sock.on('data', (d: Buffer) => {
      buf = Buffer.concat([buf, d]);
      for (;;) {
        const end = buf.indexOf('\r\n\r\n');
        if (end === -1) return;
        const head = buf.subarray(0, end).toString();
        buf = buf.subarray(end + 4);
        const r = respond(head.split('\r\n')[0], head);
        if (r.close) {
          sock.end(r.bytes);
          return;
        }
        sock.write(r.bytes);
      }
    });
    sock.on('error', () => {});
  });
  await new Promise<void>(r => server.listen(0, '127.0.0.1', r));
  cleanups.push(() => new Promise<void>(r => server.close(() => r())));
  return (server.address() as AddressInfo).port;
}

async function tunnel(proxyOverrides: Parameters<typeof startProxy>[0] = cdp, upstreamPort: number) {
  const { port } = await startProxy(proxyOverrides);
  const { proxyCa } = await testCas();
  const { socket } = await connect(port, `127.0.0.1:${upstreamPort}`);
  return startTls(socket, proxyCa.caCertPem);
}

function expectNoBrowserRoute(body: string) {
  expect(body).not.toContain('browserbase.com');
  expect(body).not.toContain('SK');
  expect(JSON.parse(body)).toMatchObject({ wsUrl: expect.stringMatching(/^ws:\/\/127\.0\.0\.1:8444\/cdp\/[a-f0-9]+$/) });
}

const debugRequest = 'GET /v1/sessions/s1/debug HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n';

// Attack (security review, finding 1): on one keep-alive tunnel the agent
// sends a request whose response has no body framing (a HEAD, a 204/304, or an
// `Expect: 100-continue` interim response). The rewriter used to switch to
// passthrough for the rest of the tunnel, so the debug endpoint's raw CDP URL
// and signingKey then reached the agent: a direct route to the browser, from
// which it can watch a broker login fill the real password.
describe('adapter responses after a bodiless response on the same tunnel', () => {
  const poisons: Array<{ name: string; request: string; response: string }> = [
    { name: 'HEAD', request: 'HEAD /v1/sessions HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n', response: 'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n' },
    { name: '204', request: 'DELETE /v1/x HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n', response: 'HTTP/1.1 204 No Content\r\n\r\n' },
    { name: '304', request: 'GET /v1/x HTTP/1.1\r\nHost: 127.0.0.1\r\nIf-None-Match: "a"\r\n\r\n', response: 'HTTP/1.1 304 Not Modified\r\n\r\n' },
    { name: '100 Continue', request: 'GET /v1/x HTTP/1.1\r\nHost: 127.0.0.1\r\nExpect: 100-continue\r\n\r\n', response: 'HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}' },
  ];
  for (const p of poisons) {
    it(`are still rewritten after a ${p.name} response`, async () => {
      const upstream = await startRawUpstream(line => ({ bytes: line.includes('/debug') ? cl(debugBody) : Buffer.from(p.response) }));
      const t = await tunnel(cdp, upstream);
      t.write(p.request);
      t.write(debugRequest);
      const responses = await readResponses(t, p.name === '100 Continue' ? 3 : 2);
      expectNoBrowserRoute(responses[responses.length - 1].body);
    });
  }
});

// Attack: the agent asks for a compressed response (`Accept-Encoding: gzip`);
// gzipped JSON used to fail to parse and pass through with the raw CDP URL.
it('rewrites a gzip-encoded adapter response', async () => {
  const upstream = await startRawUpstream(() => ({ bytes: cl(gzipSync(debugBody), 'Content-Encoding: gzip\r\n') }));
  const t = await tunnel(cdp, upstream);
  t.write('GET /v1/sessions/s1/debug HTTP/1.1\r\nHost: 127.0.0.1\r\nAccept-Encoding: gzip\r\n\r\n');
  const [res] = await readResponses(t, 1);
  expect(res.head.toLowerCase()).not.toContain('content-encoding');
  expectNoBrowserRoute(res.body);
});

it('rewrites a close-delimited adapter response', async () => {
  const upstream = await startRawUpstream(() => ({ bytes: Buffer.from(`HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n${debugBody}`), close: true }));
  const t = await tunnel(cdp, upstream);
  t.write(debugRequest);
  const [res] = await readResponses(t, 1);
  expectNoBrowserRoute(res.body);
});

describe('refuses an adapter response it cannot inspect, and closes the tunnel', () => {
  const cases: Array<[string, Buffer, Parameters<typeof startProxy>[0]]> = [
    ['unknown content coding', cl(debugBody, 'Content-Encoding: compress\r\n'), cdp],
    ['over COATCHECK_MAX_SWAP_BODY_BYTES', cl(JSON.stringify({ wsUrl: REAL, pad: 'x'.repeat(4096) })), { ...cdp, maxSwapBodyBytes: 1024 }],
  ];
  for (const [name, bytes, overrides] of cases) {
    it(name, async () => {
      const logs = captureLogs();
      const upstream = await startRawUpstream(() => ({ bytes }));
      const t = await tunnel(overrides, upstream);
      let received = '';
      t.on('data', (d: Buffer) => { received += d.toString(); });
      t.write(debugRequest);
      await closed(t);
      expect(received).toMatch(/^HTTP\/1\.1 502 Bad Gateway\r\n/);
      expect(received).toContain('uninspectable-response');
      expect(received).not.toContain('browserbase.com');
      expect(logs).toContainEqual(expect.stringContaining('refused response: not inspectable'));
    });
  }
});
