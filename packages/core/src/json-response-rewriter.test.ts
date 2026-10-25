import { describe, it, expect } from 'vitest';
import { brotliCompressSync, gzipSync } from 'node:zlib';
import { createJsonResponseRewriter, UninspectableResponseError, type JsonResponseRewriter } from './json-response-rewriter.js';

const REAL = 'wss://connect.browserbase.com/secret-session';
const LOCAL = 'ws://127.0.0.1:8444/cdp/local';

/** Rewrites `connectUrl` and deletes `signingKey`, like the Browserbase adapter. */
function rewriter(maxBodyBytes?: number): JsonResponseRewriter {
  return createJsonResponseRewriter(body => {
    const b = body as Record<string, unknown>;
    if (typeof b.connectUrl !== 'string') return false;
    b.connectUrl = LOCAL;
    delete b.signingKey;
    return true;
  }, { maxBodyBytes });
}

const sessionBody = JSON.stringify({ id: 's1', connectUrl: REAL, signingKey: 'SK' });

function clResponse(body: string | Buffer, extra = ''): Buffer {
  const b = Buffer.from(body);
  return Buffer.concat([Buffer.from(`HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n${extra}Content-Length: ${b.length}\r\n\r\n`), b]);
}

function chunked(body: string, trailers = ''): Buffer {
  return Buffer.from(`HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n${Buffer.byteLength(body).toString(16)}\r\n${body}\r\n0\r\n${trailers}\r\n`);
}

function expectRewritten(out: Buffer) {
  const s = out.toString();
  expect(s).toContain(LOCAL);
  expect(s).not.toContain(REAL);
  expect(s).not.toContain('SK');
}

describe('createJsonResponseRewriter', () => {
  // Attack (security review, finding 1): a response with no body framing used
  // to switch the rewriter to passthrough for the rest of the tunnel, so the
  // next session/debug response reached the agent with raw CDP URLs.
  describe('stays in step after a bodiless response on the same connection', () => {
    const poisons: Array<{ name: string; method: string; response: string }> = [
      { name: 'HEAD without Content-Length', method: 'HEAD', response: 'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n' },
      { name: 'HEAD with Content-Length (no body follows)', method: 'HEAD', response: 'HTTP/1.1 200 OK\r\nContent-Length: 61\r\n\r\n' },
      { name: 'HEAD with chunked (no body follows)', method: 'HEAD', response: 'HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n' },
      { name: '204', method: 'DELETE', response: 'HTTP/1.1 204 No Content\r\n\r\n' },
      { name: '304', method: 'GET', response: 'HTTP/1.1 304 Not Modified\r\nETag: "x"\r\n\r\n' },
    ];
    for (const p of poisons) {
      it(p.name, () => {
        const r = rewriter();
        r.request(p.method);
        r.request('GET');
        const out = r.push(Buffer.concat([Buffer.from(p.response), clResponse(sessionBody)]));
        expect(out.subarray(0, p.response.length).toString()).toBe(p.response);
        expectRewritten(out.subarray(p.response.length));
      });
    }

    it('100 Continue and 103 Early Hints before the final response', () => {
      const r = rewriter();
      r.request('POST');
      const interim = 'HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 103 Early Hints\r\nLink: </x>\r\n\r\n';
      const out = r.push(Buffer.concat([Buffer.from(interim), clResponse(sessionBody)]));
      expect(out.subarray(0, interim.length).toString()).toBe(interim);
      expectRewritten(out);
      // And the next response is still parsed.
      r.request('GET');
      expectRewritten(r.push(clResponse(sessionBody)));
    });

    it('a status line without a reason phrase', () => {
      const r = rewriter();
      r.request('DELETE');
      r.request('GET');
      expectRewritten(r.push(Buffer.concat([Buffer.from('HTTP/1.1 204\r\n\r\n'), clResponse(sessionBody)])));
    });

    it('fed one byte at a time', () => {
      const r = rewriter();
      r.request('HEAD');
      r.request('GET');
      const all = Buffer.concat([Buffer.from('HTTP/1.1 200 OK\r\n\r\n'), chunked(sessionBody, 'X-T: 1\r\n'), Buffer.from('HTTP/1.1 204 No Content\r\n\r\n')]);
      const out: Buffer[] = [];
      for (let i = 0; i < all.length; i++) out.push(r.push(all.subarray(i, i + 1)));
      expectRewritten(Buffer.concat(out));
    });
  });

  it('rewrites a close-delimited body when the upstream closes', () => {
    const r = rewriter();
    r.request('GET');
    expect(r.push(Buffer.from(`HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n${sessionBody}`)).length).toBe(0);
    const out = r.end();
    expectRewritten(out);
    expect(out.toString()).toMatch(/Content-Length: \d+/);
  });

  it('refuses a close-delimited body when a later request was sent on the connection', () => {
    const r = rewriter();
    r.request('GET');
    r.push(Buffer.from('HTTP/1.1 200 OK\r\n\r\n{"a":1}'));
    r.request('GET');
    r.push(clResponse(sessionBody));
    expect(() => r.end()).toThrow(UninspectableResponseError);
  });

  it('drops a response cut short by the upstream closing', () => {
    const r = rewriter();
    r.request('GET');
    const full = clResponse(sessionBody);
    expect(r.push(full.subarray(0, full.length - 5)).length).toBe(0);
    expect(r.end().length).toBe(0);
  });

  it('handles chunked trailers and keeps parsing after them', () => {
    const r = rewriter();
    r.request('GET');
    r.request('GET');
    const out = r.push(Buffer.concat([chunked(sessionBody, 'X-A: 1\r\nX-B: 2\r\n'), clResponse(sessionBody)]));
    expect(out.toString().match(new RegExp(LOCAL, 'g'))).toHaveLength(2);
    expect(out.toString()).not.toContain('X-A');
  });

  // Attack: the agent sends `Accept-Encoding: gzip`, and a compressed body
  // used to fail JSON.parse and pass through with the raw CDP URL inside.
  it.each([
    ['gzip', gzipSync],
    ['br', brotliCompressSync],
  ] as const)('decodes a %s body for the transform and sends the rewrite decoded', (coding, compress) => {
    const r = rewriter();
    r.request('GET');
    const out = r.push(clResponse(compress(Buffer.from(sessionBody)), `Content-Encoding: ${coding}\r\n`));
    expectRewritten(out);
    expect(out.toString().toLowerCase()).not.toContain('content-encoding');
  });

  it('forwards a compressed body it did not change as received', () => {
    const r = rewriter();
    r.request('GET');
    const input = clResponse(gzipSync(Buffer.from('{"id":"s1"}')), 'Content-Encoding: gzip\r\n');
    expect(r.push(input).equals(input)).toBe(true);
  });

  describe('fails closed on a response it cannot inspect', () => {
    const cases: Array<[string, Buffer]> = [
      ['an unknown content coding', clResponse(sessionBody, 'Content-Encoding: compress\r\n')],
      ['a body that does not decode', clResponse('not gzip', 'Content-Encoding: gzip\r\n')],
      ['a non-chunked transfer coding', Buffer.from('HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip, chunked\r\n\r\n')],
      ['a non-numeric Content-Length', Buffer.from('HTTP/1.1 200 OK\r\nContent-Length: abc\r\n\r\n')],
      ['a repeated Content-Length', Buffer.from('HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Length: 3\r\n\r\n{}')],
      ['a bad chunk size', Buffer.from('HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nzz\r\n')],
      ['a malformed status line', Buffer.from('HTTP/2 200\r\n\r\n')],
    ];
    for (const [name, input] of cases) {
      it(name, () => {
        const r = rewriter();
        r.request('GET');
        expect(() => r.push(input)).toThrow(UninspectableResponseError);
      });
    }
  });

  // Security review finding 4: responses are held whole, so the hold is capped.
  describe('caps the body it holds', () => {
    const big = JSON.stringify({ connectUrl: REAL, pad: 'x'.repeat(2048) });
    it.each([
      ['Content-Length', clResponse(big)],
      ['chunked', chunked(big)],
      ['close-delimited', Buffer.from(`HTTP/1.1 200 OK\r\n\r\n${big}`)],
      ['decoded size (compression bomb)', clResponse(gzipSync(Buffer.alloc(1024 * 1024, 0x20)), 'Content-Encoding: gzip\r\n')],
    ])('%s', (_name, input) => {
      const r = rewriter(1024);
      r.request('GET');
      expect(() => r.push(input)).toThrow(/larger than 1024 bytes|undecodable/);
    });

    it('refuses a header section that never ends', () => {
      const r = rewriter();
      expect(() => r.push(Buffer.from(`HTTP/1.1 200 OK\r\nX: ${'a'.repeat(70 * 1024)}`))).toThrow(UninspectableResponseError);
    });
  });
});
