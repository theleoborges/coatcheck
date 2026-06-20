import { describe, it, expect } from 'vitest';
import { createConnectUrlRewriter } from './browserbase-rewrite.js';

function httpResponse(body: string): Buffer {
  const head =
    'HTTP/1.1 200 OK\r\n' +
    'Content-Type: application/json\r\n' +
    `Content-Length: ${Buffer.byteLength(body)}\r\n` +
    '\r\n';
  return Buffer.from(head + body);
}

function chunkedResponse(body: string): Buffer {
  const hex = Buffer.byteLength(body).toString(16);
  const head =
    'HTTP/1.1 200 OK\r\n' +
    'Content-Type: application/json\r\n' +
    'Transfer-Encoding: chunked\r\n' +
    '\r\n';
  return Buffer.from(head + `${hex}\r\n${body}\r\n0\r\n\r\n`);
}

function parseBody(out: Buffer): unknown {
  const s = out.toString();
  const idx = s.indexOf('\r\n\r\n');
  return JSON.parse(s.slice(idx + 4));
}

describe('createConnectUrlRewriter', () => {
  const rewrite = () => 'ws://127.0.0.1:8444/cdp/abc123';

  it('rewrites connectUrl in a Content-Length response', () => {
    const r = createConnectUrlRewriter(rewrite);
    const body = JSON.stringify({ id: 'sess', connectUrl: 'wss://connect.browserbase.com/x?signingKey=SECRET' });
    const out = r.push(httpResponse(body));
    const parsed = parseBody(out) as { connectUrl: string };
    expect(parsed.connectUrl).toBe('ws://127.0.0.1:8444/cdp/abc123');
    // the real signing key is gone
    expect(out.toString()).not.toContain('signingKey=SECRET');
    // Content-Length updated to match new body
    const cl = parseInt(out.toString().match(/content-length:\s*(\d+)/i)![1], 10);
    expect(cl).toBe(JSON.stringify(parsed).length);
  });

  it('rewrites connectUrl in a chunked response and re-frames as Content-Length', () => {
    const r = createConnectUrlRewriter(rewrite);
    const body = JSON.stringify({ id: 'sess', connectUrl: 'wss://connect.browserbase.com/x?signingKey=SECRET' });
    const out = r.push(chunkedResponse(body));
    const parsed = parseBody(out) as { connectUrl: string };
    expect(parsed.connectUrl).toBe('ws://127.0.0.1:8444/cdp/abc123');
    expect(out.toString().toLowerCase()).not.toContain('transfer-encoding');
    expect(out.toString()).toContain('Content-Length:');
  });

  it('handles a response split across multiple chunks', () => {
    const r = createConnectUrlRewriter(rewrite);
    const body = JSON.stringify({ connectUrl: 'wss://connect.browserbase.com/x' });
    const full = httpResponse(body);
    const mid = Math.floor(full.length / 2);

    const out1 = r.push(full.subarray(0, mid));
    const out2 = r.push(full.subarray(mid));
    const combined = Buffer.concat([out1, out2]);
    const parsed = parseBody(combined) as { connectUrl: string };
    expect(parsed.connectUrl).toBe('ws://127.0.0.1:8444/cdp/abc123');
  });

  it('passes through a response with no connectUrl unchanged', () => {
    const r = createConnectUrlRewriter(rewrite);
    const body = JSON.stringify({ id: 'sess', status: 'RUNNING' });
    const input = httpResponse(body);
    const out = r.push(input);
    expect(out.equals(input)).toBe(true);
  });
});
