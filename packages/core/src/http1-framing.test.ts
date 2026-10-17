import { describe, it, expect } from 'vitest';
import { ChunkedDecoder, parseRequestHead, requestFraming, scanChunked } from './http1-framing.js';

const head = (...lines: string[]) => ['POST / HTTP/1.1', 'Host: h', ...lines].join('\r\n');

describe('requestFraming', () => {
  it('reads Content-Length, chunked, or no body', () => {
    expect(requestFraming(head('Content-Length: 12'))).toEqual({ kind: 'length', length: 12 });
    expect(requestFraming(head('transfer-encoding:  Chunked '))).toEqual({ kind: 'chunked' });
    expect(requestFraming(head())).toEqual({ kind: 'none' });
    expect(requestFraming(head('X-Content-Length: 5', 'Content-Lengthy: 9'))).toEqual({ kind: 'none' });
  });

  it.each([
    ['Content-Length: 1', 'Transfer-Encoding: chunked'],
    ['Transfer-Encoding: gzip, chunked'],
    ['Transfer-Encoding: chunked', 'Transfer-Encoding: chunked'],
    ['Transfer-Encoding: identity'],
    ['Content-Length: 1', 'Content-Length: 1'],
    ['Content-Length: 1, 1'],
    ['Content-Length: -1'],
    ['Content-Length: 9999999999999999'],
    ['Content-Length : 1'],
    ['Transfer-Encoding\t: chunked'],
    ['X-A: 1', ' continued'],
    ['no colon here'],
  ])('refuses ambiguous framing: %j', (...lines) => {
    expect(requestFraming(head(...lines)).kind).toBe('invalid');
  });
});

describe('scanChunked', () => {
  const scan = (s: string) => scanChunked(Buffer.from(`HEAD${s}`), 4);

  it('decodes chunks, ignores extensions, and returns trailers as received', () => {
    const r = scan('3;a=b\r\nabc\r\nA\r\n0123456789\r\n0\r\nX-T: 1\r\n\r\nNEXT');
    expect(r.kind).toBe('complete');
    if (r.kind !== 'complete') return;
    expect(r.data.toString()).toBe('abc0123456789');
    expect(r.trailers.toString()).toBe('X-T: 1\r\n\r\n');
    expect(r.end).toBe(Buffer.byteLength('HEAD3;a=b\r\nabc\r\nA\r\n0123456789\r\n0\r\nX-T: 1\r\n\r\n'));
  });

  it('asks for more data until the message is complete', () => {
    for (const partial of ['', '3', '3\r\nab', '3\r\nabc\r\n', '3\r\nabc\r\n0\r\n', '3\r\nabc\r\n0\r\nX-T: 1\r\n']) {
      expect(scan(partial).kind, JSON.stringify(partial)).toBe('incomplete');
    }
  });

  it.each([
    'zz\r\nab\r\n0\r\n\r\n',
    '-1\r\nab\r\n0\r\n\r\n',
    '11111111111111111\r\n',
    '2\r\nabcd\r\n0\r\n\r\n',
    '0\r\nbad trailer\r\n\r\n',
  ])('refuses malformed chunking: %j', s => {
    expect(scan(s).kind).toBe('invalid');
  });

  it('refuses an endless chunk size line', () => {
    expect(scan('1'.repeat(5000)).kind).toBe('invalid');
  });
});

describe('ChunkedDecoder', () => {
  it('decodes the same body fed one byte at a time, keeping state between calls', () => {
    const wire = Buffer.from('3;x=1\r\nabc\r\n10\r\n0123456789abcdef\r\n0\r\nX-T: 1\r\n\r\nNEXT');
    const decoder = new ChunkedDecoder();
    const data: Buffer[] = [];
    let pending = Buffer.alloc(0);
    let total = 0;
    for (const byte of wire) {
      pending = Buffer.concat([pending, Buffer.from([byte])]);
      const r = decoder.feed(pending, d => data.push(Buffer.from(d)));
      if ('error' in r) throw new Error(r.error);
      total += r.consumed;
      pending = pending.subarray(r.consumed);
      if (decoder.done) break;
    }
    expect(Buffer.concat(data).toString()).toBe('abc0123456789abcdef');
    expect(decoder.trailers.toString()).toBe('X-T: 1\r\n\r\n');
    expect(total).toBe(wire.length - 'NEXT'.length);
  });

  it('decodes thousands of records in linear time', () => {
    const chunk = Buffer.from('400\r\n' + 'a'.repeat(0x400) + '\r\n');
    const decoder = new ChunkedDecoder();
    let bytes = 0;
    const started = Date.now();
    for (let i = 0; i < 20_000; i++) {
      const r = decoder.feed(chunk, d => { bytes += d.length; });
      if ('error' in r) throw new Error(r.error);
    }
    decoder.feed(Buffer.from('0\r\n\r\n'));
    expect(decoder.done).toBe(true);
    expect(bytes).toBe(20_000 * 0x400);
    expect(Date.now() - started).toBeLessThan(2000);
  });

  it('caps the trailer section', () => {
    const r = new ChunkedDecoder().feed(Buffer.from(`0\r\nX-T: ${'a'.repeat(70 * 1024)}`));
    expect(r).toEqual({ error: 'trailer section too long' });
  });
});

describe('parseRequestHead', () => {
  it('parses the head once: request line, field lines, headers, framing', () => {
    const head = parseRequestHead('POST /x HTTP/1.1\r\nHost: h\r\nContent-Type: application/json \r\nContent-Length: 2');
    expect(head.requestLine).toBe('POST /x HTTP/1.1');
    expect(head.fieldLines).toHaveLength(3);
    expect(head.header('content-type')).toBe('application/json');
    expect(head.header('Upgrade')).toBeUndefined();
    expect(head.framing).toEqual({ kind: 'length', length: 2 });
  });
});
