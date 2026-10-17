/**
 * HTTP/1.1 request framing for the MITM parser (RFC 9112 §6). Ambiguous
 * framing is refused rather than normalised: coatcheck can't know how the
 * upstream will read it (design §5, "Request framing details").
 */

export type Framing =
  | { kind: 'none' }
  | { kind: 'length'; length: number }
  | { kind: 'chunked' }
  | { kind: 'invalid'; reason: string };

/** A header line: `token ":" value`. No whitespace before the colon, no obs-fold. */
const HEADER_LINE = /^[!#$%&'*+.^_`|~0-9A-Za-z-]+:/;

/** How the body of the request whose header section is `head` (no final CRLFCRLF) is framed. */
export function requestFraming(head: string): Framing {
  const lines = head.split('\r\n').slice(1); // drop the request line
  const te: string[] = [];
  const cl: string[] = [];
  for (const line of lines) {
    if (!HEADER_LINE.test(line)) return { kind: 'invalid', reason: 'malformed header line' };
    const colon = line.indexOf(':');
    const name = line.slice(0, colon).toLowerCase();
    const value = line.slice(colon + 1).trim();
    if (name === 'transfer-encoding') te.push(value);
    else if (name === 'content-length') cl.push(value);
  }
  if (te.length > 0 && cl.length > 0) return { kind: 'invalid', reason: 'both Transfer-Encoding and Content-Length' };
  if (te.length > 0) {
    if (te.length > 1 || te[0].toLowerCase() !== 'chunked') {
      return { kind: 'invalid', reason: 'unsupported Transfer-Encoding' };
    }
    return { kind: 'chunked' };
  }
  if (cl.length > 1) return { kind: 'invalid', reason: 'repeated Content-Length' };
  if (cl.length === 1) {
    if (!/^\d{1,15}$/.test(cl[0])) return { kind: 'invalid', reason: 'invalid Content-Length' };
    return { kind: 'length', length: parseInt(cl[0], 10) };
  }
  return { kind: 'none' };
}

export type ChunkedScan =
  | { kind: 'incomplete' }
  | { kind: 'invalid'; reason: string }
  /**
   * `end`: offset just past the message (after the trailer section).
   * `data`: the decoded body. `trailers`: the trailer section as received,
   * including its final CRLF.
   */
  | { kind: 'complete'; end: number; data: Buffer; trailers: Buffer };

const MAX_SIZE_LINE = 4096;

/** Scan a chunked body starting at `start` in `buf`. */
export function scanChunked(buf: Buffer, start: number): ChunkedScan {
  const parts: Buffer[] = [];
  let pos = start;
  for (;;) {
    const lineEnd = buf.indexOf('\r\n', pos);
    if (lineEnd === -1) {
      return buf.length - pos > MAX_SIZE_LINE ? { kind: 'invalid', reason: 'chunk size line too long' } : { kind: 'incomplete' };
    }
    if (lineEnd - pos > MAX_SIZE_LINE) return { kind: 'invalid', reason: 'chunk size line too long' };
    // chunk-size [ chunk-ext ]; extensions are ignored.
    const sizeHex = /^([0-9A-Fa-f]{1,16})(?:[ \t]*;.*)?$/.exec(buf.subarray(pos, lineEnd).toString('latin1'))?.[1];
    if (sizeHex === undefined) return { kind: 'invalid', reason: 'malformed chunk size' };
    const size = parseInt(sizeHex, 16);
    if (!Number.isSafeInteger(size)) return { kind: 'invalid', reason: 'chunk too large' };
    pos = lineEnd + 2;

    if (size === 0) {
      // Trailer section: header lines up to an empty line.
      const trailerStart = pos;
      for (;;) {
        const end = buf.indexOf('\r\n', pos);
        if (end === -1) return { kind: 'incomplete' };
        if (end === pos) {
          return { kind: 'complete', end: end + 2, data: Buffer.concat(parts), trailers: buf.subarray(trailerStart, end + 2) };
        }
        if (!HEADER_LINE.test(buf.subarray(pos, end).toString('latin1'))) {
          return { kind: 'invalid', reason: 'malformed trailer line' };
        }
        pos = end + 2;
      }
    }

    if (buf.length < pos + size + 2) return { kind: 'incomplete' };
    if (buf[pos + size] !== 0x0d || buf[pos + size + 1] !== 0x0a) {
      return { kind: 'invalid', reason: 'chunk data not followed by CRLF' };
    }
    parts.push(buf.subarray(pos, pos + size));
    pos += size + 2;
  }
}

/** The value of the first `name` header in a header section (request line first), trimmed. */
export function headerValue(head: string, name: string): string | undefined {
  const lower = name.toLowerCase();
  for (const line of head.split('\r\n').slice(1)) {
    const colon = line.indexOf(':');
    if (colon > 0 && line.slice(0, colon).toLowerCase() === lower) return line.slice(colon + 1).trim();
  }
  return undefined;
}
