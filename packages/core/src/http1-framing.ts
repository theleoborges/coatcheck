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

/** A request head parsed once: request line, header lines, framing. */
export interface RequestHead {
  requestLine: string;
  /** Header lines as received (`Name: value`), without line endings. */
  fieldLines: string[];
  framing: Framing;
  /** The first value of header `name` (case-insensitive), trimmed. */
  header(name: string): string | undefined;
}

/** Parse a header section (without the final CRLFCRLF). */
export function parseRequestHead(head: string): RequestHead {
  const [requestLine, ...fieldLines] = head.split('\r\n');
  const fields: Array<[string, string]> = [];
  let malformed = false;
  for (const line of fieldLines) {
    if (!HEADER_LINE.test(line)) {
      malformed = true;
      break;
    }
    const colon = line.indexOf(':');
    fields.push([line.slice(0, colon).toLowerCase(), line.slice(colon + 1).trim()]);
  }
  return {
    requestLine,
    fieldLines,
    framing: malformed ? { kind: 'invalid', reason: 'malformed header line' } : framingOf(fields),
    header: name => fields.find(([n]) => n === name.toLowerCase())?.[1],
  };
}

/** How the body of the request whose header section is `head` (no final CRLFCRLF) is framed. */
export function requestFraming(head: string): Framing {
  return parseRequestHead(head).framing;
}

function framingOf(fields: Array<[string, string]>): Framing {
  const te = fields.filter(([n]) => n === 'transfer-encoding').map(([, v]) => v);
  const cl = fields.filter(([n]) => n === 'content-length').map(([, v]) => v);
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
const MAX_TRAILER_BYTES = 64 * 1024;

/**
 * Incremental chunked-body decoder. State is kept between `feed` calls, so a
 * body arriving in many TLS records is decoded in linear time.
 */
export class ChunkedDecoder {
  private state: 'size' | 'data' | 'data-crlf' | 'trailers' | 'done' = 'size';
  private remaining = 0;
  private trailerParts: Buffer[] = [];
  private trailerBytes = 0;

  get done(): boolean {
    return this.state === 'done';
  }

  /** The trailer section as received, including its final CRLF (once `done`). */
  get trailers(): Buffer {
    return Buffer.concat(this.trailerParts);
  }

  /**
   * Decode from the start of `buf`. Returns how many bytes were consumed (a
   * prefix of `buf`; an incomplete line is left for the next call), or the
   * reason the framing is invalid. Decoded data goes to `onData`.
   */
  feed(buf: Buffer, onData?: (data: Buffer) => void): { consumed: number } | { error: string } {
    let pos = 0;
    while (this.state !== 'done') {
      if (this.state === 'size') {
        const lineEnd = buf.indexOf('\r\n', pos);
        const lineLength = (lineEnd === -1 ? buf.length : lineEnd) - pos;
        if (lineLength > MAX_SIZE_LINE) return { error: 'chunk size line too long' };
        if (lineEnd === -1) break;
        // chunk-size [ chunk-ext ]; extensions are ignored.
        const sizeHex = /^([0-9A-Fa-f]{1,16})(?:[ \t]*;.*)?$/.exec(buf.subarray(pos, lineEnd).toString('latin1'))?.[1];
        if (sizeHex === undefined) return { error: 'malformed chunk size' };
        const size = parseInt(sizeHex, 16);
        if (!Number.isSafeInteger(size)) return { error: 'chunk too large' };
        pos = lineEnd + 2;
        if (size === 0) {
          this.state = 'trailers';
        } else {
          this.remaining = size;
          this.state = 'data';
        }
      } else if (this.state === 'data') {
        const n = Math.min(this.remaining, buf.length - pos);
        if (n === 0) break;
        onData?.(buf.subarray(pos, pos + n));
        pos += n;
        this.remaining -= n;
        if (this.remaining === 0) this.state = 'data-crlf';
      } else if (this.state === 'data-crlf') {
        if (buf.length - pos < 2) break;
        if (buf[pos] !== 0x0d || buf[pos + 1] !== 0x0a) return { error: 'chunk data not followed by CRLF' };
        pos += 2;
        this.state = 'size';
      } else {
        // Trailer section: header lines up to an empty line.
        const lineEnd = buf.indexOf('\r\n', pos);
        const lineLength = (lineEnd === -1 ? buf.length : lineEnd) - pos;
        if (this.trailerBytes + lineLength > MAX_TRAILER_BYTES) return { error: 'trailer section too long' };
        if (lineEnd === -1) break;
        if (lineEnd > pos && !HEADER_LINE.test(buf.subarray(pos, lineEnd).toString('latin1'))) {
          return { error: 'malformed trailer line' };
        }
        this.trailerParts.push(buf.subarray(pos, lineEnd + 2));
        this.trailerBytes += lineLength + 2;
        if (lineEnd === pos) this.state = 'done';
        pos = lineEnd + 2;
      }
    }
    return { consumed: pos };
  }
}

/** Scan a whole chunked body starting at `start` in `buf`. */
export function scanChunked(buf: Buffer, start: number): ChunkedScan {
  const decoder = new ChunkedDecoder();
  const parts: Buffer[] = [];
  const r = decoder.feed(buf.subarray(start), d => parts.push(d));
  if ('error' in r) return { kind: 'invalid', reason: r.error };
  if (!decoder.done) return { kind: 'incomplete' };
  return { kind: 'complete', end: start + r.consumed, data: Buffer.concat(parts), trailers: decoder.trailers };
}
