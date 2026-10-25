/**
 * Rewrites JSON bodies on an HTTP/1.1 response stream: the vendor-neutral
 * framing behind browser adapters (design: v1-decisions.md §6). Adapters
 * supply only the JSON transform.
 *
 * A small streaming response parser that frames each response as RFC 9112
 * §6.3 does: a HEAD response, 1xx, 204 and 304 have no body (a 1xx is interim:
 * the final response follows); `chunked` bodies are decoded and re-emitted as
 * Content-Length so the transform sees the whole document; Content-Length
 * bodies are rewritten in place; a body with neither is read until the
 * upstream closes. Content-coded bodies (gzip, deflate, br, zstd) are decoded
 * for the transform. The rewriter stays in step across every keep-alive
 * response on the connection: nothing an agent can make the upstream send
 * turns it off.
 *
 * Fail closed: a response it can't frame or decode, or one larger than
 * `maxBodyBytes`, throws `UninspectableResponseError` and nothing of it is
 * returned (the caller ends the connection), since forwarding it raw could
 * hand the agent an unrewritten CDP URL.
 */

import zlib from 'node:zlib';

export interface JsonResponseRewriter {
  /**
   * Note a request sent upstream on this connection, in order. Its method
   * frames the response: the answer to a HEAD has no body. Without a call,
   * a response is framed as the answer to a GET.
   */
  request(method: string): void;
  /**
   * Feed raw response bytes; returns the (possibly rewritten) bytes to forward.
   * Throws `UninspectableResponseError` for a response it can't inspect.
   */
  push(chunk: Buffer): Buffer;
  /**
   * The upstream closed: returns the close-delimited response being read, if
   * any, rewritten. A response cut short is dropped, never forwarded raw.
   */
  end(): Buffer;
}

export interface JsonResponseRewriterOptions {
  /** Largest response body held for the transform (decoded, if content-coded). Default: unlimited. */
  maxBodyBytes?: number;
}

/** A response the rewriter can't inspect; nothing of it has been returned. */
export class UninspectableResponseError extends Error {
  constructor(readonly reason: string) {
    super(`response not inspectable: ${reason}`);
    this.name = 'UninspectableResponseError';
  }
}

/** Mutates the parsed body in place; returns true if anything changed. */
export type JsonTransform = (body: unknown) => boolean;

/** A response header section that hasn't ended within this many bytes is refused. */
const MAX_RESPONSE_HEAD_BYTES = 64 * 1024;

const DECODERS: Record<string, (buf: Buffer, opts: { maxOutputLength?: number }) => Buffer> = {
  gzip: zlib.gunzipSync,
  'x-gzip': zlib.gunzipSync,
  deflate: zlib.inflateSync,
  br: zlib.brotliDecompressSync,
  zstd: zlib.zstdDecompressSync,
};

export function createJsonResponseRewriter(transform: JsonTransform, opts: JsonResponseRewriterOptions = {}): JsonResponseRewriter {
  const maxBodyBytes = opts.maxBodyBytes ?? Infinity;
  let buf = Buffer.alloc(0);
  /** Methods of requests sent and not yet answered by a final response. */
  const methods: string[] = [];
  /** Set once a response's body runs until the upstream closes (or after a 101). */
  let untilClose: { headerStr: string; headers: Map<string, string[]> } | null = null;
  let rawPipe = false;

  function fail(reason: string): never {
    buf = Buffer.alloc(0);
    throw new UninspectableResponseError(reason);
  }

  /** The body the transform reads: decoded per Content-Encoding (outermost coding last). */
  function decodeBody(headers: Map<string, string[]>, body: Buffer): Buffer {
    const codings = (headers.get('content-encoding') ?? [])
      .flatMap(v => v.split(','))
      .map(c => c.trim().toLowerCase())
      .filter(c => c !== '' && c !== 'identity');
    let out = body;
    for (const coding of codings.reverse()) {
      const decode = DECODERS[coding];
      if (!decode) fail(`content-encoding ${coding}`);
      try {
        // maxOutputLength bounds a compression bomb at the body cap.
        out = decode(out, Number.isFinite(maxBodyBytes) ? { maxOutputLength: maxBodyBytes } : {});
      } catch {
        fail(`undecodable ${coding} body`);
      }
    }
    return out;
  }

  function rewriteOne(headerStr: string, headers: Map<string, string[]>, body: Buffer, forceContentLength: boolean): Buffer {
    const decoded = decodeBody(headers, body);
    let outBody = body;
    let changed = false;
    try {
      const parsed: unknown = JSON.parse(decoded.toString());
      if (transform(parsed)) {
        outBody = Buffer.from(JSON.stringify(parsed));
        changed = true;
      }
    } catch {
      // not JSON — leave body as-is
    }

    if (!changed && !forceContentLength) {
      return Buffer.concat([Buffer.from(headerStr + '\r\n\r\n', 'latin1'), body]);
    }

    // Rebuild headers: set the new Content-Length and drop chunked framing (and
    // the content coding, when the rewritten body is sent decoded).
    const lines = headerStr.split('\r\n');
    const kept: string[] = [lines[0]];
    for (const line of lines.slice(1)) {
      const lower = line.toLowerCase();
      if (lower.startsWith('content-length:') || lower.startsWith('transfer-encoding:')) continue;
      if (changed && lower.startsWith('content-encoding:')) continue;
      kept.push(line);
    }
    kept.push(`Content-Length: ${outBody.length}`);
    return Buffer.concat([Buffer.from(kept.join('\r\n') + '\r\n\r\n', 'latin1'), outBody]);
  }

  return {
    request(method: string): void {
      methods.push(method.toUpperCase());
    },

    push(chunk: Buffer): Buffer {
      if (rawPipe) return chunk;
      buf = Buffer.concat([buf, chunk]);
      if (untilClose) {
        if (buf.length > maxBodyBytes) fail(`larger than ${maxBodyBytes} bytes`);
        return Buffer.alloc(0);
      }
      const out: Buffer[] = [];

      for (;;) {
        const headerEnd = buf.indexOf('\r\n\r\n');
        if (headerEnd === -1) {
          if (buf.length > MAX_RESPONSE_HEAD_BYTES) fail('header section too large');
          break; // need more header bytes
        }
        if (headerEnd > MAX_RESPONSE_HEAD_BYTES) fail('header section too large');

        const headerStr = buf.subarray(0, headerEnd).toString('latin1');
        const status = /^HTTP\/1\.[01] (\d{3})(?:[ \r]|$)/.exec(headerStr)?.[1];
        if (!status) fail('malformed status line');
        const headers = parseHeaders(headerStr);
        const bodyStart = headerEnd + 4;

        if (status === '101') {
          // Switching protocols: the rest of the connection isn't HTTP.
          rawPipe = true;
          out.push(buf);
          buf = Buffer.alloc(0);
          break;
        }
        if (status.startsWith('1')) {
          // Interim (100 Continue, 103 Early Hints): the final response follows.
          out.push(buf.subarray(0, bodyStart));
          buf = buf.subarray(bodyStart);
          continue;
        }

        const method = methods.shift() ?? 'GET';
        if (method === 'HEAD' || status === '204' || status === '304') {
          out.push(buf.subarray(0, bodyStart));
          buf = buf.subarray(bodyStart);
          continue;
        }

        const te = headers.get('transfer-encoding');
        const cl = headers.get('content-length');
        if (te) {
          if (te.length !== 1 || te[0].toLowerCase() !== 'chunked') fail(`transfer-encoding ${te.join(', ')}`);
          const parsed = readChunkedBody(buf, bodyStart, maxBodyBytes);
          if (parsed === 'invalid') fail('bad chunked framing');
          if (parsed === 'too-large') fail(`larger than ${maxBodyBytes} bytes`);
          if (!parsed) {
            methods.unshift(method);
            break; // need more body bytes
          }
          out.push(rewriteOne(headerStr, headers, parsed.body, true));
          buf = buf.subarray(parsed.end);
          continue;
        }

        if (cl === undefined) {
          // Close-delimited: the body is everything until the upstream closes.
          untilClose = { headerStr, headers };
          buf = buf.subarray(bodyStart);
          if (buf.length > maxBodyBytes) fail(`larger than ${maxBodyBytes} bytes`);
          break;
        }

        if (cl.length !== 1 || !/^\d+$/.test(cl[0])) fail('bad content-length');
        const contentLength = Number(cl[0]);
        if (contentLength > maxBodyBytes) fail(`larger than ${maxBodyBytes} bytes`);
        const total = bodyStart + contentLength;
        if (buf.length < total) {
          methods.unshift(method);
          break; // need more body bytes
        }
        out.push(rewriteOne(headerStr, headers, buf.subarray(bodyStart, total), false));
        buf = buf.subarray(total);
      }

      return Buffer.concat(out);
    },

    end(): Buffer {
      if (rawPipe || !untilClose) return Buffer.alloc(0);
      // A compliant upstream answers nothing after a close-delimited body, so a
      // request sent after it means these bytes could hold that answer too.
      if (methods.length > 0) fail('request sent after a close-delimited response');
      const { headerStr, headers } = untilClose;
      const body = buf;
      untilClose = null;
      buf = Buffer.alloc(0);
      return rewriteOne(headerStr, headers, body, true);
    },
  };
}

/** Header values by lowercase name, in order (a repeated header keeps every value). */
function parseHeaders(headerStr: string): Map<string, string[]> {
  const headers = new Map<string, string[]>();
  for (const line of headerStr.split('\r\n').slice(1)) {
    const idx = line.indexOf(':');
    if (idx === -1) continue;
    const name = line.slice(0, idx).trim().toLowerCase();
    headers.set(name, [...(headers.get(name) ?? []), line.slice(idx + 1).trim()]);
  }
  return headers;
}

/**
 * Decode a chunked body starting at `start`; returns the assembled body and
 * the byte index just past the trailer section, null if incomplete,
 * 'invalid' for bad framing, or 'too-large' past `maxBytes` of data.
 */
function readChunkedBody(buf: Buffer, start: number, maxBytes: number): { body: Buffer; end: number } | null | 'invalid' | 'too-large' {
  const parts: Buffer[] = [];
  let total = 0;
  let pos = start;
  for (;;) {
    const lineEnd = buf.indexOf('\r\n', pos);
    if (lineEnd === -1) return buf.length - pos > 1024 ? 'invalid' : null;
    const sizeStr = buf.subarray(pos, lineEnd).toString('latin1').split(';')[0].trim();
    if (!/^[0-9a-fA-F]{1,8}$/.test(sizeStr)) return 'invalid';
    const size = parseInt(sizeStr, 16);
    const dataStart = lineEnd + 2;
    if (size === 0) {
      // Last chunk, then the trailer section: field lines up to an empty line.
      if (buf.length < dataStart + 2) return null;
      if (buf[dataStart] === 0x0d && buf[dataStart + 1] === 0x0a) return { body: Buffer.concat(parts), end: dataStart + 2 };
      const trailersEnd = buf.indexOf('\r\n\r\n', dataStart);
      if (trailersEnd === -1) return buf.length - dataStart > MAX_RESPONSE_HEAD_BYTES ? 'invalid' : null;
      return { body: Buffer.concat(parts), end: trailersEnd + 4 };
    }
    total += size;
    if (total > maxBytes) return 'too-large';
    const dataEnd = dataStart + size;
    if (buf.length < dataEnd + 2) return null; // need data + trailing CRLF
    if (buf[dataEnd] !== 0x0d || buf[dataEnd + 1] !== 0x0a) return 'invalid';
    parts.push(buf.subarray(dataStart, dataEnd));
    pos = dataEnd + 2; // skip the chunk's trailing CRLF
  }
}
