/**
 * Rewrites the `connectUrl` in Browserbase REST responses so the agent's
 * Playwright client connects to the local CDP proxy instead of dialling
 * Browserbase directly.
 *
 * This sits on the MITM response leg for `api.browserbase.com`. A session-create
 * response looks like `{ "id": "...", "connectUrl": "wss://connect.browserbase.com/..." }`;
 * we swap `connectUrl` for `ws://127.0.0.1:{port}/cdp/{sid}` (the `rewriteUrl`
 * callback registers the real URL and returns the local one). The real signing
 * key in the upstream URL therefore never reaches the agent.
 *
 * The rewriter is a small streaming HTTP/1.1 response parser: Browserbase
 * responses are Content-Length-framed JSON, but we also decode `chunked` bodies
 * (re-emitting them as Content-Length) so the connectUrl is rewritten either way.
 * Anything it can't frame, it passes through untouched.
 */

export interface ConnectUrlRewriter {
  /** Feed raw response bytes; returns the (possibly rewritten) bytes to forward. */
  push(chunk: Buffer): Buffer;
}

export function createConnectUrlRewriter(rewriteUrl: (realConnectUrl: string) => string): ConnectUrlRewriter {
  let buf = Buffer.alloc(0);
  let passthrough = false;

  function rewriteOne(headerStr: string, body: Buffer, forceContentLength: boolean): Buffer {
    let outBody = body;
    let changed = false;
    try {
      const parsed = JSON.parse(body.toString());
      if (replaceConnectUrls(parsed, rewriteUrl)) {
        outBody = Buffer.from(JSON.stringify(parsed));
        changed = true;
      }
    } catch {
      // not JSON — leave body as-is
    }

    if (!changed && !forceContentLength) {
      return Buffer.concat([Buffer.from(headerStr + '\r\n\r\n'), body]);
    }

    // Rebuild headers: set the new Content-Length and drop chunked framing.
    const lines = headerStr.split('\r\n');
    const statusLine = lines[0];
    const kept: string[] = [statusLine];
    for (const line of lines.slice(1)) {
      const lower = line.toLowerCase();
      if (lower.startsWith('content-length:') || lower.startsWith('transfer-encoding:')) continue;
      kept.push(line);
    }
    kept.push(`Content-Length: ${outBody.length}`);
    return Buffer.concat([Buffer.from(kept.join('\r\n') + '\r\n\r\n'), outBody]);
  }

  return {
    push(chunk: Buffer): Buffer {
      if (passthrough) return chunk;
      buf = Buffer.concat([buf, chunk]);
      const out: Buffer[] = [];

      for (;;) {
        const headerEnd = buf.indexOf('\r\n\r\n');
        if (headerEnd === -1) break; // need more header bytes

        const headerStr = buf.subarray(0, headerEnd).toString();
        const headers = parseHeaders(headerStr);
        const te = headers['transfer-encoding'];
        const cl = headers['content-length'];

        if (te && te.toLowerCase().includes('chunked')) {
          const parsed = readChunkedBody(buf, headerEnd + 4);
          if (!parsed) break; // need more body bytes
          out.push(rewriteOne(headerStr, parsed.body, true));
          buf = buf.subarray(parsed.end);
          continue;
        }

        if (cl === undefined) {
          // No framing we understand — flush everything raw and stop parsing.
          passthrough = true;
          out.push(buf);
          buf = Buffer.alloc(0);
          break;
        }

        const contentLength = parseInt(cl, 10);
        const total = headerEnd + 4 + contentLength;
        if (buf.length < total) break; // need more body bytes
        const body = buf.subarray(headerEnd + 4, total);
        out.push(rewriteOne(headerStr, body, false));
        buf = buf.subarray(total);
      }

      return Buffer.concat(out);
    },
  };
}

function parseHeaders(headerStr: string): Record<string, string> {
  const headers: Record<string, string> = {};
  for (const line of headerStr.split('\r\n').slice(1)) {
    const idx = line.indexOf(':');
    if (idx === -1) continue;
    headers[line.slice(0, idx).trim().toLowerCase()] = line.slice(idx + 1).trim();
  }
  return headers;
}

/** Decode a chunked body starting at `start`; returns the assembled body and the byte index just past the terminator, or null if incomplete. */
function readChunkedBody(buf: Buffer, start: number): { body: Buffer; end: number } | null {
  const parts: Buffer[] = [];
  let pos = start;
  for (;;) {
    const lineEnd = buf.indexOf('\r\n', pos);
    if (lineEnd === -1) return null;
    const sizeStr = buf.subarray(pos, lineEnd).toString().split(';')[0].trim();
    const size = parseInt(sizeStr, 16);
    if (Number.isNaN(size)) return null;
    const dataStart = lineEnd + 2;
    if (size === 0) {
      // final chunk; consume trailing CRLF (and any trailers up to the blank line)
      const termEnd = buf.indexOf('\r\n', dataStart);
      if (termEnd === -1) return null;
      return { body: Buffer.concat(parts), end: termEnd + 2 };
    }
    const dataEnd = dataStart + size;
    if (buf.length < dataEnd + 2) return null; // need data + trailing CRLF
    parts.push(buf.subarray(dataStart, dataEnd));
    pos = dataEnd + 2; // skip the chunk's trailing CRLF
  }
}

/** Recursively replace every `connectUrl` string value. Returns true if any changed. */
function replaceConnectUrls(obj: unknown, rewriteUrl: (url: string) => string): boolean {
  if (obj === null || typeof obj !== 'object') return false;
  let changed = false;
  const record = obj as Record<string, unknown>;
  for (const k of Object.keys(record)) {
    const v = record[k];
    if (k === 'connectUrl' && typeof v === 'string') {
      record[k] = rewriteUrl(v);
      changed = true;
    } else if (v !== null && typeof v === 'object') {
      if (replaceConnectUrls(v, rewriteUrl)) changed = true;
    }
  }
  return changed;
}
