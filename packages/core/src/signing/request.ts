import type { RequestHead } from '../http1-framing.js';

/**
 * A request as a signing scheme sees it (design: docs/design/signing-processors.md
 * §4.1). Built from the MITM parser's field lines or from Node's raw headers.
 */
export interface SignableRequest {
  method: string;
  /** Path and query as sent (origin-form). */
  target: string;
  /** Wire order, names as sent; values as sent after the colon (untrimmed on the MITM path). */
  headers: Array<[name: string, value: string]>;
}

/** A request and, when the scheme hashes it, its (decoded) body. */
export interface SigningView {
  request: SignableRequest;
  /** Undefined when the body wasn't buffered (the scheme said it doesn't need it). */
  body?: Buffer;
}

/** A `SignableRequest` from a parsed MITM request head (request line `METHOD target HTTP/1.1`). */
export function signableFromHead(requestLine: string, fieldLines: readonly string[]): SignableRequest {
  const [method = '', target = ''] = requestLine.split(' ');
  return {
    method,
    target,
    headers: fieldLines.map(line => {
      // parseRequestHead accepted the line, so it has a colon.
      const colon = line.indexOf(':');
      return [line.slice(0, colon), line.slice(colon + 1)];
    }),
  };
}

/** `signableFromHead` on a `RequestHead`. */
export function signableFromRequestHead(head: RequestHead): SignableRequest {
  return signableFromHead(head.requestLine, head.fieldLines);
}

/** All values of header `name` (case-insensitive), as sent, in wire order. */
export function rawHeaderValues(req: SignableRequest, name: string): string[] {
  const lower = name.toLowerCase();
  return req.headers.filter(([n]) => n.toLowerCase() === lower).map(([, v]) => v);
}

/** All values of header `name` (case-insensitive), without surrounding whitespace (SP / HTAB), in wire order. */
export function headerValues(req: SignableRequest, name: string): string[] {
  return rawHeaderValues(req, name).map(v => v.replace(/^[ \t]+|[ \t]+$/g, ''));
}

/** The first value of header `name`, trimmed. */
export function firstHeader(req: SignableRequest, name: string): string | undefined {
  return headerValues(req, name)[0];
}

/** The request's headers without any named in `names` (lowercase). */
export function withoutHeaders(req: SignableRequest, names: ReadonlySet<string>): Array<[string, string]> {
  return req.headers.filter(([n]) => !names.has(n.toLowerCase()));
}
