import http from 'node:http';
import { URL } from 'node:url';
import type { TokenStore, SwapInfo } from './token-store.js';
import { DENIED_HEADER, hostMismatchBody, invalidValueBody, logBodyUnscanned, logSwapOutcome } from './swap-log.js';
import { swapRequestBody } from './body-swap.js';
import { headerFieldValue, percentEncodeUnsafe } from './value-encoding.js';

/**
 * Hop-by-hop headers (RFC 9110 §7.6.1) that must not be forwarded, plus
 * `proxy-authorization`, which is meant for coatcheck and not the upstream.
 * `transfer-encoding` is kept for a streamed body: Node re-frames the piped
 * body according to it. A swapped body is re-sent with `Content-Length`.
 */
const HOP_BY_HOP = new Set([
  'connection', 'keep-alive', 'proxy-authenticate', 'proxy-authorization',
  'proxy-connection', 'te', 'trailer', 'upgrade',
]);

/**
 * Forward a plain-HTTP proxy request (`GET http://host/path`), swapping tickets
 * in the path, query and headers, and in the body for secrets that opt in
 * (`swap_body`). Tickets only swap for hosts their secret is bound to with an
 * `http://` entry; otherwise the request is answered `403` and never forwarded.
 * The body streams unless a `swap_body` ticket could apply; then it is
 * buffered up to `maxSwapBodyBytes` (design §3, "Swap-path hardening").
 */
export function handleForwardRequest(
  req: http.IncomingMessage,
  res: http.ServerResponse,
  tokenStore: TokenStore,
  maxSwapBodyBytes: number,
): void {
  let parsed: URL | null = null;
  try {
    parsed = new URL(req.url ?? '');
  } catch {
    // fall through
  }
  if (!parsed || parsed.protocol !== 'http:') {
    res.writeHead(400);
    res.end('Bad request');
    return;
  }

  // The WHATWG-parsed hostname is the host that is dialled, so it is the key.
  const hostname = parsed.hostname;
  const target = { host: hostname, scheme: 'http' as const };
  const swaps: SwapInfo[] = [];
  const denied: SwapInfo[] = [];
  const invalid: SwapInfo[] = [];
  let postSwapText = '';
  const swap = (text: string, encode: (value: string) => string | null): string => {
    const r = tokenStore.replaceAll(text, target, encode);
    swaps.push(...r.swaps);
    denied.push(...r.denied);
    invalid.push(...(r.invalid ?? []));
    postSwapText += r.output + '\n';
    return r.output;
  };

  // Only the path and query: a ticket in the host or userinfo is left as a
  // literal, so swapping can never change where the request goes.
  // A real value may hold characters Node refuses in a request path (space,
  // non-ASCII), so those are percent-encoded; one that can't be a header value
  // (control characters) refuses the request.
  const path = swap(parsed.pathname + parsed.search, percentEncodeUnsafe);
  const headers: http.OutgoingHttpHeaders = {};
  for (const [key, value] of Object.entries(stripHopByHop(req.headers))) {
    if (typeof value === 'string') headers[key] = swap(value, headerFieldValue);
    else if (Array.isArray(value)) headers[key] = value.map(v => swap(v, headerFieldValue));
  }
  headers.host = parsed.host;

  const deny = () => {
    req.resume();
    if (denied.length > 0) {
      res.writeHead(403, { 'Content-Type': 'application/json', [DENIED_HEADER]: 'host-mismatch' });
      res.end(hostMismatchBody(denied, hostname));
    } else {
      res.writeHead(403, { 'Content-Type': 'application/json', [DENIED_HEADER]: 'invalid-value' });
      res.end(invalidValueBody(invalid));
    }
  };
  if (denied.length > 0 || invalid.length > 0) {
    logSwapOutcome('http', hostname, { swaps, denied, invalid }, postSwapText);
    deny();
    return;
  }

  const send = (): http.ClientRequest | null => {
    try {
      const proxyReq = http.request({
        // WHATWG keeps IPv6 brackets in `hostname`; the dialler needs the bare address.
        hostname: hostname.replace(/^\[(.*)\]$/, '$1'),
        port: parsed.port || 80,
        path,
        method: req.method,
        headers,
      }, (proxyRes) => {
        res.writeHead(proxyRes.statusCode ?? 502, proxyRes.headers);
        proxyRes.pipe(res);
      });
      proxyReq.on('error', (err) => {
        console.error('HTTP proxy error:', err.message);
        if (!res.headersSent) res.writeHead(502);
        res.end('Proxy error');
      });
      return proxyReq;
    } catch (err) {
      // http.request throws synchronously on invalid header values Node
      // refuses beyond the check above (e.g. characters above U+00FF); an
      // uncaught throw here would take the process down.
      console.error('HTTP proxy request rejected:', (err as NodeJS.ErrnoException).code ?? 'unknown');
      req.resume();
      res.writeHead(502);
      res.end('Proxy error');
      return null;
    }
  };

  const hasBody = req.headers['content-length'] !== undefined || req.headers['transfer-encoding'] !== undefined;
  if (!hasBody || !tokenStore.hasLiveBodyTicketFor(target)) {
    logSwapOutcome('http', hostname, { swaps, denied }, postSwapText);
    const proxyReq = send();
    if (proxyReq) req.pipe(proxyReq);
    return;
  }

  // A body ticket could apply: buffer the body (up to the cap) to swap it.
  const chunks: Buffer[] = [];
  let bytes = 0;
  const onData = (chunk: Buffer) => {
    chunks.push(chunk);
    bytes += chunk.length;
    if (bytes <= maxSwapBodyBytes) return;
    // Too large to hold: send what we have and stream the rest unscanned,
    // with the client's framing.
    req.off('data', onData);
    req.off('end', onEnd);
    logSwapOutcome('http', hostname, { swaps, denied }, postSwapText);
    logBodyUnscanned('http', hostname, maxSwapBodyBytes);
    const proxyReq = send();
    if (!proxyReq) return;
    for (const c of chunks) proxyReq.write(c);
    req.pipe(proxyReq);
  };
  const onEnd = () => {
    let body: Buffer = Buffer.concat(chunks);
    let skipped: SwapInfo[] | undefined;
    const bodySwap = swapRequestBody(tokenStore, body, {
      contentType: firstHeader(req.headers['content-type']),
      contentEncoding: firstHeader(req.headers['content-encoding']),
    }, target);
    if (bodySwap) {
      swaps.push(...bodySwap.result.swaps);
      denied.push(...bodySwap.result.denied);
      skipped = bodySwap.result.skipped;
      postSwapText += bodySwap.result.output;
      body = bodySwap.body;
    }
    logSwapOutcome('http', hostname, { swaps, denied, skipped }, postSwapText);
    if (denied.length > 0) {
      deny();
      return;
    }
    // Node de-chunked the body; re-send it with an exact length.
    delete headers['transfer-encoding'];
    headers['content-length'] = body.length;
    send()?.end(body);
  };
  req.on('data', onData);
  req.on('end', onEnd);
  req.on('error', () => res.destroy());
}

function firstHeader(value: string | string[] | undefined): string | undefined {
  return Array.isArray(value) ? value[0] : value;
}

function stripHopByHop(headers: http.IncomingHttpHeaders): http.IncomingHttpHeaders {
  // Headers named in Connection are hop-by-hop too.
  const named = new Set(
    String(headers.connection ?? '').split(',').map(h => h.trim().toLowerCase()).filter(Boolean),
  );
  const out: http.IncomingHttpHeaders = {};
  for (const [key, value] of Object.entries(headers)) {
    if (!HOP_BY_HOP.has(key) && !named.has(key)) out[key] = value;
  }
  return out;
}
