import http from 'node:http';
import { URL } from 'node:url';
import type { TokenStore, SwapInfo } from './token-store.js';
import { DENIED_HEADER, hostMismatchBody, logSwapOutcome } from './swap-log.js';

/**
 * Hop-by-hop headers (RFC 9110 §7.6.1) that must not be forwarded, plus
 * `proxy-authorization`, which is meant for coatcheck and not the upstream.
 * `transfer-encoding` is kept: Node re-frames the piped body according to it.
 */
const HOP_BY_HOP = new Set([
  'connection', 'keep-alive', 'proxy-authenticate', 'proxy-authorization',
  'proxy-connection', 'te', 'trailer', 'upgrade',
]);

/**
 * Forward a plain-HTTP proxy request (`GET http://host/path`), swapping tickets
 * in the path, query and headers. Tickets only swap for hosts their secret is
 * bound to with an `http://` entry; otherwise the request is answered `403`
 * and never forwarded.
 */
export function handleForwardRequest(
  req: http.IncomingMessage,
  res: http.ServerResponse,
  tokenStore: TokenStore,
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
  let postSwapText = '';
  const swap = (text: string): string => {
    const r = tokenStore.replaceAll(text, target);
    swaps.push(...r.swaps);
    denied.push(...r.denied);
    postSwapText += r.output + '\n';
    return r.output;
  };

  // Only the path and query: a ticket in the host or userinfo is left as a
  // literal, so swapping can never change where the request goes.
  // A real value may hold characters Node refuses in a request path (space,
  // non-ASCII), so percent-encode those after the swap.
  const path = percentEncodeUnsafe(swap(parsed.pathname + parsed.search));
  const headers: http.OutgoingHttpHeaders = {};
  for (const [key, value] of Object.entries(stripHopByHop(req.headers))) {
    if (typeof value === 'string') headers[key] = swap(value);
    else if (Array.isArray(value)) headers[key] = value.map(swap);
  }
  headers.host = parsed.host;

  logSwapOutcome('http', hostname, { swaps, denied }, postSwapText);
  if (denied.length > 0) {
    req.resume();
    res.writeHead(403, { 'Content-Type': 'application/json', [DENIED_HEADER]: 'host-mismatch' });
    res.end(hostMismatchBody(denied, hostname));
    return;
  }

  let proxyReq: http.ClientRequest;
  try {
    proxyReq = http.request({
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
  } catch (err) {
    // http.request throws synchronously on invalid header values (e.g. a real
    // value with CR/LF); an uncaught throw here would take the process down.
    console.error('HTTP proxy request rejected:', (err as NodeJS.ErrnoException).code ?? 'unknown');
    req.resume();
    res.writeHead(502);
    res.end('Proxy error');
    return;
  }

  proxyReq.on('error', (err) => {
    console.error('HTTP proxy error:', err.message);
    res.writeHead(502);
    res.end('Proxy error');
  });

  req.pipe(proxyReq);
}

/** Percent-encode control, space and non-ASCII characters (UTF-8), leaving everything else as is. */
function percentEncodeUnsafe(path: string): string {
  // eslint-disable-next-line no-control-regex -- matching control characters is the point
  return path.replace(/[\u0000-\u0020\u007f-\uffff]+/g, run =>
    [...Buffer.from(run, 'utf8')].map(b => `%${b.toString(16).toUpperCase().padStart(2, '0')}`).join(''));
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
