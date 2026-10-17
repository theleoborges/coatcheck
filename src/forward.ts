import http from 'node:http';
import { URL } from 'node:url';
import type { TokenStore, SwapInfo } from './token-store.js';
import { logSwapOutcome } from './swap-log.js';

/** Forward a plain-HTTP proxy request (`GET http://host/path`), swapping tickets in the URL and headers. */
export function handleForwardRequest(
  req: http.IncomingMessage,
  res: http.ServerResponse,
  tokenStore: TokenStore,
): void {
  const targetUrl = req.url;
  if (!targetUrl || !targetUrl.startsWith('http')) {
    res.writeHead(400);
    res.end('Bad request');
    return;
  }

  const parsed = new URL(targetUrl);

  const proxyReq = http.request({
    hostname: parsed.hostname,
    port: parsed.port || 80,
    path: parsed.pathname + parsed.search,
    method: req.method,
    headers: { ...req.headers, host: parsed.host },
  }, (proxyRes) => {
    res.writeHead(proxyRes.statusCode ?? 502, proxyRes.headers);
    proxyRes.pipe(res);
  });

  proxyReq.on('error', (err) => {
    console.error('HTTP proxy error:', err.message);
    res.writeHead(502);
    res.end('Proxy error');
  });

  // Swap tokens in the outbound HTTP request
  // For HTTP we can modify headers and URL in-place
  swapTokensInRequest(proxyReq, parsed, tokenStore);

  req.pipe(proxyReq);
}

function swapTokensInRequest(proxyReq: http.ClientRequest, parsed: URL, tokenStore: TokenStore): void {
  const allSwaps: SwapInfo[] = [];
  let postSwapBytes = '';

  // Swap tokens in URL (query params)
  const urlResult = tokenStore.replaceAll(parsed.href);
  postSwapBytes += urlResult.output;
  if (urlResult.output !== parsed.href) {
    const newParsed = new URL(urlResult.output);
    proxyReq.path = newParsed.pathname + newParsed.search;
    allSwaps.push(...urlResult.swaps);
  }

  // Swap tokens in headers
  const headers = proxyReq.getHeaders();
  for (const [key, value] of Object.entries(headers)) {
    if (typeof value === 'string') {
      const headerResult = tokenStore.replaceAll(value);
      postSwapBytes += '\n' + headerResult.output;
      if (headerResult.output !== value) {
        proxyReq.setHeader(key, headerResult.output);
        allSwaps.push(...headerResult.swaps);
      }
    }
  }

  logSwapOutcome('http', parsed.hostname, allSwaps, postSwapBytes);
}
