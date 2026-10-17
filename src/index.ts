import http from 'node:http';
import net from 'node:net';
import tls from 'node:tls';
import { URL } from 'node:url';
import { TokenStore, TOKEN_LITERAL_PATTERN, type SwapInfo } from './token-store.js';
import { SecretFetcher } from './secret-fetcher.js';
import { CertAuthority, type HostCert } from './ca.js';
import { handleVaultRequest } from './vault-handler.js';
import { CdpSessionStore } from './cdp-session-store.js';
import { startCdpProxy } from './cdp/proxy.js';
import { createConnectUrlRewriter } from './browserbase-rewrite.js';
import { parseConnectTarget } from './connect-target.js';

const PROXY_PORT = parseInt(process.env.PROXY_PORT ?? '3128', 10);
const AGENT_LABEL = process.env.AGENT_LABEL;

// CDP credential injection: when enabled, the sidecar runs a CDP WebSocket proxy
// and rewrites Browserbase `connectUrl`s to route the agent's browser session
// through it. Off by default for a flag-gated rollout.
const CDP_PROXY_ENABLED = process.env.CDP_PROXY_ENABLED === '1';
const CDP_PROXY_PORT = parseInt(process.env.CDP_PROXY_PORT ?? '8444', 10);
// Host the agent's Playwright client uses to reach the CDP proxy. In prod the
// sidecar shares the task's network namespace, so 127.0.0.1 is correct. In
// docker-compose dev the agent/client is a separate container reaching the proxy
// via a published port or service name — override with CDP_PROXY_ADVERTISE_HOST.
const CDP_PROXY_ADVERTISE_HOST = process.env.CDP_PROXY_ADVERTISE_HOST ?? '127.0.0.1';
const BROWSERBASE_API_HOST = 'api.browserbase.com';

if (!AGENT_LABEL) {
  console.error('AGENT_LABEL is required');
  process.exit(1);
}

const tokenStore = new TokenStore();
const secretFetcher = new SecretFetcher(AGENT_LABEL);
// CA_DIR unset: ephemeral in-memory CA. Set: the CA key + cert persist there.
const ca = await CertAuthority.create({ dir: process.env.CA_DIR });
const cdpSessionStore = new CdpSessionStore();
const vaultDeps = { tokenStore, secretFetcher, ca };

// --- HTTP proxy (CONNECT for HTTPS, forward for HTTP) ---

const server = http.createServer((req, res) => {
  // Handle vault API requests directly
  if (handleVaultRequest(req, res, vaultDeps)) return;

  // Forward HTTP proxy request
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
  swapTokensInRequest(proxyReq, parsed);

  req.pipe(proxyReq);
});

// HTTPS CONNECT tunneling with MITM for token swapping
server.on('connect', async (req: http.IncomingMessage, clientSocket: net.Socket, head: Buffer) => {
  // Strict DNS-name / IP-literal validation: the hostname reaches certificate
  // generation and the upstream dial, so reject anything else up front.
  const target = parseConnectTarget(req.url);
  if (!target) {
    console.warn('[connect] rejected invalid CONNECT target');
    clientSocket.end('HTTP/1.1 400 Bad Request\r\n\r\n');
    return;
  }
  const { hostname, port } = target;

  // Prevent unhandled socket errors from crashing the process
  clientSocket.on('error', (err) => {
    console.error(`Client socket error (CONNECT ${hostname}):`, err.message);
  });

  // Check if we have any active tokens — if not, just tunnel directly (no MITM needed)
  if (tokenStore.size === 0) {
    console.log(`[connect] host=${hostname}:${port} mode=passthrough store_size=0`);
    tunnelDirect(hostname, port, clientSocket, head);
    return;
  }
  console.log(`[connect] host=${hostname}:${port} mode=mitm store_size=${tokenStore.size}`);

  // Mint the leaf cert before acknowledging the CONNECT: the client sends its
  // ClientHello as soon as it sees the 200.
  let serverCert: HostCert;
  try {
    serverCert = await ca.getCertForHost(hostname);
  } catch (err) {
    console.error(`Certificate generation failed for ${hostname}:`, (err as Error).message);
    clientSocket.end('HTTP/1.1 502 Bad Gateway\r\n\r\n');
    return;
  }

  // MITM: terminate TLS from client, inspect/modify, re-encrypt to server
  clientSocket.write('HTTP/1.1 200 Connection Established\r\n\r\n');

  const tlsSocket = new tls.TLSSocket(clientSocket, {
    isServer: true,
    key: serverCert.key,
    cert: serverCert.cert,
  });

  tlsSocket.on('error', (err) => {
    console.error(`TLS error for ${hostname}:`, err.message);
    clientSocket.destroy();
  });

  // Read the decrypted HTTP request from the client
  let requestData = Buffer.from(head);
  let realSocket: tls.TLSSocket | null = null;
  let upstreamReady = false;
  let pendingWrites: Buffer[] = [];

  /**
   * Process buffered client data, extracting complete HTTP requests and
   * swapping tokens in each one. Handles HTTP keep-alive: after the first
   * request, subsequent requests on the same connection are also parsed
   * and token-swapped (not raw-piped).
   */
  function processClientData() {
    for (;;) {
      const headerEnd = requestData.indexOf('\r\n\r\n');
      if (headerEnd === -1) return; // need more data

      const headerStr = requestData.subarray(0, headerEnd).toString();

      // Determine Content-Length to know how much body to consume.
      // TODO: Transfer-Encoding: chunked is not handled — body length will be
      // wrong for chunked requests, potentially misaligning the request parser.
      // Not an issue today (Google APIs use Content-Length; Browserbase bypasses
      // the proxy), but revisit if we proxy chunked POST/PUT requests.
      const clMatch = headerStr.match(/content-length:\s*(\d+)/i);
      const contentLength = clMatch ? parseInt(clMatch[1], 10) : 0;
      const totalLength = headerEnd + 4 + contentLength;

      if (requestData.length < totalLength) return; // need more data for body

      const body = requestData.subarray(headerEnd + 4, totalLength);
      requestData = requestData.subarray(totalLength); // remainder for next request

      // Swap tokens in headers
      const swapped = swapTokensInRawHeaders(headerStr, hostname);

      const outBuf = Buffer.concat([
        Buffer.from(swapped + '\r\n\r\n'),
        body,
      ]);

      if (realSocket && upstreamReady) {
        realSocket.write(outBuf);
      } else {
        pendingWrites.push(outBuf);
      }
    }
  }

  tlsSocket.on('data', (chunk: Buffer) => {
    requestData = Buffer.concat([requestData, chunk]);
    processClientData();
  });

  // Connect to the real server once (reused for keep-alive)
  // SNI must not be an IP literal (RFC 6066); certificate checks still use `host`.
  realSocket = tls.connect({ host: hostname, port, servername: net.isIP(hostname) ? undefined : hostname }, () => {
    upstreamReady = true;
    // Flush any requests that were parsed before the upstream connected
    for (const buf of pendingWrites) {
      realSocket!.write(buf);
    }
    pendingWrites = [];

    // Responses flow back to the client. For the Browserbase REST host (when the
    // CDP proxy is on) we rewrite the session `connectUrl` to point at the local
    // CDP proxy; every other host pipes through unmodified.
    if (CDP_PROXY_ENABLED && hostname === BROWSERBASE_API_HOST) {
      const rewriter = createConnectUrlRewriter(
        (realConnectUrl) => `ws://${CDP_PROXY_ADVERTISE_HOST}:${CDP_PROXY_PORT}/cdp/${cdpSessionStore.register(realConnectUrl)}`,
      );
      realSocket!.on('data', (chunk: Buffer) => {
        const out = rewriter.push(chunk);
        if (out.length > 0) tlsSocket.write(out);
      });
      realSocket!.on('end', () => tlsSocket.end());
    } else {
      realSocket!.pipe(tlsSocket);
    }

    // Process any data that arrived during connection setup
    processClientData();
  });

  realSocket.on('error', (err) => {
    console.error(`Upstream TLS error for ${hostname}:`, err.message);
    tlsSocket.destroy();
  });
});

function tunnelDirect(hostname: string, port: number, clientSocket: net.Socket, head: Buffer) {
  const serverSocket = net.connect(port, hostname, () => {
    clientSocket.write('HTTP/1.1 200 Connection Established\r\n\r\n');
    if (head.length > 0) serverSocket.write(head);
    clientSocket.pipe(serverSocket);
    serverSocket.pipe(clientSocket);
  });

  serverSocket.on('error', (err) => {
    console.error(`Tunnel error to ${hostname}:${port}:`, err.message);
    clientSocket.destroy();
  });

  clientSocket.on('error', (err) => {
    console.error(`Client socket error for ${hostname}:${port}:`, err.message);
    serverSocket.destroy();
  });
}

// --- Token swapping logic ---

function swapTokensInRequest(proxyReq: http.ClientRequest, parsed: URL): void {
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

function swapTokensInRawHeaders(headerStr: string, hostname: string): string {
  const result = tokenStore.replaceAll(headerStr);
  logSwapOutcome('https', hostname, result.swaps, result.output);
  return result.output;
}

/**
 * Emit a single structured line per outbound request describing the swap outcome.
 * `postSwapText` is the text *after* swaps were applied — any `tok_<hex>` literal
 * remaining in it is un-swapped (TTL-expired token, stale tunnel, or a literal
 * the agent typed by mistake). Never logs token values, IDs, or request bodies.
 */
function logSwapOutcome(
  scheme: 'http' | 'https',
  hostname: string,
  swaps: SwapInfo[],
  postSwapText: string,
): void {
  if (swaps.length > 0) {
    const secrets = swaps.map(s => s.secretName).join(',');
    const maxAge = Math.max(...swaps.map(s => s.ageMs));
    console.log(`[swap] scheme=${scheme} host=${hostname} result=hit secrets=${secrets} max_age_ms=${maxAge}`);
  }

  // Reset regex state — TOKEN_LITERAL_PATTERN is a /g RegExp shared across calls.
  TOKEN_LITERAL_PATTERN.lastIndex = 0;
  const unswapped = (postSwapText.match(TOKEN_LITERAL_PATTERN) ?? []).length;
  if (unswapped > 0) {
    console.warn(
      `[swap] scheme=${scheme} host=${hostname} result=miss unswapped_tok_literals=${unswapped} ` +
      `(TTL expiry, passthrough tunnel, or never-issued token — request reaching upstream with tok_… intact)`
    );
  }
}

// --- Start ---

// Bind to 0.0.0.0 in dev (docker-compose port mapping), 127.0.0.1 in prod (sidecar)
const BIND_HOST = process.env.PROXY_BIND_HOST ?? '127.0.0.1';

server.listen(PROXY_PORT, BIND_HOST, () => {
  console.log(`Secret proxy listening on ${BIND_HOST}:${PROXY_PORT}`);
  console.log(`Agent label: ${AGENT_LABEL}`);
  console.log(`Vault API: http://localhost:${PROXY_PORT}/_vault`);
});

let cdpProxyHandle: { close(): Promise<void> } | null = null;
if (CDP_PROXY_ENABLED) {
  startCdpProxy({ tokenStore, cdpSessionStore, port: CDP_PROXY_PORT, bindHost: BIND_HOST })
    .then(handle => { cdpProxyHandle = handle; })
    .catch(err => {
      console.error('Failed to start CDP proxy:', err);
      process.exit(1);
    });
} else {
  console.log('CDP proxy disabled (set CDP_PROXY_ENABLED=1 to enable)');
}

// Graceful shutdown
process.on('SIGTERM', () => {
  console.log('Shutting down secret proxy...');
  const closeServer = () => server.close(() => process.exit(0));
  if (cdpProxyHandle) {
    cdpProxyHandle.close().then(closeServer).catch(closeServer);
  } else {
    closeServer();
  }
});
