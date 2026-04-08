import http from 'node:http';
import net from 'node:net';
import tls from 'node:tls';
import { URL } from 'node:url';
import { TokenStore } from './token-store.js';
import { SecretFetcher } from './secret-fetcher.js';
import { CertAuthority } from './ca.js';

const PROXY_PORT = parseInt(process.env.PROXY_PORT ?? '3128', 10);
const AGENT_LABEL = process.env.AGENT_LABEL;

if (!AGENT_LABEL) {
  console.error('AGENT_LABEL is required');
  process.exit(1);
}

const tokenStore = new TokenStore();
const secretFetcher = new SecretFetcher(AGENT_LABEL);
const ca = new CertAuthority();

// --- Vault API handler (requests to the proxy itself) ---

function handleVaultRequest(req: http.IncomingMessage, res: http.ServerResponse): boolean {
  const url = req.url ?? '';

  // Health check
  if (url === '/_health') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ status: 'ok', tokens_active: tokenStore.size }));
    return true;
  }

  // Serve CA certificate (for agent container to trust)
  if (url === '/_ca') {
    res.writeHead(200, { 'Content-Type': 'application/x-pem-file' });
    res.end(ca.caCertPem);
    return true;
  }

  // List integrations/secrets
  if (url === '/_vault' && req.method === 'GET') {
    secretFetcher.listSecrets().then(names => {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ secrets: names }));
    }).catch(err => {
      console.error('Error listing secrets:', err);
      res.writeHead(500, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Failed to list secrets' }));
    });
    return true;
  }

  // Get/check a secret
  const vaultMatch = url.match(/^\/_vault\/([^/?]+)(\?.*)?$/);
  if (vaultMatch && req.method === 'GET') {
    const secretName = decodeURIComponent(vaultMatch[1]);
    const params = new URLSearchParams(vaultMatch[2] ?? '');

    if (params.get('check') === '1') {
      secretFetcher.exists(secretName).then(exists => {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ exists }));
      }).catch(err => {
        console.error('Error checking secret:', err);
        res.writeHead(500, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Failed to check secret' }));
      });
      return true;
    }

    // Issue a proxy token
    secretFetcher.get(secretName).then(value => {
      if (value === null) {
        res.writeHead(404, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: `Secret '${secretName}' not found`, vault_url: 'https://example.com/dashboard/vault' }));
        return;
      }
      const token = tokenStore.issue(secretName, value);
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ token: token.id, expires_in: token.ttlSeconds }));
    }).catch(err => {
      console.error('Error fetching secret:', err);
      res.writeHead(500, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Failed to fetch secret' }));
    });
    return true;
  }

  return false;
}

// --- HTTP proxy (CONNECT for HTTPS, forward for HTTP) ---

const server = http.createServer((req, res) => {
  // Handle vault API requests directly
  if (handleVaultRequest(req, res)) return;

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
server.on('connect', (req: http.IncomingMessage, clientSocket: net.Socket, head: Buffer) => {
  const [hostname, portStr] = (req.url ?? '').split(':');
  const port = parseInt(portStr ?? '443', 10);

  if (!hostname) {
    clientSocket.end('HTTP/1.1 400 Bad Request\r\n\r\n');
    return;
  }

  // Prevent unhandled socket errors from crashing the process
  clientSocket.on('error', (err) => {
    console.error(`Client socket error (CONNECT ${hostname}):`, err.message);
  });

  // Check if we have any active tokens — if not, just tunnel directly (no MITM needed)
  if (tokenStore.size === 0) {
    tunnelDirect(hostname, port, clientSocket, head);
    return;
  }

  // MITM: terminate TLS from client, inspect/modify, re-encrypt to server
  clientSocket.write('HTTP/1.1 200 Connection Established\r\n\r\n');

  const serverCert = ca.getCertForHost(hostname);

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
  tlsSocket.on('data', (chunk: Buffer) => {
    requestData = Buffer.concat([requestData, chunk]);

    // Check if we have a complete HTTP request (headers end with \r\n\r\n)
    const headerEnd = requestData.indexOf('\r\n\r\n');
    if (headerEnd === -1) return;

    const headerStr = requestData.subarray(0, headerEnd).toString();
    const body = requestData.subarray(headerEnd + 4);

    // Swap tokens in headers and reconstruct
    const swapped = swapTokensInRawHeaders(headerStr, hostname);

    // Connect to the real server and forward
    const realSocket = tls.connect({ host: hostname, port, servername: hostname }, () => {
      realSocket.write(swapped + '\r\n\r\n');
      if (body.length > 0) realSocket.write(body);

      // Pipe bidirectionally for the rest of the connection
      tlsSocket.pipe(realSocket);
      realSocket.pipe(tlsSocket);
    });

    realSocket.on('error', (err) => {
      console.error(`Upstream TLS error for ${hostname}:`, err.message);
      tlsSocket.destroy();
    });
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
  // Swap tokens in URL (query params)
  let urlChanged = false;
  const newUrl = tokenStore.replaceAll(parsed.href);
  if (newUrl !== parsed.href) {
    urlChanged = true;
    const newParsed = new URL(newUrl);
    proxyReq.path = newParsed.pathname + newParsed.search;
  }

  // Swap tokens in headers
  const headers = proxyReq.getHeaders();
  for (const [key, value] of Object.entries(headers)) {
    if (typeof value === 'string') {
      const swapped = tokenStore.replaceAll(value);
      if (swapped !== value) {
        proxyReq.setHeader(key, swapped);
      }
    }
  }

  if (urlChanged) {
    console.log(`Token swapped in URL for ${parsed.hostname}`);
  }
}

function swapTokensInRawHeaders(headerStr: string, hostname: string): string {
  const swapped = tokenStore.replaceAll(headerStr);
  if (swapped !== headerStr) {
    console.log(`Token swapped in HTTPS request to ${hostname}`);
  }
  return swapped;
}

// --- Start ---

// Bind to 0.0.0.0 in dev (docker-compose port mapping), 127.0.0.1 in prod (sidecar)
const BIND_HOST = process.env.PROXY_BIND_HOST ?? '127.0.0.1';

server.listen(PROXY_PORT, BIND_HOST, () => {
  console.log(`Secret proxy listening on ${BIND_HOST}:${PROXY_PORT}`);
  console.log(`Agent label: ${AGENT_LABEL}`);
  console.log(`Vault API: http://localhost:${PROXY_PORT}/_vault`);
});

// Graceful shutdown
process.on('SIGTERM', () => {
  console.log('Shutting down secret proxy...');
  server.close(() => process.exit(0));
});
