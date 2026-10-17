import http from 'node:http';
import net from 'node:net';
import tls from 'node:tls';
import type { TokenStore } from './token-store.js';
import type { CertAuthority, HostCert } from './ca.js';
import type { CdpSessionStore } from './cdp-session-store.js';
import { createConnectUrlRewriter } from './browserbase-rewrite.js';
import { parseConnectTarget } from './connect-target.js';
import { logSwapOutcome } from './swap-log.js';

export interface MitmDeps {
  tokenStore: TokenStore;
  ca: CertAuthority;
  cdpSessionStore: CdpSessionStore;
  /** Set when CDP injection is enabled: where rewritten connectUrls point. */
  cdp?: { port: number; advertiseHost: string };
  /** REST host whose responses carry the browser `connectUrl`. */
  browserbaseApiHost: string;
  /** Extra trust anchors for upstream TLS (tests). Default: Node's root store. */
  upstreamCa?: string;
}

/** Handle a `CONNECT host:port` request: MITM when tickets are live, raw tunnel otherwise. */
export function createConnectHandler(deps: MitmDeps) {
  const { tokenStore, ca, cdpSessionStore, cdp, browserbaseApiHost, upstreamCa } = deps;

  return async (req: http.IncomingMessage, clientSocket: net.Socket, head: Buffer): Promise<void> => {
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
        // wrong for chunked requests, potentially misaligning the request parser
        // (roadmap item 16).
        const clMatch = headerStr.match(/content-length:\s*(\d+)/i);
        const contentLength = clMatch ? parseInt(clMatch[1], 10) : 0;
        const totalLength = headerEnd + 4 + contentLength;

        if (requestData.length < totalLength) return; // need more data for body

        const body = requestData.subarray(headerEnd + 4, totalLength);
        requestData = requestData.subarray(totalLength); // remainder for next request

        // Swap tokens in headers
        const result = tokenStore.replaceAll(headerStr);
        logSwapOutcome('https', hostname, result.swaps, result.output);

        const outBuf = Buffer.concat([
          Buffer.from(result.output + '\r\n\r\n'),
          body,
        ]);

        if (upstreamReady) {
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

    // Connect to the real server once (reused for keep-alive).
    // SNI must not be an IP literal (RFC 6066); certificate checks still use `host`.
    const realSocket = tls.connect({
      host: hostname,
      port,
      servername: net.isIP(hostname) ? undefined : hostname,
      ...(upstreamCa ? { ca: upstreamCa } : {}),
    }, () => {
      upstreamReady = true;
      // Flush any requests that were parsed before the upstream connected
      for (const buf of pendingWrites) {
        realSocket.write(buf);
      }
      pendingWrites = [];

      // Responses flow back to the client. For the Browserbase REST host (when the
      // CDP proxy is on) we rewrite the session `connectUrl` to point at the local
      // CDP proxy; every other host pipes through unmodified.
      if (cdp && hostname === browserbaseApiHost) {
        const rewriter = createConnectUrlRewriter(
          (realConnectUrl) => `ws://${cdp.advertiseHost}:${cdp.port}/cdp/${cdpSessionStore.register(realConnectUrl)}`,
        );
        realSocket.on('data', (chunk: Buffer) => {
          const out = rewriter.push(chunk);
          if (out.length > 0) tlsSocket.write(out);
        });
        realSocket.on('end', () => tlsSocket.end());
      } else {
        realSocket.pipe(tlsSocket);
      }

      // Process any data that arrived during connection setup
      processClientData();
    });

    realSocket.on('error', (err) => {
      console.error(`Upstream TLS error for ${hostname}:`, err.message);
      tlsSocket.destroy();
    });

    // Tie the two legs' lifetimes together, so a client that goes away does
    // not leave the upstream connection (and the client socket) open until the
    // upstream's idle timeout.
    tlsSocket.on('end', () => realSocket.end()); // forward the client's half-close
    tlsSocket.on('close', () => realSocket.destroy());
    realSocket.on('close', () => tlsSocket.destroy());
  };
}

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
