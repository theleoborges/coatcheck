import http from 'node:http';
import net from 'node:net';
import tls from 'node:tls';
import type { TokenStore } from './token-store.js';
import type { CertAuthority, HostCert } from './ca.js';
import type { CdpSessionStore } from './cdp-session-store.js';
import { createJsonResponseRewriter } from './json-response-rewriter.js';
import type { BrowserAdapter } from './browser-adapters.js';
import { parseConnectTarget } from './connect-target.js';
import { matchesHost, parseHostPattern, type HostPattern } from './host-matcher.js';
import { allPolicyHosts, type Policy } from './policy.js';
import type { MitmMode } from './config.js';
import { DENIED_HEADER, hostMismatchBody, logSwapOutcome } from './swap-log.js';

export interface MitmDeps {
  tokenStore: TokenStore;
  ca: CertAuthority;
  cdpSessionStore: CdpSessionStore;
  /** Set when CDP injection is enabled: where rewritten connectUrls point. */
  cdp?: { port: number; advertiseHost: string };
  /** Browser adapters: their REST hosts' responses get CDP URLs rewritten (when `cdp` is set). */
  browserAdapters: readonly BrowserAdapter[];
  /** Extra trust anchors for upstream TLS (tests). Default: Node's root store. */
  upstreamCa?: string;
  /** Operator policy: in `bound` mode its hosts are MITM'd. */
  policy: Policy;
  mitm: MitmMode;
  /** Never MITM'd, in either mode. */
  passthroughHosts: readonly HostPattern[];
}

/**
 * Handle a `CONNECT host:port` request. `bound` mode MITMs only targets a ticket
 * could be swapped for (policy hosts, live tickets, adapter hosts); `always`
 * MITMs everything. Passthrough hosts are always a raw tunnel.
 */
export function createConnectHandler(deps: MitmDeps) {
  const { tokenStore, ca, cdpSessionStore, cdp, upstreamCa, mitm, passthroughHosts } = deps;
  const policyHosts = allPolicyHosts(deps.policy);
  // Parsed once: a bad adapter host pattern fails here, at startup.
  const adapters = deps.browserAdapters.map(adapter => ({
    adapter,
    hosts: adapter.hosts.map(h => {
      const p = parseHostPattern(h);
      if (typeof p === 'string') throw new Error(`browser adapter '${adapter.name}' host '${h}': ${p}`);
      return p;
    }),
  }));

  /** The adapter whose REST hosts include `hostname`, when CDP injection is on. */
  function adapterFor(hostname: string): BrowserAdapter | undefined {
    if (!cdp) return undefined;
    const target = { host: hostname, scheme: 'https' as const };
    return adapters.find(a => matchesHost(a.hosts, target))?.adapter;
  }

  /** Why this target is MITM'd, or null (with the reason) for a raw tunnel. */
  function decide(hostname: string): { mitm: boolean; reason: string } {
    const target = { host: hostname, scheme: 'https' as const };
    if (matchesHost(passthroughHosts, target)) return { mitm: false, reason: 'passthrough-list' };
    if (mitm === 'always') return { mitm: true, reason: 'always' };
    if (matchesHost(policyHosts, target)) return { mitm: true, reason: 'policy' };
    if (adapterFor(hostname)) return { mitm: true, reason: 'adapter' };
    if (tokenStore.hasLiveTicketFor(target)) return { mitm: true, reason: 'ticket' };
    return { mitm: false, reason: 'not-bound' };
  }

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

    // Decrypting a host no ticket can be swapped for gains nothing and risks
    // breaking clients, so those get a raw tunnel (design §5).
    const decision = decide(hostname);
    console.log(`[connect] host=${hostname}:${port} mode=${decision.mitm ? 'mitm' : 'passthrough'} reason=${decision.reason}`);
    if (!decision.mitm) {
      tunnelDirect(hostname, port, clientSocket, head);
      return;
    }

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

    // The request parser below is HTTP/1.1 only, so h2-capable clients must
    // negotiate http/1.1 rather than fail or stall.
    const tlsSocket = new tls.TLSSocket(clientSocket, {
      isServer: true,
      key: serverCert.key,
      cert: serverCert.cert,
      ALPNProtocols: ['http/1.1'],
    });

    tlsSocket.on('error', (err) => {
      console.error(`TLS error for ${hostname}:`, err.message);
      clientSocket.destroy();
    });

    // Read the decrypted HTTP request from the client
    let requestData = Buffer.from(head);
    let upstreamReady = false;
    let pendingWrites: Buffer[] = [];
    let denied = false;
    // Upgrade (e.g. WebSocket): after forwarding a request with an Upgrade
    // header, hold client bytes until the upstream's response head; a 101
    // turns the tunnel into a raw pipe (design §5).
    let awaitingUpgrade = false;
    let rawPipe = false;
    let responseHead = Buffer.alloc(0);

    function sendUpstream(buf: Buffer) {
      if (upstreamReady) realSocket.write(buf);
      else pendingWrites.push(buf);
    }

    /**
     * Process buffered client data, extracting complete HTTP requests and
     * swapping tokens in each one. Handles HTTP keep-alive: after the first
     * request, subsequent requests on the same connection are also parsed
     * and token-swapped (not raw-piped).
     */
    function processClientData() {
      while (!denied && !awaitingUpgrade && !rawPipe) {
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

        // Swap tokens in headers. The binding key is the validated CONNECT
        // target (upstream TLS proves it is the recipient), never Host or SNI.
        const result = tokenStore.replaceAll(headerStr, { host: hostname, scheme: 'https' });
        logSwapOutcome('https', hostname, result, result.output);
        if (result.denied.length > 0) {
          denyAndClose(hostMismatchBody(result.denied, hostname));
          return;
        }

        const outBuf = Buffer.concat([
          Buffer.from(result.output + '\r\n\r\n'),
          body,
        ]);

        sendUpstream(outBuf);
        if (/^upgrade:/im.test(headerStr)) awaitingUpgrade = true;
      }
    }

    /** Watch upstream bytes for the response head that answers an upgrade request. */
    function sniffUpgradeResponse(chunk: Buffer) {
      if (!awaitingUpgrade) return;
      responseHead = Buffer.concat([responseHead, chunk]);
      for (;;) {
        const end = responseHead.indexOf('\r\n\r\n');
        if (end === -1) return;
        const status = /^HTTP\/1\.[01] (\d{3})/.exec(responseHead.subarray(0, end).toString())?.[1];
        responseHead = responseHead.subarray(end + 4);
        // Interim responses (100 Continue) precede the real answer.
        if (status && status.startsWith('1') && status !== '101') continue;
        responseHead = Buffer.alloc(0);
        awaitingUpgrade = false;
        if (status === '101') {
          rawPipe = true;
          if (requestData.length > 0) sendUpstream(requestData);
          requestData = Buffer.alloc(0);
        } else {
          processClientData();
        }
        return;
      }
    }

    /**
     * Answer 403 instead of forwarding, and close the tunnel: requests
     * pipelined ahead of this one that the upstream hasn't answered are
     * abandoned (design §3, "Host binding details").
     */
    function denyAndClose(body: string) {
      denied = true;
      pendingWrites = [];
      requestData = Buffer.alloc(0);
      realSocket.unpipe(tlsSocket);
      realSocket.destroy();
      tlsSocket.end(
        'HTTP/1.1 403 Forbidden\r\n' +
        'Content-Type: application/json\r\n' +
        `${DENIED_HEADER}: host-mismatch\r\n` +
        `Content-Length: ${Buffer.byteLength(body)}\r\n` +
        'Connection: close\r\n\r\n' +
        body,
      );
    }

    tlsSocket.on('data', (chunk: Buffer) => {
      if (denied) return;
      if (rawPipe) {
        sendUpstream(chunk);
        return;
      }
      requestData = Buffer.concat([requestData, chunk]);
      processClientData();
    });

    // Connect to the real server once (reused for keep-alive).
    // SNI must not be an IP literal (RFC 6066); certificate checks still use `host`.
    const realSocket = tls.connect({
      host: hostname,
      port,
      servername: net.isIP(hostname) ? undefined : hostname,
      ALPNProtocols: ['http/1.1'],
      ...(upstreamCa ? { ca: upstreamCa } : {}),
    }, () => {
      upstreamReady = true;
      // Flush any requests that were parsed before the upstream connected
      for (const buf of pendingWrites) {
        realSocket.write(buf);
      }
      pendingWrites = [];

      // Registered before the pipe/rewriter so a 101 flips rawPipe before they see the chunk.
      realSocket.on('data', sniffUpgradeResponse);

      // Responses flow back to the client. For a browser adapter's REST host (when
      // the CDP proxy is on) the adapter rewrites CDP URLs to the local CDP proxy;
      // every other host pipes through unmodified.
      const adapter = adapterFor(hostname);
      if (cdp && adapter) {
        const register = (realUrl: string) =>
          `ws://${cdp.advertiseHost}:${cdp.port}/cdp/${cdpSessionStore.register(realUrl, adapter.name)}`;
        const rewriter = createJsonResponseRewriter(body => adapter.rewriteJson(body, register));
        realSocket.on('data', (chunk: Buffer) => {
          if (denied) return;
          if (rawPipe) {
            tlsSocket.write(chunk);
            return;
          }
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
      if (!denied) tlsSocket.destroy();
    });

    // Tie the two legs' lifetimes together, so a client that goes away does
    // not leave the upstream connection (and the client socket) open until the
    // upstream's idle timeout.
    tlsSocket.on('end', () => realSocket.end()); // forward the client's half-close
    tlsSocket.on('close', () => realSocket.destroy());
    realSocket.on('close', () => { if (!denied) tlsSocket.destroy(); }); // a denial ends tlsSocket itself
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
