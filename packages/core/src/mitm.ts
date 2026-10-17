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
import { ChunkedDecoder, parseRequestHead, type RequestHead } from './http1-framing.js';
import { swapRequestBody } from './body-swap.js';
import { headerFieldValue, percentEncodeUnsafe } from './value-encoding.js';
import type { SwapInfo } from './token-store.js';
import { DENIED_HEADER, hostMismatchBody, invalidValueBody, logBodyUnscanned, logSwapOutcome, type SwapOutcome } from './swap-log.js';

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
  /** Largest request body buffered for `swap_body` swapping; larger ones stream unscanned. */
  maxSwapBodyBytes: number;
}

const STATUS_TEXT = { 400: 'Bad Request', 403: 'Forbidden', 431: 'Request Header Fields Too Large' } as const;

/** A header section that hasn't ended within this many bytes gets 431. */
export const MAX_HEAD_BYTES = 64 * 1024;

/** The body of the request being read, after its head. */
type BodyState =
  /** Forwarded as it arrives. */
  | { mode: 'stream'; remaining: number; decoder?: ChunkedDecoder }
  /** Held for `swap_body` swapping, up to `maxSwapBodyBytes`. */
  | {
      mode: 'buffer';
      remaining: number;
      decoder?: ChunkedDecoder;
      head: RequestHead;
      /** The swapped head, without the final CRLFCRLF. */
      headOut: string;
      headOutcome: SwapOutcome & { postSwapText: string };
      raw: Buffer[];
      rawBytes: number;
      data: Buffer[];
    };

/**
 * Handle a `CONNECT host:port` request. `bound` mode MITMs only targets a ticket
 * could be swapped for (policy hosts, live tickets, adapter hosts); `always`
 * MITMs everything. Passthrough hosts are always a raw tunnel.
 */
export function createConnectHandler(deps: MitmDeps) {
  const { tokenStore, ca, cdpSessionStore, cdp, upstreamCa, mitm, passthroughHosts, maxSwapBodyBytes } = deps;
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

    // The body of the request being read (null between requests), and whether
    // that request asked for an upgrade (honoured once it has been sent).
    let body: BodyState | null = null;
    let upgradeRequested = false;
    // The binding key is the validated CONNECT target (upstream TLS proves it
    // is the recipient), never Host or SNI.
    const swapTarget = { host: hostname, scheme: 'https' as const };

    /**
     * Process buffered client data request by request (HTTP keep-alive: every
     * request on the tunnel is parsed and swapped, not raw-piped). Bodies
     * stream unless a `swap_body` ticket could apply (design §3, "Swap-path
     * hardening").
     */
    function processClientData() {
      while (!denied && !awaitingUpgrade && !rawPipe) {
        if (body) {
          if (!advanceBody(body)) return; // need more data
          continue;
        }
        // Empty lines before a request line are ignored (RFC 9112 §2.2), e.g.
        // a stray CRLF some clients send after a request body.
        while (requestData.length >= 2 && requestData[0] === 0x0d && requestData[1] === 0x0a) {
          requestData = requestData.subarray(2);
        }
        const headerEnd = requestData.indexOf('\r\n\r\n');
        if (headerEnd > MAX_HEAD_BYTES || (headerEnd === -1 && requestData.length > MAX_HEAD_BYTES)) {
          console.warn(`[connect] host=${hostname} rejected request: header section over ${MAX_HEAD_BYTES} bytes`);
          denyAndClose(431, 'head-too-large', JSON.stringify({ error: 'Request header section too large', reason: 'head-too-large' }));
          return;
        }
        if (headerEnd === -1) return; // need more data

        const head = parseRequestHead(requestData.subarray(0, headerEnd).toString());
        requestData = requestData.subarray(headerEnd + 4);
        upgradeRequested = head.header('upgrade') !== undefined;

        // Find where this request ends (RFC 9112 §6); ambiguous framing is
        // refused, since the upstream might read it differently (design §5).
        const { framing } = head;
        if (framing.kind === 'invalid') {
          rejectFraming(framing.reason);
          return;
        }

        const swapped = swapHead(head);
        if (swapped.denied.length > 0 || swapped.invalid.length > 0) {
          logSwapOutcome('https', hostname, swapped, swapped.postSwapText);
          denyForSwaps(swapped.denied, swapped.invalid);
          return;
        }

        const remaining = framing.kind === 'length' ? framing.length : 0;
        const decoder = framing.kind === 'chunked' ? new ChunkedDecoder() : undefined;
        if (framing.kind !== 'none' && (decoder || remaining > 0) && tokenStore.hasLiveBodyTicketFor(swapTarget)) {
          body = {
            mode: 'buffer', remaining, decoder, head, headOut: swapped.output,
            headOutcome: swapped, raw: [], rawBytes: 0, data: [],
          };
          continue;
        }
        logSwapOutcome('https', hostname, swapped, swapped.postSwapText);
        sendUpstream(Buffer.from(swapped.output + '\r\n\r\n'));
        if (decoder || remaining > 0) body = { mode: 'stream', remaining, decoder };
        else finishRequest();
      }
    }

    /**
     * Swap tickets in a head: in the request line (values percent-encoded, as
     * on the forward path) and in the header fields (values that can't be a
     * field value are refused).
     */
    function swapHead(head: RequestHead) {
      const line = tokenStore.replaceAll(head.requestLine, swapTarget, percentEncodeUnsafe);
      const fields = tokenStore.replaceAll(head.fieldLines.join('\r\n'), swapTarget, headerFieldValue);
      const output = head.fieldLines.length > 0 ? `${line.output}\r\n${fields.output}` : line.output;
      return {
        output,
        postSwapText: output,
        swaps: [...line.swaps, ...fields.swaps],
        denied: [...line.denied, ...fields.denied],
        invalid: [...(line.invalid ?? []), ...(fields.invalid ?? [])],
      };
    }

    /**
     * Consume body bytes from `requestData`. Returns true when the body is
     * complete (or the tunnel was denied), false when more data is needed.
     */
    function advanceBody(state: BodyState): boolean {
      let consumed: Buffer;
      if (state.decoder) {
        const r = state.decoder.feed(requestData, state.mode === 'buffer' ? d => state.data.push(d) : undefined);
        if ('error' in r) {
          rejectFraming(r.error);
          return true;
        }
        consumed = requestData.subarray(0, r.consumed);
      } else {
        consumed = requestData.subarray(0, Math.min(state.remaining, requestData.length));
        state.remaining -= consumed.length;
      }
      requestData = requestData.subarray(consumed.length);
      const complete = state.decoder ? state.decoder.done : state.remaining === 0;

      if (state.mode === 'stream') {
        if (consumed.length > 0) sendUpstream(consumed);
      } else {
        if (state.decoder === undefined) state.data.push(consumed);
        state.raw.push(consumed);
        state.rawBytes += consumed.length;
        if (state.rawBytes > maxSwapBodyBytes) {
          // Too large to hold: forward what we have and stream the rest unscanned.
          logSwapOutcome('https', hostname, state.headOutcome, state.headOutcome.postSwapText);
          logBodyUnscanned('https', hostname, maxSwapBodyBytes);
          sendUpstream(Buffer.concat([Buffer.from(state.headOut + '\r\n\r\n'), ...state.raw]));
          body = { mode: 'stream', remaining: state.remaining, decoder: state.decoder };
          if (complete) finishRequest();
          return complete;
        }
        if (complete) {
          sendBuffered(state);
          if (denied) return true;
        }
      }
      if (complete) finishRequest();
      return complete;
    }

    /** Swap a complete buffered body (opt-in secrets only) and send the request. */
    function sendBuffered(state: Extract<BodyState, { mode: 'buffer' }>) {
      const decoded = Buffer.concat(state.data);
      const bodySwap = swapRequestBody(tokenStore, decoded, {
        contentType: state.head.header('content-type'),
        contentEncoding: state.head.header('content-encoding'),
      }, swapTarget);
      const outcome = state.headOutcome;
      const deniedSwaps = [...outcome.denied, ...(bodySwap?.result.denied ?? [])];
      logSwapOutcome('https', hostname, {
        swaps: [...outcome.swaps, ...(bodySwap?.result.swaps ?? [])],
        denied: deniedSwaps,
        skipped: bodySwap?.result.skipped,
      }, bodySwap ? `${outcome.postSwapText}\n${bodySwap.result.output}` : outcome.postSwapText);
      if (deniedSwaps.length > 0) {
        denyForSwaps(deniedSwaps, []);
        return;
      }

      let head = state.headOut;
      let outBody: Buffer = Buffer.concat(state.raw);
      if (bodySwap && bodySwap.result.swaps.length > 0) {
        const swapped = bodySwap.body;
        if (state.decoder) {
          // One chunk, then the last chunk and the trailers as received.
          outBody = Buffer.concat([
            Buffer.from(swapped.length > 0 ? `${swapped.length.toString(16)}\r\n` : ''),
            swapped,
            Buffer.from(swapped.length > 0 ? '\r\n0\r\n' : '0\r\n'),
            state.decoder.trailers,
          ]);
        } else {
          // Framing was validated (exactly one all-digit Content-Length), and
          // swapped header values can't hold CR/LF, so this is the only such line.
          head = head.replace(/^(content-length:[ \t]*)\d+/im, `$1${swapped.length}`);
          outBody = swapped;
        }
      }
      sendUpstream(Buffer.concat([Buffer.from(head + '\r\n\r\n'), outBody]));
    }

    /** The request has been sent in full: honour an upgrade it asked for. */
    function finishRequest() {
      body = null;
      if (upgradeRequested) awaitingUpgrade = true;
      upgradeRequested = false;
    }

    function rejectFraming(reason: string) {
      console.warn(`[connect] host=${hostname} rejected request: ${reason}`);
      denyAndClose(400, 'bad-framing', JSON.stringify({ error: `Bad request framing: ${reason}`, reason: 'bad-framing' }));
    }

    function denyForSwaps(deniedSwaps: SwapInfo[], invalid: SwapInfo[]) {
      if (deniedSwaps.length > 0) denyAndClose(403, 'host-mismatch', hostMismatchBody(deniedSwaps, hostname));
      else denyAndClose(403, 'invalid-value', invalidValueBody(invalid));
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
     * Answer 403 (host mismatch, invalid value), 400 (bad framing) or 431
     * (header section too large) instead of forwarding,
     * and close the tunnel: requests pipelined ahead of this one that the
     * upstream hasn't answered are abandoned (design §3, "Host binding details").
     */
    function denyAndClose(status: 400 | 403 | 431, reason: string, responseBody: string) {
      denied = true;
      pendingWrites = [];
      requestData = Buffer.alloc(0);
      realSocket.unpipe(tlsSocket);
      realSocket.destroy();
      tlsSocket.end(
        `HTTP/1.1 ${status} ${STATUS_TEXT[status]}\r\n` +
        'Content-Type: application/json\r\n' +
        `${DENIED_HEADER}: ${reason}\r\n` +
        `Content-Length: ${Buffer.byteLength(responseBody)}\r\n` +
        'Connection: close\r\n\r\n' +
        responseBody,
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
