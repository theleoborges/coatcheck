import { WebSocketServer, WebSocket } from 'ws';
import type { AddressInfo } from 'node:net';
import type { TokenStore } from '../token-store.js';
import type { CdpSessionStore } from '../cdp-session-store.js';
import { substituteOutbound, substituteInbound } from './substitution.js';
import { KeystrokeDetector } from './keystroke-detector.js';

const DEFAULT_PORT = 8444;
const DEFAULT_PENDING_FRAME_CAP = 256;
const DEFAULT_UPSTREAM_TIMEOUT_MS = 10_000;
const MAX_CONCURRENT = 1; // agents drive a single browser at a time in v1

export interface CdpProxyOptions {
  tokenStore: TokenStore;
  cdpSessionStore: CdpSessionStore;
  port?: number;
  bindHost?: string;
  pendingFrameCap?: number;
  upstreamTimeoutMs?: number;
}

export interface CdpProxyHandle {
  port: number;
  close(): Promise<void>;
}

// CDP error id reused for fail-closed and overflow conditions.
const CDP_ERROR_CODE = -32000;

/**
 * Start the CDP WebSocket proxy. The agent's Playwright client connects to
 * `ws://{bindHost}:{port}/cdp/{sid}`; we look the sid up in the session store,
 * dial the real Browserbase connectUrl, and relay frames both ways through the
 * substitution / keystroke-detection layer. Tokens minted for the session are
 * revoked when the connection closes.
 */
export function startCdpProxy(opts: CdpProxyOptions): Promise<CdpProxyHandle> {
  const {
    tokenStore,
    cdpSessionStore,
    port = DEFAULT_PORT,
    bindHost = '127.0.0.1',
    pendingFrameCap = DEFAULT_PENDING_FRAME_CAP,
    upstreamTimeoutMs = DEFAULT_UPSTREAM_TIMEOUT_MS,
  } = opts;

  const wss = new WebSocketServer({ host: bindHost, port });
  let activeConnections = 0;

  wss.on('connection', (clientWs: WebSocket, req) => {
    const sid = parseSid(req.url ?? '');
    const realConnectUrl = sid ? cdpSessionStore.get(sid) : null;

    if (!sid || !realConnectUrl) {
      console.warn(`[cdp] reject connection: unknown session sid=${sid ?? '(none)'}`);
      clientWs.close(1008, 'unknown CDP session');
      return;
    }
    if (activeConnections >= MAX_CONCURRENT) {
      console.warn(`[cdp] reject connection: concurrency cap reached (${MAX_CONCURRENT})`);
      clientWs.close(1013, 'CDP proxy busy');
      return;
    }

    activeConnections++;
    console.log(`[cdp] session sid=${sid} adapter=${cdpSessionStore.adapterName(sid) ?? 'unknown'} connected, dialling upstream`);

    const detector = new KeystrokeDetector();
    const upstream = new WebSocket(realConnectUrl);
    const pending: Array<{ payload: string | Buffer; isBinary: boolean }> = [];
    let upstreamOpen = false;
    let closed = false;

    const upstreamTimer = setTimeout(() => {
      if (!upstreamOpen) {
        console.warn(`[cdp] sid=${sid} upstream connect timeout`);
        teardown();
      }
    }, upstreamTimeoutMs);
    upstreamTimer.unref();

    function teardown() {
      if (closed) return;
      closed = true;
      clearTimeout(upstreamTimer);
      activeConnections--;
      const revoked = tokenStore.revokeSession(sid!);
      cdpSessionStore.revoke(sid!);
      console.log(`[cdp] sid=${sid} closed, revoked ${revoked} token(s)`);
      try { clientWs.close(); } catch { /* ignore */ }
      try { upstream.close(); } catch { /* ignore */ }
    }

    // --- agent → upstream ---
    clientWs.on('message', (data: Buffer, isBinary: boolean) => {
      if (isBinary) {
        forwardUpstream(data, true);
        return;
      }
      const raw = data.toString();

      // Keystroke fail-closed: detect page.type() runs that spell a session token.
      if (raw.indexOf('Input.dispatchKeyEvent') !== -1) {
        const text = extractKeyEventText(raw);
        if (text !== null) {
          const matched = detector.inspect(text, tokenStore.sessionTokenIds(sid!));
          if (matched) {
            const id = extractFrameId(raw);
            console.warn(`[cdp] sid=${sid} FAIL-CLOSED: page.type() detected on a vault token`);
            sendCdpError(
              clientWs,
              id,
              'credential-flow violation: page.type() detected on a vault token; use page.fill() instead',
            );
            return; // drop the frame — never forward the literal token upstream
          }
        }
        forwardUpstream(data, false);
        return;
      }

      const result = substituteOutbound(raw, tokenStore, sid!);
      if (result.unsupportedTokenMethod) {
        console.warn(
          `[cdp] sid=${sid} token observed in unsupported method ${result.unsupportedTokenMethod} (not substituted)`,
        );
      }
      if (result.substitutions > 0) {
        console.log(`[cdp] sid=${sid} outbound substitutions=${result.substitutions}`);
      }
      forwardUpstream(result.payload, false);
    });

    function forwardUpstream(payload: string | Buffer, isBinary: boolean) {
      if (upstreamOpen) {
        upstream.send(payload, { binary: isBinary });
        return;
      }
      if (pending.length >= pendingFrameCap) {
        console.warn(`[cdp] sid=${sid} pending-frame cap (${pendingFrameCap}) exceeded`);
        sendCdpError(clientWs, null, 'CDP proxy buffer overflow before upstream ready');
        teardown();
        return;
      }
      pending.push({ payload, isBinary });
    }

    clientWs.on('close', () => teardown());
    clientWs.on('error', (e: Error) => {
      console.error(`[cdp] sid=${sid} client error: ${e.message}`);
      teardown();
    });

    // --- upstream → agent ---
    upstream.on('open', () => {
      upstreamOpen = true;
      clearTimeout(upstreamTimer);
      for (const { payload, isBinary } of pending) upstream.send(payload, { binary: isBinary });
      pending.length = 0;
      console.log(`[cdp] sid=${sid} upstream open, relaying`);
    });
    upstream.on('message', (data: Buffer, isBinary: boolean) => {
      if (isBinary) {
        if (!closed) clientWs.send(data, { binary: true });
        return;
      }
      const result = substituteInbound(data.toString(), tokenStore, sid!);
      if (result.dropped) {
        console.warn(`[cdp] sid=${sid} inbound frame dropped (real value present)`);
        return; // do not forward — echo-back floor
      }
      if (result.redactions > 0) {
        console.log(`[cdp] sid=${sid} inbound redactions=${result.redactions}`);
      }
      if (!closed) clientWs.send(result.payload as string, { binary: false });
    });
    upstream.on('close', () => teardown());
    upstream.on('error', (e: Error) => {
      console.error(`[cdp] sid=${sid} upstream error: ${e.message}`);
      teardown();
    });
  });

  return new Promise((resolve, reject) => {
    wss.on('error', reject);
    wss.on('listening', () => {
      const boundPort = (wss.address() as AddressInfo).port;
      console.log(`CDP proxy listening on ws://${bindHost}:${boundPort}/cdp/{sid}`);
      resolve({
        port: boundPort,
        close: () =>
          new Promise<void>((res) => {
            wss.close(() => res());
          }),
      });
    });
  });
}

/** Extract the sid from a `/cdp/{sid}` path. */
function parseSid(urlPath: string): string | null {
  const m = urlPath.match(/^\/cdp\/([a-f0-9]+)\/?$/);
  return m ? m[1] : null;
}

function extractKeyEventText(raw: string): string | null {
  try {
    const parsed = JSON.parse(raw) as { method?: string; params?: { text?: unknown } };
    if (parsed.method === 'Input.dispatchKeyEvent' && typeof parsed.params?.text === 'string') {
      return parsed.params.text;
    }
  } catch {
    /* ignore */
  }
  return null;
}

function extractFrameId(raw: string): number | null {
  try {
    const parsed = JSON.parse(raw) as { id?: unknown };
    return typeof parsed.id === 'number' ? parsed.id : null;
  } catch {
    return null;
  }
}

function sendCdpError(clientWs: WebSocket, id: number | null, message: string): void {
  if (clientWs.readyState !== WebSocket.OPEN) return;
  clientWs.send(
    JSON.stringify({ id: id ?? 0, error: { code: CDP_ERROR_CODE, message } }),
    { binary: false },
  );
}
