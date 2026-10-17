import { WebSocketServer, WebSocket } from 'ws';
import type { AddressInfo } from 'node:net';
import type { TokenStore } from '../token-store.js';
import type { CdpSessionStore, CdpController, LoginRequest, LoginResult } from '../cdp-session-store.js';
import { substituteOutbound, substituteInbound } from './substitution.js';
import { OriginTracker } from './origin-tracker.js';
import { KeystrokeDetector } from './keystroke-detector.js';
import { runLogin } from './login-driver.js';

const DEFAULT_PORT = 8444;
const DEFAULT_PENDING_FRAME_CAP = 256;
const DEFAULT_UPSTREAM_TIMEOUT_MS = 10_000;
const MAX_CONCURRENT = 1; // agents drive a single browser at a time in v1

/**
 * coatcheck's own CDP command ids start here. Playwright's client ids are a
 * sequential counter that never reaches 2³⁰, so ids in this range are
 * unambiguously coatcheck's: inbound responses to them are swallowed, and an
 * agent frame carrying an id this large is refused (decision 3).
 */
const COATCHECK_ID_BASE = 0x4000_0000; // 2³⁰
/** Cap on agent frames queued during a login window before failing closed (decision 4). */
const DEFAULT_AGENT_QUEUE_CAP = 4096;

export interface CdpProxyOptions {
  tokenStore: TokenStore;
  cdpSessionStore: CdpSessionStore;
  port?: number;
  bindHost?: string;
  pendingFrameCap?: number;
  upstreamTimeoutMs?: number;
  agentQueueCap?: number;
}

export interface CdpProxyHandle {
  port: number;
  close(): Promise<void>;
}

// CDP error id reused for fail-closed and overflow conditions.
const CDP_ERROR_CODE = -32000;

interface CdpMessage {
  id?: unknown;
  method?: unknown;
  sessionId?: unknown;
  params?: Record<string, unknown>;
  result?: Record<string, unknown>;
  error?: unknown;
}

/** Frames without a flattened `sessionId` share this key. */
const ROOT = '';

function sessionKey(msg: CdpMessage): string {
  return typeof msg.sessionId === 'string' ? msg.sessionId : ROOT;
}

/**
 * One agent ⇄ remote-browser CDP connection. Owns all per-connection state the
 * broker-login window needs (design: docs/design/cdp-broker-login.md):
 *
 * - attached page targets and their flattened sessionIds,
 * - the new-document script identifiers the agent registered, per target,
 * - whether request interception is enabled, per target,
 * - a high-range id multiplexer (coatcheck's own commands and their pending
 *   responses, swallowed from the agent),
 * - the agent → upstream frame queue used to quiesce the agent for the window.
 *
 * It is attached to `CdpSessionStore` as the sid's `CdpController` so the vault
 * handler can drive a login over it.
 */
export class CdpConnection implements CdpController {
  // --- login-window state, all derived from frames the proxy already sees ---
  /** Flattened sessionId → committed page target (type === 'page'). */
  readonly pageTargets = new Map<string, { targetId: string }>();
  /** Session key → identifiers of non-empty new-document scripts the agent registered. */
  readonly agentScriptIds = new Map<string, Set<string>>();
  /** Session keys with request interception (Fetch / Network) enabled by the agent. */
  readonly interception = new Set<string>();
  /** Agent `Page.addScriptToEvaluateOnNewDocument` request id → session key, awaiting its identifier. */
  private readonly pendingAgentAddScript = new Map<string, string>();

  // --- id multiplexing ---
  private nextCoatcheckId = COATCHECK_ID_BASE;
  private readonly pendingCoatcheck = new Map<number, { resolve(msg: CdpMessage): void; reject(err: Error): void }>();

  // --- agent frame queue (window quiescing) ---
  private queueing = false;
  private readonly agentQueue: Array<{ payload: string | Buffer; isBinary: boolean }> = [];
  private loginInProgress = false;

  // --- legacy v1 substitution helpers (removed in a later commit) ---
  private readonly detector = new KeystrokeDetector();
  readonly origins = new OriginTracker();

  private upstreamOpen = false;
  private closed = false;
  private readonly pending: Array<{ payload: string | Buffer; isBinary: boolean }> = [];

  constructor(
    readonly sid: string,
    private readonly clientWs: WebSocket,
    private readonly upstream: WebSocket,
    private readonly tokenStore: TokenStore,
    private readonly pendingFrameCap: number,
    private readonly agentQueueCap: number,
    private readonly onTeardown: () => void,
  ) {}

  // ---------------------------------------------------------------------------
  // agent → upstream
  // ---------------------------------------------------------------------------

  handleAgentMessage(data: Buffer, isBinary: boolean): void {
    if (isBinary) {
      if (this.queueing) { this.enqueue(data, true); return; }
      this.forwardUpstream(data, true);
      return;
    }
    const raw = data.toString();

    // Refuse any agent frame in coatcheck's reserved id range (decision 3):
    // it could otherwise collide with a pending coatcheck command and route a
    // browser response to the wrong side. Never forwarded.
    const parsedId = extractId(raw);
    if (typeof parsedId === 'number' && parsedId >= COATCHECK_ID_BASE) {
      const { sessionId } = extractFrameRouting(raw);
      sendCdpError(this.clientWs, parsedId, 'reserved command id range; use ids below 2^30', sessionId);
      return;
    }

    if (this.queueing) { this.enqueue(data, false); return; }

    this.trackOutbound(raw);

    // --- legacy v1 outbound substitution (removed in a later commit) ---
    if (raw.indexOf('Input.dispatchKeyEvent') !== -1 || raw.indexOf('\\') !== -1) {
      const text = extractKeyEventText(raw);
      if (text !== null) {
        const matched = this.detector.inspect(text, this.tokenStore.sessionTokenIds(this.sid));
        if (matched) {
          const { id, sessionId } = extractFrameRouting(raw);
          console.warn(`[cdp] sid=${this.sid} FAIL-CLOSED: page.type() detected on a vault token`);
          sendCdpError(this.clientWs, id, 'credential-flow violation: page.type() detected on a vault token; use page.fill() instead', sessionId);
          return;
        }
        this.forwardUpstream(data, false);
        return;
      }
    }

    const result = substituteOutbound(raw, this.tokenStore, this.sid, cdpSessionId => this.origins.originFor(cdpSessionId));
    if (result.denial) {
      const { id, sessionId, secretNames, message } = result.denial;
      console.warn(`[cdp] sid=${this.sid} FAIL-CLOSED: origin binding refused Input.insertText secrets=${secretNames.join(',')}`);
      sendCdpError(this.clientWs, id, message, sessionId);
      return;
    }
    if (result.unsupportedTokenMethod) {
      const log = result.unsupportedTokenMethod.startsWith('Runtime.') ? console.log : console.warn;
      log(`[cdp] sid=${this.sid} token observed in ${result.unsupportedTokenMethod} (not substituted)`);
    }
    if (result.substitutions > 0) {
      console.log(`[cdp] sid=${this.sid} outbound substitutions=${result.substitutions}`);
    }
    this.forwardUpstream(result.payload, false);
  }

  /** Track the per-connection state needed for a login window. Pure bookkeeping. */
  private trackOutbound(raw: string): void {
    // Keep origin tracking working (also used by the login origin check).
    if (raw.indexOf('"Page.navigate') !== -1 || raw.indexOf('"Page.reload"') !== -1 || raw.indexOf('\\') !== -1) {
      const parsed = parseJson(raw);
      if (parsed) this.origins.onOutbound(parsed);
    }
    if (
      raw.indexOf('ScriptToEvaluateOnNewDocument') === -1 &&
      raw.indexOf('Fetch.enable') === -1 &&
      raw.indexOf('Fetch.disable') === -1 &&
      raw.indexOf('setRequestInterception') === -1 &&
      raw.indexOf('\\') === -1
    ) return;
    const msg = parseJson(raw) as CdpMessage | null;
    if (!msg || typeof msg.method !== 'string') return;
    const key = sessionKey(msg);

    switch (msg.method) {
      case 'Page.addScriptToEvaluateOnNewDocument': {
        const source = msg.params?.source;
        // Playwright registers an empty-source script to create its utility
        // world (decision 2); it runs nothing, so it is not tracked or removed.
        if (typeof source === 'string' && source.trim() !== '' && (typeof msg.id === 'number' || typeof msg.id === 'string')) {
          this.pendingAgentAddScript.set(`${key}\0${String(msg.id)}`, key);
        }
        return;
      }
      case 'Page.removeScriptToEvaluateOnNewDocument': {
        const identifier = msg.params?.identifier;
        if (typeof identifier === 'string') this.agentScriptIds.get(key)?.delete(identifier);
        return;
      }
      case 'Fetch.enable':
        this.interception.add(key);
        return;
      case 'Fetch.disable':
        this.interception.delete(key);
        return;
      case 'Network.setRequestInterception': {
        const patterns = msg.params?.patterns;
        if (Array.isArray(patterns) && patterns.length > 0) this.interception.add(key);
        else this.interception.delete(key);
        return;
      }
    }
  }

  private enqueue(payload: string | Buffer, isBinary: boolean): void {
    if (this.agentQueue.length >= this.agentQueueCap) {
      console.warn(`[cdp] sid=${this.sid} agent-queue cap (${this.agentQueueCap}) exceeded during login window`);
      this.teardown();
      return;
    }
    this.agentQueue.push({ payload, isBinary });
  }

  private forwardUpstream(payload: string | Buffer, isBinary: boolean): void {
    if (this.upstreamOpen) {
      this.upstream.send(payload, { binary: isBinary });
      return;
    }
    if (this.pending.length >= this.pendingFrameCap) {
      console.warn(`[cdp] sid=${this.sid} pending-frame cap (${this.pendingFrameCap}) exceeded`);
      sendCdpError(this.clientWs, null, 'CDP proxy buffer overflow before upstream ready');
      this.teardown();
      return;
    }
    this.pending.push({ payload, isBinary });
  }

  // ---------------------------------------------------------------------------
  // upstream → agent
  // ---------------------------------------------------------------------------

  handleUpstreamMessage(data: Buffer, isBinary: boolean): void {
    if (isBinary) {
      if (!this.closed) this.clientWs.send(data, { binary: true });
      return;
    }
    const raw = data.toString();

    // Swallow responses to coatcheck's own commands.
    const id = extractId(raw);
    if (typeof id === 'number' && id >= COATCHECK_ID_BASE) {
      const waiter = this.pendingCoatcheck.get(id);
      if (waiter) {
        this.pendingCoatcheck.delete(id);
        waiter.resolve((parseJson(raw) as CdpMessage) ?? {});
      }
      return; // never relay a coatcheck frame to the agent
    }

    this.trackInbound(raw);

    const result = substituteInbound(raw, this.tokenStore, this.sid);
    if (result.dropped) {
      console.warn(`[cdp] sid=${this.sid} inbound frame dropped (real value present)`);
      return;
    }
    if (result.redactions > 0) {
      console.log(`[cdp] sid=${this.sid} inbound redactions=${result.redactions}`);
    }
    if (!this.closed) this.clientWs.send(result.payload as string, { binary: false });
  }

  /** Track target attach/detach and the identifiers of agent-registered scripts. */
  private trackInbound(raw: string): void {
    const needsParse =
      raw.indexOf('"Page.frame') !== -1 ||
      raw.indexOf('attachedToTarget') !== -1 ||
      raw.indexOf('detachedFromTarget') !== -1 ||
      this.origins.awaitingNavigateResponse ||
      this.pendingAgentAddScript.size > 0;
    if (!needsParse) return;
    const msg = parseJson(raw) as CdpMessage | null;
    if (!msg) return;

    if (msg.method === undefined && msg.id !== undefined) {
      // A response: is it the identifier for an agent addScript we tracked?
      const key = sessionKey(msg);
      const pendKey = `${key}\0${String(msg.id)}`;
      const scriptSession = this.pendingAgentAddScript.get(pendKey);
      if (scriptSession !== undefined) {
        this.pendingAgentAddScript.delete(pendKey);
        const identifier = msg.result?.identifier;
        if (typeof identifier === 'string') {
          let set = this.agentScriptIds.get(scriptSession);
          if (!set) { set = new Set(); this.agentScriptIds.set(scriptSession, set); }
          set.add(identifier);
        }
      }
    }

    this.origins.onInbound(msg);

    switch (msg.method) {
      case 'Target.attachedToTarget': {
        const info = msg.params?.targetInfo as { type?: unknown; targetId?: unknown } | undefined;
        const flatSession = msg.params?.sessionId;
        if (info?.type === 'page' && typeof flatSession === 'string' && typeof info.targetId === 'string') {
          this.pageTargets.set(flatSession, { targetId: info.targetId });
        }
        return;
      }
      case 'Target.detachedFromTarget': {
        const detached = msg.params?.sessionId;
        if (typeof detached === 'string') {
          this.pageTargets.delete(detached);
          this.agentScriptIds.delete(detached);
          this.interception.delete(detached);
        }
        return;
      }
    }
  }

  // ---------------------------------------------------------------------------
  // id multiplexing, queue control — used by the login driver (next commit)
  // ---------------------------------------------------------------------------

  /** Send a coatcheck command upstream and resolve with its response. */
  sendCommand(method: string, params: Record<string, unknown> = {}, flatSessionId?: string): Promise<CdpMessage> {
    if (!this.upstreamOpen || this.closed) return Promise.reject(new Error('upstream not open'));
    const id = this.nextCoatcheckId++;
    const frame: CdpMessage = { id, method, params };
    if (flatSessionId !== undefined) frame.sessionId = flatSessionId;
    return new Promise<CdpMessage>((resolve, reject) => {
      this.pendingCoatcheck.set(id, { resolve, reject });
      try {
        this.upstream.send(JSON.stringify(frame), { binary: false });
      } catch (err) {
        this.pendingCoatcheck.delete(id);
        reject(err as Error);
      }
    });
  }

  /** Begin quiescing the agent: frames from here are queued, not forwarded. */
  beginWindow(): void { this.queueing = true; }

  /** Release queued agent frames in order and resume normal forwarding. */
  endWindow(): void {
    this.queueing = false;
    const drained = this.agentQueue.splice(0, this.agentQueue.length);
    for (const { payload, isBinary } of drained) {
      if (this.closed) break;
      this.handleAgentMessage(typeof payload === 'string' ? Buffer.from(payload) : payload, isBinary);
    }
  }

  get queuedCount(): number { return this.agentQueue.length; }

  // ---------------------------------------------------------------------------
  // CdpController: broker-performed login
  // ---------------------------------------------------------------------------

  async login(req: LoginRequest): Promise<LoginResult> {
    if (this.loginInProgress) return { status: 409, reason: 'busy' };
    this.loginInProgress = true;
    try {
      return await runLogin(this, req);
    } finally {
      this.loginInProgress = false;
    }
  }

  // ---------------------------------------------------------------------------
  // lifecycle
  // ---------------------------------------------------------------------------

  get isUpstreamOpen(): boolean { return this.upstreamOpen; }

  onUpstreamOpen(): void {
    this.upstreamOpen = true;
    for (const { payload, isBinary } of this.pending) this.upstream.send(payload, { binary: isBinary });
    this.pending.length = 0;
  }

  teardown(): void {
    if (this.closed) return;
    this.closed = true;
    for (const waiter of this.pendingCoatcheck.values()) waiter.reject(new Error('connection closed'));
    this.pendingCoatcheck.clear();
    this.onTeardown();
  }
}

/**
 * Start the CDP WebSocket proxy. The agent's Playwright client connects to
 * `ws://{bindHost}:{port}/cdp/{sid}`; we look the sid up in the session store,
 * dial the real Browserbase connectUrl, and relay frames both ways. Each
 * connection gets a `CdpConnection` attached to the session store so the vault
 * handler can drive a broker-performed login over it.
 */
export function startCdpProxy(opts: CdpProxyOptions): Promise<CdpProxyHandle> {
  const {
    tokenStore,
    cdpSessionStore,
    port = DEFAULT_PORT,
    bindHost = '127.0.0.1',
    pendingFrameCap = DEFAULT_PENDING_FRAME_CAP,
    upstreamTimeoutMs = DEFAULT_UPSTREAM_TIMEOUT_MS,
    agentQueueCap = DEFAULT_AGENT_QUEUE_CAP,
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
    cdpSessionStore.markConnected(sid);
    console.log(`[cdp] session sid=${sid} adapter=${cdpSessionStore.adapterName(sid) ?? 'unknown'} connected, dialling upstream`);

    const upstream = new WebSocket(realConnectUrl);

    let tornDown = false;
    function teardown() {
      if (tornDown) return;
      tornDown = true;
      clearTimeout(upstreamTimer);
      activeConnections--;
      const revoked = tokenStore.revokeSession(sid!);
      cdpSessionStore.revoke(sid!);
      console.log(`[cdp] sid=${sid} closed, revoked ${revoked} token(s)`);
      try { clientWs.close(); } catch { /* ignore */ }
      try { upstream.close(); } catch { /* ignore */ }
    }

    const conn = new CdpConnection(sid, clientWs, upstream, tokenStore, pendingFrameCap, agentQueueCap, teardown);
    cdpSessionStore.attach(sid, conn);

    const upstreamTimer = setTimeout(() => {
      if (!conn.isUpstreamOpen) {
        console.warn(`[cdp] sid=${sid} upstream connect timeout`);
        teardown();
      }
    }, upstreamTimeoutMs);
    upstreamTimer.unref();

    clientWs.on('message', (data: Buffer, isBinary: boolean) => conn.handleAgentMessage(data, isBinary));
    clientWs.on('close', () => { conn.teardown(); });
    clientWs.on('error', (e: Error) => { console.error(`[cdp] sid=${sid} client error: ${e.message}`); conn.teardown(); });

    upstream.on('open', () => {
      clearTimeout(upstreamTimer);
      conn.onUpstreamOpen();
      console.log(`[cdp] sid=${sid} upstream open, relaying`);
    });
    upstream.on('message', (data: Buffer, isBinary: boolean) => conn.handleUpstreamMessage(data, isBinary));
    upstream.on('close', () => { conn.teardown(); });
    upstream.on('error', (e: Error) => { console.error(`[cdp] sid=${sid} upstream error: ${e.message}`); conn.teardown(); });
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
            for (const client of wss.clients) client.terminate();
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

/** The numeric/string `id` of a frame, or undefined, via a cheap scan then parse. */
function extractId(raw: string): number | string | undefined {
  if (raw.indexOf('"id"') === -1) return undefined;
  const parsed = parseJson(raw);
  const id = parsed?.id;
  return typeof id === 'number' || typeof id === 'string' ? id : undefined;
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

function parseJson(raw: string): Record<string, unknown> | null {
  try {
    const parsed: unknown = JSON.parse(raw);
    return parsed !== null && typeof parsed === 'object' ? parsed as Record<string, unknown> : null;
  } catch {
    return null;
  }
}

/** The `id` and flattened `sessionId` of a request, so an error reaches the waiting call. */
function extractFrameRouting(raw: string): { id: unknown; sessionId?: string } {
  const parsed = parseJson(raw);
  return {
    id: parsed?.id ?? null,
    sessionId: typeof parsed?.sessionId === 'string' ? parsed.sessionId : undefined,
  };
}

export function sendCdpError(clientWs: WebSocket, id: unknown, message: string, sessionId?: string): void {
  if (clientWs.readyState !== WebSocket.OPEN) return;
  clientWs.send(
    JSON.stringify({
      id: typeof id === 'number' || typeof id === 'string' ? id : 0,
      ...(sessionId !== undefined ? { sessionId } : {}),
      error: { code: CDP_ERROR_CODE, message },
    }),
    { binary: false },
  );
}
