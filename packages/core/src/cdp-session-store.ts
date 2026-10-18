import { randomBytes } from 'node:crypto';

const DEFAULT_TTL_SECONDS = 600; // 10 minutes — covers session create → connect latency
const CLEANUP_INTERVAL_MS = 30_000;

interface CdpSession {
  sid: string;
  realConnectUrl: string;
  /** The browser adapter that registered it, for logs. */
  adapterName: string;
  createdAt: number;
  expiresAt: number;
}

/**
 * Maps short session ids to the real remote-browser CDP URL.
 *
 * When the agent creates a Browserbase session, the proxy rewrites the
 * response's `connectUrl` to `ws://127.0.0.1:{CDP_PROXY_PORT}/cdp/{sid}` and
 * records the real URL here. When the agent's Playwright client then connects
 * to that local URL, the CDP proxy looks the sid up to find the upstream to
 * dial. The sid is opaque so it carries no signing-key material into the agent.
 */
/**
 * The per-connection CDP controller the vault handler drives for
 * `POST /_vault/{name}/login`. Implemented by `CdpConnection` in `cdp/proxy.ts`;
 * the vault handler only needs this surface. Attached while a client is
 * connected on the sid, cleared at teardown.
 */
export interface CdpController {
  login(req: LoginRequest): Promise<LoginResult>;
}

/** A broker-performed login request (design: docs/design/cdp-broker-login.md). */
export interface LoginRequest {
  /** Field label (the multi-value secret's field) → CSS selector. */
  fields: Record<string, string>;
  /** Real value per field label; never logged. */
  values: Record<string, string>;
  /** Fields listed as `_cleartext` on the secret (filled but not redacted). */
  cleartextFields?: string[];
  /** Secret name, for logs only. */
  secretName: string;
  /** The secret's allowed hosts; the page's committed origin must match. */
  allowedHosts?: readonly import('./host-matcher.js').HostPattern[];
  /** Which page target to drive (prefix-matched against committed URLs). */
  pageUrlPrefix?: string;
  /** CSS selector to click, or Enter on the last filled field. */
  submit: { selector: string } | { press: 'Enter' };
  until: { kind: 'navigation' } | { kind: 'selector'; selector: string } | { kind: 'urlPrefix'; urlPrefix: string };
  timeoutMs: number;
}

export type LoginResult =
  | { status: 200; url: string }
  | { status: 403; error: string }
  | { status: 404; field?: string; reason: 'selector-not-found' | 'unknown-sid-or-secret' }
  | { status: 409; reason: 'no-success' | 'interception-active' | 'busy' | 'page-ambiguous'; cleared?: boolean }
  | { status: 501 }
  | { status: 502; reason: 'driver-error' | 'upstream-closed'; cleared?: boolean };

export class CdpSessionStore {
  private sessions = new Map<string, CdpSession>();
  private controllers = new Map<string, CdpController>();
  private cleanupTimer: NodeJS.Timeout;

  constructor() {
    this.cleanupTimer = setInterval(() => this.evictExpired(), CLEANUP_INTERVAL_MS);
    this.cleanupTimer.unref();
  }

  /** Register a real connectUrl, returning the opaque sid to hand the agent. */
  register(realConnectUrl: string, adapterName = 'unknown', ttlSeconds = DEFAULT_TTL_SECONDS): string {
    const sid = randomBytes(12).toString('hex');
    const now = Date.now();
    this.sessions.set(sid, {
      sid,
      realConnectUrl,
      adapterName,
      createdAt: now,
      expiresAt: now + ttlSeconds * 1000,
    });
    return sid;
  }

  /** Resolve a sid to its real connectUrl, or null if unknown/expired. */
  get(sid: string): string | null {
    const entry = this.sessions.get(sid);
    if (!entry) return null;
    if (Date.now() > entry.expiresAt) {
      this.sessions.delete(sid);
      return null;
    }
    return entry.realConnectUrl;
  }

  /** True while `sid` is live: registered and not expired, revoked, or (once connected) closed. */
  has(sid: string): boolean {
    return this.get(sid) !== null;
  }

  /**
   * A client connected: the sid stays live until `revoke` (connection
   * teardown) instead of expiring at its TTL, so a long session can still mint.
   */
  markConnected(sid: string): void {
    const entry = this.sessions.get(sid);
    if (entry) entry.expiresAt = Number.POSITIVE_INFINITY;
  }

  /** The adapter that registered a live sid, or null if unknown/expired. */
  adapterName(sid: string): string | null {
    return this.get(sid) === null ? null : this.sessions.get(sid)!.adapterName;
  }

  /**
   * Attach the live connection's controller for `sid` (decision 1 in the
   * design): the login handler looks it up here. A sid is "connected" for
   * `/login` exactly while a controller is attached.
   */
  attach(sid: string, controller: CdpController): void {
    this.controllers.set(sid, controller);
  }

  /** The attached controller for a connected sid, or null. */
  controller(sid: string): CdpController | null {
    return this.controllers.get(sid) ?? null;
  }

  /** Drop a session mapping and any attached controller. Called when its WS connection closes. */
  revoke(sid: string): void {
    this.sessions.delete(sid);
    this.controllers.delete(sid);
  }

  get size(): number {
    return this.sessions.size;
  }

  private evictExpired(): void {
    const now = Date.now();
    for (const [sid, entry] of this.sessions) {
      if (now > entry.expiresAt) this.sessions.delete(sid);
    }
  }

  destroy(): void {
    clearInterval(this.cleanupTimer);
  }
}
