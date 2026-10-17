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
export class CdpSessionStore {
  private sessions = new Map<string, CdpSession>();
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

  /** The adapter that registered a live sid, or null if unknown/expired. */
  adapterName(sid: string): string | null {
    return this.get(sid) === null ? null : this.sessions.get(sid)!.adapterName;
  }

  /** Drop a session mapping. Called when its WS connection closes. */
  revoke(sid: string): void {
    this.sessions.delete(sid);
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
