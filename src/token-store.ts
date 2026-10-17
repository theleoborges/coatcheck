import { randomBytes } from 'node:crypto';
import { matchesHost, type HostPattern, type MatchTarget } from './host-matcher.js';

/**
 * Prefix of every ticket id ("coatcheck ticket"). Distinctive so tickets are
 * easy to grep for and to register with secret scanners. Single source of truth:
 * the swap logger and the CDP pre-filter use it too.
 */
export const TICKET_PREFIX = 'cct_';
const DEFAULT_TTL_SECONDS = 900; // 15 minutes — covers conversational latency between get-secret.sh and outbound call

export interface TokenStoreOptions {
  /** TTL for tickets issued without an explicit one (`COATCHECK_TICKET_TTL_SECONDS`). */
  defaultTtlSeconds?: number;
}
const CLEANUP_INTERVAL_MS = 30_000; // 30 seconds

/** Matches any issued ticket id (prefix + 32-byte hex). Used to spot un-swapped literals in outbound traffic. */
export const TICKET_PATTERN = new RegExp(`${TICKET_PREFIX}[a-f0-9]{64}`, 'g');

interface TokenEntry {
  id: string;
  secretName: string;
  realValue: string;
  createdAt: number;
  expiresAt: number;
  /**
   * When set, the token only substitutes on traffic for this CDP session
   * (see replaceAllForSession). Unscoped tokens (sessionId undefined) keep the
   * agent-wide behaviour used by the HTTP/platform paths.
   */
  sessionId?: string;
  /** Hosts this ticket may be swapped for, snapshotted at mint. Undefined = unbound. */
  allowedHosts?: readonly HostPattern[];
}

export interface IssueOptions {
  /** Default: the store's `defaultTtlSeconds`. */
  ttlSeconds?: number;
  /** Hosts the ticket may be swapped for. Omit only for an unbound ticket (`COATCHECK_ALLOW_UNBOUND_SECRETS`). */
  allowedHosts?: readonly HostPattern[];
  /** Bind to a CDP session: substitutes only on that session's frames, revoked when it closes. */
  sessionId?: string;
}

export interface SessionValue {
  value: string;
  secretName: string;
}

export interface IssuedToken {
  id: string;
  ttlSeconds: number;
}

export interface SwapInfo {
  secretName: string;
  ageMs: number;
  /** Set when the ticket carries no host binding (swapped for any host). */
  unbound?: true;
}

export interface SwapResult {
  output: string;
  swaps: SwapInfo[];
  /**
   * Tickets present in the input whose allowed hosts don't match the target.
   * When non-empty, nothing is swapped (`output` is the input) and the caller
   * must not forward the request.
   */
  denied: SwapInfo[];
}

/**
 * In-memory store for proxy tokens.
 * Maps opaque token IDs to real secret values.
 * Tokens expire after a configurable TTL.
 */
export class TokenStore {
  private tokens = new Map<string, TokenEntry>();
  private cleanupTimer: NodeJS.Timeout;

  private readonly defaultTtlSeconds: number;

  constructor(opts: TokenStoreOptions = {}) {
    this.defaultTtlSeconds = opts.defaultTtlSeconds ?? DEFAULT_TTL_SECONDS;
    // Periodically clean up expired tokens
    this.cleanupTimer = setInterval(() => this.evictExpired(), CLEANUP_INTERVAL_MS);
    this.cleanupTimer.unref();
  }

  /**
   * Issue a ticket for a secret. With `sessionId` the ticket only substitutes on
   * that CDP session's traffic (replaceAllForSession) and never on HTTP(S).
   */
  issue(secretName: string, realValue: string, opts: IssueOptions = {}): IssuedToken {
    const ttlSeconds = opts.ttlSeconds ?? this.defaultTtlSeconds;
    const id = TICKET_PREFIX + randomBytes(32).toString('hex');
    const now = Date.now();

    this.tokens.set(id, {
      id,
      secretName,
      realValue,
      createdAt: now,
      expiresAt: now + ttlSeconds * 1000,
      sessionId: opts.sessionId,
      allowedHosts: opts.allowedHosts,
    });

    return { id, ttlSeconds };
  }

  /** Resolve a token to its real value, or null if expired/unknown */
  resolve(tokenId: string): string | null {
    const entry = this.tokens.get(tokenId);
    if (!entry) return null;
    if (Date.now() > entry.expiresAt) {
      this.tokens.delete(tokenId);
      return null;
    }
    return entry.realValue;
  }

  /**
   * Replace all active token IDs in a string with their real values, for a
   * request going to `target` (the CONNECT target on HTTPS, the URL host on the
   * forward path). This is the core of the proxy.
   * Returns the rewritten string plus per-secret swap info so the call site can log
   * which secrets were swapped and how old the tokens were at swap time (diagnostic).
   * If any ticket present is bound to other hosts, nothing is swapped and the
   * ticket is reported in `denied`: one denied ticket denies the whole request.
   */
  replaceAll(input: string, target: MatchTarget): SwapResult {
    if (this.tokens.size === 0) return { output: input, swaps: [], denied: [] };

    let result = input;
    const swaps: SwapInfo[] = [];
    const denied: SwapInfo[] = [];
    const now = Date.now();

    for (const [tokenId, entry] of this.tokens) {
      if (now > entry.expiresAt) {
        this.tokens.delete(tokenId);
        continue;
      }
      // Session-scoped tokens (CDP credential injection) must never substitute
      // on the agent-wide HTTP/TLS path — they only resolve inside their WS session.
      if (entry.sessionId !== undefined) continue;
      if (!input.includes(tokenId)) continue;
      const info: SwapInfo = { secretName: entry.secretName, ageMs: now - entry.createdAt };
      if (entry.allowedHosts === undefined) {
        info.unbound = true;
      } else if (!matchesHost(entry.allowedHosts, target)) {
        denied.push(info);
        continue;
      }
      result = result.replaceAll(tokenId, entry.realValue);
      swaps.push(info);
    }

    if (denied.length > 0) return { output: input, swaps: [], denied };
    return { output: result, swaps, denied };
  }

  /**
   * Like replaceAll, but only substitutes tokens minted for the given CDP
   * session. Used on the CDP proxy's outbound (agent → Browserbase) leg so a
   * session's credential tokens resolve only on that session's frames.
   */
  replaceAllForSession(input: string, sessionId: string): SwapResult {
    if (this.tokens.size === 0) return { output: input, swaps: [], denied: [] };

    let result = input;
    const swaps: SwapInfo[] = [];
    const now = Date.now();

    for (const [tokenId, entry] of this.tokens) {
      if (now > entry.expiresAt) {
        this.tokens.delete(tokenId);
        continue;
      }
      if (entry.sessionId !== sessionId) continue;
      if (result.includes(tokenId)) {
        result = result.replaceAll(tokenId, entry.realValue);
        swaps.push({ secretName: entry.secretName, ageMs: now - entry.createdAt });
      }
    }

    // Origin binding on the CDP path is roadmap item 15; nothing is denied here yet.
    return { output: result, swaps, denied: [] };
  }

  /**
   * Active (non-expired) real values for a session, for the CDP proxy's inbound
   * leg: the byte-level pre-scan / drop-frame floor and the echo-back redactor.
   */
  sessionValues(sessionId: string): SessionValue[] {
    const out: SessionValue[] = [];
    const now = Date.now();
    for (const [tokenId, entry] of this.tokens) {
      if (now > entry.expiresAt) {
        this.tokens.delete(tokenId);
        continue;
      }
      if (entry.sessionId !== sessionId) continue;
      out.push({ value: entry.realValue, secretName: entry.secretName });
    }
    return out;
  }

  /** Active token ids minted for a session, for the keystroke fail-closed detector. */
  sessionTokenIds(sessionId: string): string[] {
    const out: string[] = [];
    const now = Date.now();
    for (const [tokenId, entry] of this.tokens) {
      if (now > entry.expiresAt) {
        this.tokens.delete(tokenId);
        continue;
      }
      if (entry.sessionId !== sessionId) continue;
      out.push(tokenId);
    }
    return out;
  }

  /** Evict every token minted for a session. Called when its WS connection closes. */
  revokeSession(sessionId: string): number {
    let revoked = 0;
    for (const [tokenId, entry] of this.tokens) {
      if (entry.sessionId === sessionId) {
        this.tokens.delete(tokenId);
        revoked++;
      }
    }
    return revoked;
  }

  /** Number of active (non-expired) tokens */
  get size(): number {
    return this.tokens.size;
  }

  /** Remove expired tokens */
  private evictExpired(): void {
    const now = Date.now();
    let evicted = 0;
    for (const [tokenId, entry] of this.tokens) {
      if (now > entry.expiresAt) {
        this.tokens.delete(tokenId);
        evicted++;
      }
    }
    if (evicted > 0) {
      console.log(`Evicted ${evicted} expired tokens (${this.tokens.size} active)`);
    }
  }

  /** Shut down cleanup timer */
  destroy(): void {
    clearInterval(this.cleanupTimer);
  }
}
