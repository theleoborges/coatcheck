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
  /** Also swapped in request bodies (opt-in per secret), snapshotted at mint. */
  swapBody: boolean;
}

export interface IssueOptions {
  /** Default: the store's `defaultTtlSeconds`. */
  ttlSeconds?: number;
  /** Hosts the ticket may be swapped for. Omit only for an unbound ticket (`COATCHECK_ALLOW_UNBOUND_SECRETS`). */
  allowedHosts?: readonly HostPattern[];
  /** Bind to a CDP session: substitutes only on that session's frames, revoked when it closes. */
  sessionId?: string;
  /** Also substitute in HTTP(S) request bodies (see replaceAllInBody). Default false. */
  swapBody?: boolean;
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
  /**
   * replaceAllInBody only: tickets present in the body whose secret doesn't
   * opt in to body swapping. Left as literals; they never deny.
   */
  skipped?: SwapInfo[];
  /**
   * Tickets whose real value the encoder refused (it can't be represented
   * where the ticket sits, e.g. CR/LF in a header). When non-empty, nothing is
   * swapped and the caller must not forward the request.
   */
  invalid?: SwapInfo[];
}

/** Adapts a real value to where it lands; null = it can't be represented there. */
export type ValueEncoder = (value: string) => string | null;

/**
 * Replace every ticket id in one pass, so a real value that happens to contain
 * another ticket literal is never substituted again. A replacer function keeps
 * `$&` etc. in values literal.
 */
function substitute(input: string, replacements: ReadonlyMap<string, string>): string {
  if (replacements.size === 0) return input;
  return input.replace(TICKET_PATTERN, id => replacements.get(id) ?? id);
}

/**
 * In-memory store for proxy tokens.
 * Maps opaque token IDs to real secret values.
 * Tokens expire after a configurable TTL.
 */
export class TokenStore {
  private tokens = new Map<string, TokenEntry>();
  /**
   * Real values registered for a CDP session's inbound-redaction set that are
   * not tickets (broker-performed login: the login's field values for the life
   * of the window). Dropped by `revokeSession` at teardown.
   */
  private sessionValueSets = new Map<string, SessionValue[]>();
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
      swapBody: opts.swapBody ?? false,
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
   * `encode` adapts each real value to where it lands (percent-encoding in a
   * URL); when it returns null the value can't be represented there, nothing
   * is swapped, and the ticket is reported in `invalid`.
   */
  replaceAll(input: string, target: MatchTarget, encode: ValueEncoder = v => v): SwapResult {
    return this.replaceHttp(input, target, false, encode);
  }

  /**
   * Like replaceAll, for a request body: only tickets whose secret opts in to
   * body swapping (`swapBody`) are candidates, and each real value goes
   * through `encode` (escaping for the body's content type). Tickets of other
   * secrets are reported in `skipped` and left as literals.
   */
  replaceAllInBody(input: string, target: MatchTarget, encode: ValueEncoder): SwapResult {
    return this.replaceHttp(input, target, true, encode);
  }

  private replaceHttp(input: string, target: MatchTarget, body: boolean, encode: ValueEncoder): SwapResult {
    const swaps: SwapInfo[] = [];
    const denied: SwapInfo[] = [];
    const invalid: SwapInfo[] = [];
    const skipped: SwapInfo[] = [];
    const replacements = new Map<string, string>();
    const now = Date.now();

    for (const [tokenId, entry] of this.ticketsIn(input, now)) {
      // Session-scoped tokens (CDP credential injection) must never substitute
      // on the agent-wide HTTP/TLS path — they only resolve inside their WS session.
      if (entry.sessionId !== undefined) continue;
      const info: SwapInfo = { secretName: entry.secretName, ageMs: now - entry.createdAt };
      if (body && !entry.swapBody) {
        skipped.push(info);
        continue;
      }
      if (entry.allowedHosts === undefined) {
        info.unbound = true;
      } else if (!matchesHost(entry.allowedHosts, target)) {
        denied.push(info);
        continue;
      }
      const value = encode(entry.realValue);
      if (value === null) {
        invalid.push(info);
        continue;
      }
      replacements.set(tokenId, value);
      swaps.push(info);
    }

    const extra = { ...(body ? { skipped } : {}), ...(invalid.length > 0 ? { invalid } : {}) };
    if (denied.length > 0 || invalid.length > 0) return { output: input, swaps: [], denied, ...extra };
    return { output: substitute(input, replacements), swaps, denied, ...extra };
  }

  /**
   * True when a live HTTP(S) ticket could be swapped for `target`: one bound to
   * it, or any unbound ticket. Session-bound tickets don't count (they never
   * swap on HTTP(S)). Drives the `COATCHECK_MITM=bound` decision.
   */
  hasLiveTicketFor(target: MatchTarget): boolean {
    return this.hasLiveHttpTicket(target, false);
  }

  /**
   * True when a live `swapBody` ticket could be swapped in a body for
   * `target`: decides whether a request body is buffered or streamed.
   */
  hasLiveBodyTicketFor(target: MatchTarget): boolean {
    return this.hasLiveHttpTicket(target, true);
  }

  private hasLiveHttpTicket(target: MatchTarget, swapBodyOnly: boolean): boolean {
    const now = Date.now();
    for (const entry of this.tokens.values()) {
      if (swapBodyOnly && !entry.swapBody) continue;
      if (now > entry.expiresAt || entry.sessionId !== undefined) continue;
      if (entry.allowedHosts === undefined || matchesHost(entry.allowedHosts, target)) return true;
    }
    return false;
  }

  /**
   * Live tickets whose ids appear in `input`, found with one pattern scan
   * rather than a substring search per live ticket. Expired ones met on the
   * way are evicted.
   */
  private ticketsIn(input: string, now: number): Array<[string, TokenEntry]> {
    if (this.tokens.size === 0 || !input.includes(TICKET_PREFIX)) return [];
    const out: Array<[string, TokenEntry]> = [];
    for (const id of new Set(input.match(TICKET_PATTERN) ?? [])) {
      const entry = this.tokens.get(id);
      if (!entry) continue;
      if (now > entry.expiresAt) {
        this.tokens.delete(id);
        continue;
      }
      out.push([id, entry]);
    }
    return out;
  }

  /**
   * Like replaceAll, but only substitutes tokens minted for the given CDP
   * session, for a page at `origin` (the session's committed main-frame
   * origin, or null when unknown). Used on the CDP proxy's outbound leg.
   * A ticket bound to other hosts, or any ticket while the origin is unknown,
   * is reported in `denied` and nothing is swapped. Unbound session tickets
   * swap on any known origin.
   */
  replaceAllForSession(input: string, sessionId: string, origin: MatchTarget | null): SwapResult {
    const swaps: SwapInfo[] = [];
    const denied: SwapInfo[] = [];
    const replacements = new Map<string, string>();
    const now = Date.now();

    for (const [tokenId, entry] of this.ticketsIn(input, now)) {
      if (entry.sessionId !== sessionId) continue;
      const info: SwapInfo = { secretName: entry.secretName, ageMs: now - entry.createdAt };
      if (origin === null) {
        denied.push(info);
        continue;
      }
      if (entry.allowedHosts === undefined) {
        info.unbound = true;
      } else if (!matchesHost(entry.allowedHosts, origin)) {
        denied.push(info);
        continue;
      }
      replacements.set(tokenId, entry.realValue);
      swaps.push(info);
    }

    if (denied.length > 0) return { output: input, swaps: [], denied };
    return { output: substitute(input, replacements), swaps, denied };
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
    const registered = this.sessionValueSets.get(sessionId);
    if (registered) out.push(...registered);
    return out;
  }

  /**
   * Register real values for a session's inbound-redaction set without minting
   * tickets (broker-performed login). They never substitute anywhere; they are
   * only matched by the CDP proxy's inbound redactor and dropped at teardown.
   */
  registerSessionValues(sessionId: string, values: SessionValue[]): void {
    const nonEmpty = values.filter(v => v.value.length > 0);
    if (nonEmpty.length === 0) return;
    const existing = this.sessionValueSets.get(sessionId) ?? [];
    this.sessionValueSets.set(sessionId, [...existing, ...nonEmpty]);
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
    this.sessionValueSets.delete(sessionId);
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
