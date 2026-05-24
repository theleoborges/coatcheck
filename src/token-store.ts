import { randomBytes } from 'node:crypto';

const TOKEN_PREFIX = 'tok_';
const DEFAULT_TTL_SECONDS = 900; // 15 minutes — covers conversational latency between get-secret.sh and outbound call
const CLEANUP_INTERVAL_MS = 30_000; // 30 seconds

/** Matches any issued token ID (32-byte hex). Used to spot un-swapped literals in outbound traffic. */
export const TOKEN_LITERAL_PATTERN = /tok_[a-f0-9]{64}/g;

interface TokenEntry {
  id: string;
  secretName: string;
  realValue: string;
  createdAt: number;
  expiresAt: number;
}

export interface IssuedToken {
  id: string;
  ttlSeconds: number;
}

export interface SwapInfo {
  secretName: string;
  ageMs: number;
}

export interface SwapResult {
  output: string;
  swaps: SwapInfo[];
}

/**
 * In-memory store for proxy tokens.
 * Maps opaque token IDs to real secret values.
 * Tokens expire after a configurable TTL.
 */
export class TokenStore {
  private tokens = new Map<string, TokenEntry>();
  private cleanupTimer: NodeJS.Timeout;

  constructor() {
    // Periodically clean up expired tokens
    this.cleanupTimer = setInterval(() => this.evictExpired(), CLEANUP_INTERVAL_MS);
    this.cleanupTimer.unref();
  }

  /** Issue a new proxy token for a secret */
  issue(secretName: string, realValue: string, ttlSeconds = DEFAULT_TTL_SECONDS): IssuedToken {
    const id = TOKEN_PREFIX + randomBytes(32).toString('hex');
    const now = Date.now();

    this.tokens.set(id, {
      id,
      secretName,
      realValue,
      createdAt: now,
      expiresAt: now + ttlSeconds * 1000,
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
   * Replace all active token IDs in a string with their real values.
   * This is the core of the proxy — scans outbound data for tokens and swaps them.
   * Returns the rewritten string plus per-secret swap info so the call site can log
   * which secrets were swapped and how old the tokens were at swap time (diagnostic).
   */
  replaceAll(input: string): SwapResult {
    if (this.tokens.size === 0) return { output: input, swaps: [] };

    let result = input;
    const swaps: SwapInfo[] = [];
    const now = Date.now();

    for (const [tokenId, entry] of this.tokens) {
      if (now > entry.expiresAt) {
        this.tokens.delete(tokenId);
        continue;
      }
      if (result.includes(tokenId)) {
        result = result.replaceAll(tokenId, entry.realValue);
        swaps.push({ secretName: entry.secretName, ageMs: now - entry.createdAt });
      }
    }

    return { output: result, swaps };
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
