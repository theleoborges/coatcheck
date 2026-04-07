import { randomBytes } from 'node:crypto';

const TOKEN_PREFIX = 'tok_';
const DEFAULT_TTL_SECONDS = 300; // 5 minutes
const CLEANUP_INTERVAL_MS = 30_000; // 30 seconds

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
   */
  replaceAll(input: string): string {
    if (this.tokens.size === 0) return input;

    let result = input;
    const now = Date.now();

    for (const [tokenId, entry] of this.tokens) {
      if (now > entry.expiresAt) {
        this.tokens.delete(tokenId);
        continue;
      }
      if (result.includes(tokenId)) {
        result = result.replaceAll(tokenId, entry.realValue);
      }
    }

    return result;
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
