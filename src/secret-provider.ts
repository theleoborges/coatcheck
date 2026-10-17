/**
 * Secret backends sit behind this interface (design: docs/design/v1-decisions.md §2).
 * Core never talks to a specific store; it validates names, then calls a provider.
 */

export interface Secret {
  value: string;
  /** Provider-native host policy (e.g. tags). Unused in v1; in-band `_allowed_hosts` is parsed by core. */
  allowedHosts?: string[];
}

export interface SecretStore {
  get(name: string): Promise<Secret | null>;
  exists(name: string): Promise<boolean>;
  list(): Promise<string[]>;
  /** Absent: the store is read-only and `/_vault/{name}/refresh` returns 501. */
  put?(name: string, value: string): Promise<void>;
}

export interface SecretProvider {
  readonly name: string;
  /** Per-agent secrets (`/_vault/*`). */
  secrets: SecretStore;
  /** Shared, allowlisted secrets (`/_secret/*`). Absent: `/_secret/*` returns 404. */
  shared?: Pick<SecretStore, 'get'>;
  close?(): Promise<void>;
}

export interface ProviderContext {
  env: Readonly<Record<string, string | undefined>>;
  agentId?: string;
}

export type CreateProvider = (ctx: ProviderContext) => Promise<SecretProvider>;

/** Names core accepts before any provider call: no `/`, no leading `.`, so no traversal. */
export const SECRET_NAME_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;

export function isValidSecretName(name: string): boolean {
  return SECRET_NAME_PATTERN.test(name);
}

type Readable = Pick<SecretStore, 'get'> & Partial<SecretStore>;

/**
 * Cache `get` results for `ttlMs` (found secrets only). `put` writes through and
 * invalidates the entry; `exists` and `list` are not cached.
 */
export function withCache<T extends Readable>(store: T, ttlMs: number): T {
  const cache = new Map<string, { secret: Secret; fetchedAt: number }>();
  const cached: Readable = {
    async get(name) {
      const hit = cache.get(name);
      if (hit && Date.now() - hit.fetchedAt < ttlMs) return hit.secret;
      const secret = await store.get(name);
      if (secret !== null) cache.set(name, { secret, fetchedAt: Date.now() });
      else cache.delete(name);
      return secret;
    },
  };
  if (store.exists) cached.exists = name => store.exists!(name);
  if (store.list) cached.list = () => store.list!();
  if (store.put) {
    cached.put = async (name, value) => {
      await store.put!(name, value);
      cache.delete(name);
    };
  }
  return cached as T;
}

/** Wrap a provider's per-agent store in `withCache`. `ttlMs` 0 leaves it uncached. */
export function withProviderCache(provider: SecretProvider, ttlMs: number): SecretProvider {
  if (ttlMs <= 0) return provider;
  return { ...provider, secrets: withCache(provider.secrets, ttlMs) };
}
