import type { Secret, SecretProvider, SecretStore } from './secret-provider.js';

export interface MemoryProviderInit {
  secrets?: Record<string, string>;
  /** Omit to model a provider without shared secrets. */
  shared?: Record<string, string>;
  /** False: the per-agent store has no `put` (read-only backend). */
  writable?: boolean;
}

/** In-memory provider for tests and embedding. Values live only in this process. */
export function createMemoryProvider(init: MemoryProviderInit = {}): SecretProvider {
  const secrets = new Map(Object.entries(init.secrets ?? {}));
  const toSecret = (v: string | undefined): Secret | null => (v === undefined ? null : { value: v });

  const store: SecretStore = {
    get: async name => toSecret(secrets.get(name)),
    exists: async name => secrets.has(name),
    list: async () => [...secrets.keys()].sort(),
  };
  if (init.writable !== false) {
    store.put = async (name, value) => { secrets.set(name, value); };
  }

  const shared = init.shared ? new Map(Object.entries(init.shared)) : undefined;
  return {
    name: 'memory',
    secrets: store,
    shared: shared ? { get: async name => toSecret(shared.get(name)) } : undefined,
  };
}
