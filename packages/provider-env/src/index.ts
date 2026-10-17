/**
 * `COATCHECK_PROVIDER=env`: secrets from environment variables.
 *
 * Names are restricted to `[a-z0-9-]+` so the mapping is reversible:
 * `github-token` ↔ `COATCHECK_SECRET_GITHUB_TOKEN` (uppercase, `-` → `_`).
 * Shared secrets use `COATCHECK_SHARED_SECRET_`. Read-only: no `put`, so
 * OAuth refresh returns 501.
 */
import {
  ConfigError, EnvReader, InvalidSecretNameError,
  type CreateProvider, type ProviderContext, type Secret, type SecretProvider, type SecretStore,
} from '@coatcheck/core';

export const DEFAULT_ENV_PREFIX = 'COATCHECK_SECRET_';
export const SHARED_ENV_PREFIX = 'COATCHECK_SHARED_SECRET_';
export const ENV_SECRET_NAME = /^[a-z0-9-]+$/;
const ENV_PREFIX = /^[A-Z][A-Z0-9_]*$/;
/** Core settings that fall under the default prefix; never secrets. */
const RESERVED_ENV_NAMES: ReadonlySet<string> = new Set(['COATCHECK_SECRET_CACHE_TTL_SECONDS']);

/** `github-token` → `GITHUB_TOKEN`. Throws `InvalidSecretNameError` outside `[a-z0-9-]+`. */
export function envSuffixFor(name: string): string {
  if (!ENV_SECRET_NAME.test(name)) {
    throw new InvalidSecretNameError(`The env provider accepts only [a-z0-9-]+ secret names (got '${name}')`);
  }
  return name.toUpperCase().replace(/-/g, '_');
}

/** `GITHUB_TOKEN` → `github-token`, or null when the suffix doesn't map back. */
export function nameForEnvSuffix(suffix: string): string | null {
  if (!/^[A-Z0-9_]+$/.test(suffix)) return null;
  const name = suffix.toLowerCase().replace(/_/g, '-');
  return ENV_SECRET_NAME.test(name) ? name : null;
}

export interface EnvProviderConfig {
  prefix: string;
}

export function loadEnvConfig(ctx: ProviderContext): EnvProviderConfig {
  const r = new EnvReader(ctx.env);
  const prefix = r.string('COATCHECK_ENV_PREFIX') ?? DEFAULT_ENV_PREFIX;
  if (!ENV_PREFIX.test(prefix)) {
    r.problems.push(`COATCHECK_ENV_PREFIX must be an uppercase variable-name prefix like ${DEFAULT_ENV_PREFIX} (got '${prefix}')`);
  } else if (prefix === SHARED_ENV_PREFIX || SHARED_ENV_PREFIX.startsWith(prefix) || prefix.startsWith(SHARED_ENV_PREFIX)) {
    r.problems.push(`COATCHECK_ENV_PREFIX must not overlap ${SHARED_ENV_PREFIX} (shared secrets)`);
  }
  if (r.problems.length > 0) throw new ConfigError(r.problems);
  return { prefix };
}

/** Snapshot `env` at startup; later changes to the process environment are not seen. */
export function createEnvProvider(env: ProviderContext['env'], config: EnvProviderConfig): SecretProvider {
  const snapshot = { ...env };
  const read = (prefix: string, name: string): Secret | null => {
    const key = prefix + envSuffixFor(name);
    if (RESERVED_ENV_NAMES.has(key)) return null;
    const value = snapshot[key];
    return value === undefined || value === '' ? null : { value };
  };
  const secrets: SecretStore = {
    get: async name => read(config.prefix, name),
    exists: async name => read(config.prefix, name) !== null,
    list: async () => Object.keys(snapshot)
      .filter(k => k.startsWith(config.prefix) && snapshot[k] && !RESERVED_ENV_NAMES.has(k))
      .map(k => nameForEnvSuffix(k.slice(config.prefix.length)))
      .filter((n): n is string => n !== null)
      .sort(),
  };
  return {
    name: 'env',
    secrets,
    shared: { get: async name => read(SHARED_ENV_PREFIX, name) },
  };
}

const createProvider: CreateProvider = async ctx => createEnvProvider(ctx.env, loadEnvConfig(ctx));
export default createProvider;
