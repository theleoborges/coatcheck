import { TokenStore } from './token-store.js';
import { CertAuthority } from './ca.js';
import { CdpSessionStore } from './cdp-session-store.js';
import { startCdpProxy, type CdpProxyHandle } from './cdp/proxy.js';
import { createCoatcheck, type Coatcheck } from './server.js';
import type { Config } from './config.js';
import { withProviderCache, type SecretProvider } from './secret-provider.js';
import { builtinBrowserAdapters, type BrowserAdapter } from './browser-adapters.js';

export interface StartOptions {
  config: Config;
  /** Uncached; `startCoatcheck` wraps it in `withCache` per `config.secretCacheTtlSeconds`. */
  provider: SecretProvider;
  /** Browser adapters to use instead of the built-ins named by `config.browserAdapters`. */
  adapters?: BrowserAdapter[];
}

export interface RunningCoatcheck {
  coatcheck: Coatcheck;
  tokenStore: TokenStore;
  ca: CertAuthority;
  /** The proxy + vault API port (resolved when `config.port` is 0). */
  port: number;
  /** Set when CDP injection is enabled. */
  cdp?: CdpProxyHandle;
  /** Close the CDP proxy (revoking session tickets), the server, and the provider. */
  close(): Promise<void>;
}

/**
 * Library entrypoint: build every dependency from `config`, listen on the
 * proxy port and, when enabled, the CDP port. The `coatcheck` bin is a thin
 * wrapper that reads the environment and calls this.
 */
export async function startCoatcheck(opts: StartOptions): Promise<RunningCoatcheck> {
  const { config } = opts;
  const provider = withProviderCache(opts.provider, config.secretCacheTtlSeconds * 1000);
  const tokenStore = new TokenStore({ defaultTtlSeconds: config.ticketTtlSeconds });
  // No CA dir: ephemeral in-memory CA. Set: the CA key + cert persist there.
  const ca = await CertAuthority.create({ dir: config.ca.dir, subject: config.ca.subject });
  const cdpSessionStore = new CdpSessionStore();

  const coatcheck = createCoatcheck({
    tokenStore,
    provider,
    ca,
    cdpSessionStore,
    cdp: config.cdp,
    browserAdapters: opts.adapters ?? builtinBrowserAdapters(config.browserAdapters),
    missingSecretUrl: config.missingSecretUrl,
    policy: config.policy,
    allowUnboundSecrets: config.allowUnboundSecrets,
    mitm: config.mitm,
    passthroughHosts: config.passthroughHosts,
    apiToken: config.apiToken,
  });

  const { port } = await coatcheck.listen(config.port, config.bindHost);
  let cdp: CdpProxyHandle | undefined;
  try {
    if (config.cdp) {
      cdp = await startCdpProxy({ tokenStore, cdpSessionStore, port: config.cdp.port, bindHost: config.bindHost });
    }
  } catch (err) {
    await coatcheck.close();
    await opts.provider.close?.();
    throw err;
  }

  return {
    coatcheck,
    tokenStore,
    ca,
    port,
    cdp,
    async close() {
      await cdp?.close();
      await coatcheck.close();
      await opts.provider.close?.();
    },
  };
}
