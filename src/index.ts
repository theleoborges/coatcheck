import fs from 'node:fs';
import { TokenStore } from './token-store.js';
import { CertAuthority } from './ca.js';
import { CdpSessionStore } from './cdp-session-store.js';
import { startCdpProxy } from './cdp/proxy.js';
import { createCoatcheck } from './server.js';
import { ConfigError, loadConfig, type Config } from './config.js';
import { loadProvider } from './providers/index.js';
import { withProviderCache, type SecretProvider } from './secret-provider.js';

// The entrypoint is the only module (besides config.ts) that touches process.env;
// everything below receives parsed configuration.
const env = process.env;

function exitOnConfigError(err: unknown): never {
  if (err instanceof ConfigError) {
    console.error(err.message);
    process.exit(1);
  }
  throw err;
}

let config: Config;
let rawProvider: SecretProvider;
try {
  config = loadConfig(env, path => fs.readFileSync(path, 'utf8'));
  rawProvider = await loadProvider(config.provider, { env, agentId: config.agentId });
} catch (err) {
  exitOnConfigError(err);
}

const provider = withProviderCache(rawProvider, config.secretCacheTtlSeconds * 1000);
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
  missingSecretUrl: config.missingSecretUrl,
  policy: config.policy,
  allowUnboundSecrets: config.allowUnboundSecrets,
  mitm: config.mitm,
  passthroughHosts: config.passthroughHosts,
});

const { port } = await coatcheck.listen(config.port, config.bindHost);
console.log(`coatcheck listening on ${config.bindHost}:${port} (provider=${provider.name}${config.agentId ? ` agent=${config.agentId}` : ''})`);
console.log(`Vault API: http://localhost:${port}/_vault`);
console.log(config.policyFile
  ? `Policy: ${config.policyFile} (${config.policy.secrets.length} secret rule(s), ${config.policy.shared.size} shared secret(s))`
  : 'Policy: none (no shared secrets; set COATCHECK_POLICY_FILE)');
console.log(`MITM: ${config.mitm}${config.passthroughHosts.length ? ` (${config.passthroughHosts.length} passthrough host pattern(s))` : ''}`);
if (config.allowUnboundSecrets) {
  console.warn('WARNING: COATCHECK_ALLOW_UNBOUND_SECRETS=1: secrets with no allowed hosts get tickets that swap for ANY host');
}

let cdpProxyHandle: { close(): Promise<void> } | null = null;
if (config.cdp) {
  startCdpProxy({ tokenStore, cdpSessionStore, port: config.cdp.port, bindHost: config.bindHost })
    .then(handle => { cdpProxyHandle = handle; })
    .catch(err => {
      console.error('Failed to start CDP proxy:', err);
      process.exit(1);
    });
} else {
  console.log('CDP proxy disabled (set COATCHECK_CDP_ENABLED=1 to enable)');
}

// Graceful shutdown
process.on('SIGTERM', () => {
  console.log('Shutting down coatcheck...');
  const closeServer = () => { coatcheck.server.close(() => process.exit(0)); };
  if (cdpProxyHandle) {
    cdpProxyHandle.close().then(closeServer).catch(closeServer);
  } else {
    closeServer();
  }
});
