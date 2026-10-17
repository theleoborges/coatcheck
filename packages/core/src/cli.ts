#!/usr/bin/env node
import fs from 'node:fs';
import { ConfigError, loadConfig, type Config } from './config.js';
import { loadProvider } from './load-provider.js';
import type { SecretProvider } from './secret-provider.js';
import { startCoatcheck } from './start.js';

// The bin is the only module (besides config.ts) that touches process.env;
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
let provider: SecretProvider;
try {
  config = loadConfig(env, path => fs.readFileSync(path, 'utf8'));
  provider = await loadProvider(config.provider, { env, agentId: config.agentId });
} catch (err) {
  exitOnConfigError(err);
}

let running: Awaited<ReturnType<typeof startCoatcheck>>;
try {
  running = await startCoatcheck({ config, provider });
} catch (err) {
  console.error('Failed to start coatcheck:', err);
  process.exit(1);
}

const { port } = running;
console.log(`coatcheck listening on ${config.bindHost}:${port} (provider=${provider.name}${config.agentId ? ` agent=${config.agentId}` : ''})`);
console.log(`Vault API: http://localhost:${port}/_vault`);
console.log(config.policyFile
  ? `Policy: ${config.policyFile} (${config.policy.secrets.length} secret rule(s), ${config.policy.shared.size} shared secret(s))`
  : 'Policy: none (no shared secrets; set COATCHECK_POLICY_FILE)');
console.log(config.apiToken
  ? 'API token: required (vault API: Authorization: Bearer; proxy: Proxy-Authorization)'
  : 'API token: none (listeners are open to anything on this host; loopback only)');
console.log(`MITM: ${config.mitm}${config.passthroughHosts.length ? ` (${config.passthroughHosts.length} passthrough host pattern(s))` : ''}`);
if (config.allowUnboundSecrets) {
  console.warn('WARNING: COATCHECK_ALLOW_UNBOUND_SECRETS=1: secrets with no allowed hosts get tickets that swap for ANY host');
}
if (!running.cdp) console.log('CDP proxy disabled (set COATCHECK_CDP_ENABLED=1 to enable)');

// Graceful shutdown
process.on('SIGTERM', () => {
  console.log('Shutting down coatcheck...');
  running.close().then(() => process.exit(0), () => process.exit(1));
});
