import { TokenStore } from './token-store.js';
import { createAwsProvider } from './providers/aws.js';
import { CertAuthority } from './ca.js';
import { CdpSessionStore } from './cdp-session-store.js';
import { startCdpProxy } from './cdp/proxy.js';
import { createCoatcheck } from './server.js';

const PROXY_PORT = parseInt(process.env.PROXY_PORT ?? '3128', 10);
const AGENT_LABEL = process.env.AGENT_LABEL;

// CDP credential injection: when enabled, the sidecar runs a CDP WebSocket proxy
// and rewrites Browserbase `connectUrl`s to route the agent's browser session
// through it. Off by default for a flag-gated rollout.
const CDP_PROXY_ENABLED = process.env.CDP_PROXY_ENABLED === '1';
const CDP_PROXY_PORT = parseInt(process.env.CDP_PROXY_PORT ?? '8444', 10);
// Host the agent's Playwright client uses to reach the CDP proxy. In prod the
// sidecar shares the task's network namespace, so 127.0.0.1 is correct. In
// docker-compose dev the agent/client is a separate container reaching the proxy
// via a published port or service name — override with CDP_PROXY_ADVERTISE_HOST.
const CDP_PROXY_ADVERTISE_HOST = process.env.CDP_PROXY_ADVERTISE_HOST ?? '127.0.0.1';

// Bind to 0.0.0.0 in dev (docker-compose port mapping), 127.0.0.1 in prod (sidecar)
const BIND_HOST = process.env.PROXY_BIND_HOST ?? '127.0.0.1';

if (!AGENT_LABEL) {
  console.error('AGENT_LABEL is required');
  process.exit(1);
}

const tokenStore = new TokenStore();
const provider = createAwsProvider({ label: AGENT_LABEL, roleArn: process.env.PROXY_ROLE_ARN });
// CA_DIR unset: ephemeral in-memory CA. Set: the CA key + cert persist there.
const ca = await CertAuthority.create({ dir: process.env.CA_DIR });
const cdpSessionStore = new CdpSessionStore();

const coatcheck = createCoatcheck({
  tokenStore,
  provider,
  ca,
  cdpSessionStore,
  cdp: CDP_PROXY_ENABLED ? { port: CDP_PROXY_PORT, advertiseHost: CDP_PROXY_ADVERTISE_HOST } : undefined,
});

await coatcheck.listen(PROXY_PORT, BIND_HOST);
console.log(`Secret proxy listening on ${BIND_HOST}:${PROXY_PORT}`);
console.log(`Agent label: ${AGENT_LABEL}`);
console.log(`Vault API: http://localhost:${PROXY_PORT}/_vault`);

let cdpProxyHandle: { close(): Promise<void> } | null = null;
if (CDP_PROXY_ENABLED) {
  startCdpProxy({ tokenStore, cdpSessionStore, port: CDP_PROXY_PORT, bindHost: BIND_HOST })
    .then(handle => { cdpProxyHandle = handle; })
    .catch(err => {
      console.error('Failed to start CDP proxy:', err);
      process.exit(1);
    });
} else {
  console.log('CDP proxy disabled (set CDP_PROXY_ENABLED=1 to enable)');
}

// Graceful shutdown
process.on('SIGTERM', () => {
  console.log('Shutting down secret proxy...');
  const closeServer = () => { coatcheck.server.close(() => process.exit(0)); };
  if (cdpProxyHandle) {
    cdpProxyHandle.close().then(closeServer).catch(closeServer);
  } else {
    closeServer();
  }
});
