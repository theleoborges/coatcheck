import http from 'node:http';
import type { AddressInfo, Socket } from 'node:net';
import type { TokenStore } from './token-store.js';
import type { SecretProvider } from './secret-provider.js';
import type { CertAuthority } from './ca.js';
import type { CdpSessionStore } from './cdp-session-store.js';
import { handleVaultRequest } from './vault-handler.js';
import { EMPTY_POLICY, type Policy } from './policy.js';
import type { HostPattern } from './host-matcher.js';
import type { MitmMode } from './config.js';
import { handleForwardRequest } from './forward.js';
import { createConnectHandler } from './mitm.js';
import { createApiAuth, isOpenVaultPath, PROXY_AUTH_REQUIRED, sendUnauthorized } from './auth.js';

export const BROWSERBASE_API_HOST = 'api.browserbase.com';

export interface CoatcheckDeps {
  tokenStore: TokenStore;
  provider: SecretProvider;
  ca: CertAuthority;
  cdpSessionStore: CdpSessionStore;
  /** Set when CDP injection is enabled: where rewritten connectUrls point. */
  cdp?: { port: number; advertiseHost: string };
  /** Operator policy (`COATCHECK_POLICY_FILE`). Default: empty. */
  policy?: Policy;
  /** `COATCHECK_ALLOW_UNBOUND_SECRETS`. Default: false (unbound secrets get 403 at mint). */
  allowUnboundSecrets?: boolean;
  /** `COATCHECK_MITM`. Default: `bound`. */
  mitm?: MitmMode;
  /** `COATCHECK_PASSTHROUGH_HOSTS`. Default: none. */
  passthroughHosts?: HostPattern[];
  /** `COATCHECK_API_TOKEN`: required on the vault API and the proxy when set. */
  apiToken?: string;
  /** `vault_url` hint in 404s (`COATCHECK_MISSING_SECRET_URL`). */
  missingSecretUrl?: string;
  /** Defaults to `api.browserbase.com`. */
  browserbaseApiHost?: string;
  /** Extra trust anchors for upstream TLS (tests). */
  upstreamCa?: string;
}

export interface Coatcheck {
  server: http.Server;
  listen(port: number, host: string): Promise<AddressInfo>;
  close(): Promise<void>;
}

/**
 * Build the proxy + vault API server: vault routes, plain-HTTP forwarding, and
 * CONNECT (MITM or passthrough). No side effects until `listen`.
 */
export function createCoatcheck(deps: CoatcheckDeps): Coatcheck {
  const vaultDeps = {
    tokenStore: deps.tokenStore,
    provider: deps.provider,
    ca: deps.ca,
    missingSecretUrl: deps.missingSecretUrl,
    policy: deps.policy ?? EMPTY_POLICY,
    allowUnboundSecrets: deps.allowUnboundSecrets ?? false,
  };

  const auth = createApiAuth(deps.apiToken);

  const server = http.createServer((req, res) => {
    const url = req.url ?? '';
    // Absolute-form (`GET http://host/…`) is a proxy request; anything else is the vault API.
    if (/^[a-z][a-z0-9+.-]*:\/\//i.test(url)) {
      if (!auth.proxy(req)) {
        console.warn('[auth] rejected proxy request: missing or invalid Proxy-Authorization');
        req.resume();
        res.writeHead(407, { 'Proxy-Authenticate': 'Basic realm="coatcheck"', 'Content-Length': '0' });
        res.end();
        return;
      }
      handleForwardRequest(req, res, deps.tokenStore);
      return;
    }
    if (!isOpenVaultPath(url) && !auth.vault(req)) {
      console.warn('[auth] rejected API request: missing or invalid Authorization');
      req.resume();
      sendUnauthorized(res);
      return;
    }
    // Handle vault API requests directly
    if (handleVaultRequest(req, res, vaultDeps)) return;
    handleForwardRequest(req, res, deps.tokenStore);
  });

  const onConnect = createConnectHandler({
    tokenStore: deps.tokenStore,
    ca: deps.ca,
    cdpSessionStore: deps.cdpSessionStore,
    cdp: deps.cdp,
    browserbaseApiHost: deps.browserbaseApiHost ?? BROWSERBASE_API_HOST,
    upstreamCa: deps.upstreamCa,
    policy: vaultDeps.policy,
    mitm: deps.mitm ?? 'bound',
    passthroughHosts: deps.passthroughHosts ?? [],
  });
  server.on('connect', (req, socket, head) => {
    if (!auth.proxy(req)) {
      console.warn('[auth] rejected CONNECT: missing or invalid Proxy-Authorization');
      socket.end(PROXY_AUTH_REQUIRED);
      return;
    }
    void onConnect(req, socket as Socket, head);
  });

  return {
    server,
    listen: (port, host) => new Promise((resolve, reject) => {
      server.once('error', reject);
      server.listen(port, host, () => {
        server.off('error', reject);
        resolve(server.address() as AddressInfo);
      });
    }),
    close: () => new Promise(resolve => {
      server.close(() => resolve());
      server.closeAllConnections();
    }),
  };
}
