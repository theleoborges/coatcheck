import http from 'node:http';
import type { AddressInfo, Socket } from 'node:net';
import type { TokenStore } from './token-store.js';
import type { SecretProvider } from './secret-provider.js';
import type { CertAuthority } from './ca.js';
import type { CdpSessionStore } from './cdp-session-store.js';
import { handleVaultRequest } from './vault-handler.js';
import { EMPTY_POLICY, type Policy } from './policy.js';
import type { HostPattern } from './host-matcher.js';
import { DEFAULT_MAX_SWAP_BODY_BYTES, type MitmMode } from './config.js';
import { handleForwardRequest } from './forward.js';
import { createConnectHandler } from './mitm.js';
import { createBrowserbaseAdapter, type BrowserAdapter } from './browser-adapters.js';
import { createApiAuth, isOpenVaultPath, PROXY_AUTH_REQUIRED, sendProxyAuthRequired, sendUnauthorized } from './auth.js';

export { BROWSERBASE_API_HOST } from './browser-adapters.js';

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
  /** Browser adapters for CDP URL rewriting. Default: Browserbase (at `browserbaseApiHost`). */
  browserAdapters?: BrowserAdapter[];
  /** API host of the default Browserbase adapter (tests). Ignored when `browserAdapters` is set. */
  browserbaseApiHost?: string;
  /** Extra trust anchors for upstream TLS (tests). */
  upstreamCa?: string;
  /** `COATCHECK_MAX_SWAP_BODY_BYTES`. Default: 1 MiB. */
  maxSwapBodyBytes?: number;
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
  const maxSwapBodyBytes = deps.maxSwapBodyBytes ?? DEFAULT_MAX_SWAP_BODY_BYTES;
  const vaultDeps = {
    tokenStore: deps.tokenStore,
    provider: deps.provider,
    ca: deps.ca,
    missingSecretUrl: deps.missingSecretUrl,
    policy: deps.policy ?? EMPTY_POLICY,
    allowUnboundSecrets: deps.allowUnboundSecrets ?? false,
    cdpSessionStore: deps.cdpSessionStore,
  };

  const auth = createApiAuth(deps.apiToken);

  const server = http.createServer((req, res) => {
    const url = req.url ?? '';
    // Absolute-form (`GET http://host/…`) is a proxy request; anything else is the vault API.
    if (/^[a-z][a-z0-9+.-]*:\/\//i.test(url)) {
      if (!auth.proxy(req)) {
        console.warn('[auth] rejected proxy request: missing or invalid Proxy-Authorization');
        req.resume();
        sendProxyAuthRequired(res);
        return;
      }
      handleForwardRequest(req, res, deps.tokenStore, maxSwapBodyBytes);
      return;
    }
    if (!isOpenVaultPath(url) && !auth.vault(req)) {
      console.warn('[auth] rejected API request: missing or invalid Authorization');
      req.resume();
      sendUnauthorized(res);
      return;
    }
    if (handleVaultRequest(req, res, vaultDeps)) return;
    // Origin-form but not a vault route: not a proxy request either.
    req.resume();
    res.writeHead(400);
    res.end('Bad request');
  });

  const onConnect = createConnectHandler({
    tokenStore: deps.tokenStore,
    ca: deps.ca,
    cdpSessionStore: deps.cdpSessionStore,
    cdp: deps.cdp,
    browserAdapters: deps.browserAdapters ?? [createBrowserbaseAdapter(deps.browserbaseApiHost)],
    upstreamCa: deps.upstreamCa,
    policy: vaultDeps.policy,
    mitm: deps.mitm ?? 'bound',
    passthroughHosts: deps.passthroughHosts ?? [],
    maxSwapBodyBytes,
  });
  // CONNECT sockets leave the HTTP server's connection tracking, so close()
  // destroys them itself (a tunnel paused for backpressure may never see EOF).
  const tunnels = new Set<Socket>();
  server.on('connect', (req, socket, head) => {
    tunnels.add(socket as Socket);
    socket.once('close', () => tunnels.delete(socket as Socket));
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
      for (const socket of tunnels) socket.destroy();
    }),
  };
}
