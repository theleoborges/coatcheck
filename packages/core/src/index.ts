/**
 * `@coatcheck/core` library API. The `coatcheck` bin (`cli.ts`) wraps
 * `loadConfig` + `loadProvider` + `startCoatcheck`.
 */
export { startCoatcheck, type StartOptions, type RunningCoatcheck } from './start.js';
export { createCoatcheck, type Coatcheck, type CoatcheckDeps } from './server.js';
export {
  loadConfig, ConfigError, EnvReader, interpolateAgentId, isLoopbackHost, KNOWN_PROVIDERS,
  type Config, type Env, type MitmMode, type ReadFile,
} from './config.js';
export { loadProvider, BUILTIN_PROVIDERS, type ImportModule } from './load-provider.js';
export {
  isValidSecretName, SECRET_NAME_PATTERN, withCache, withProviderCache, InvalidSecretNameError,
  type Secret, type SecretStore, type SecretProvider, type ProviderContext, type CreateProvider,
} from './secret-provider.js';
export { createMemoryProvider, type MemoryProviderInit } from './memory-provider.js';
export { TokenStore, TicketLimitError, TICKET_PREFIX, TICKET_PATTERN } from './token-store.js';
export { CertAuthority, type CertAuthorityOptions } from './ca.js';
export { CdpSessionStore } from './cdp-session-store.js';
export { startCdpProxy, type CdpProxyOptions, type CdpProxyHandle } from './cdp/proxy.js';
export { parsePolicy, EMPTY_POLICY, type Policy, type PolicyRule, type SharedRule } from './policy.js';
export {
  browserbaseAdapter, createBrowserbaseAdapter, BUILTIN_BROWSER_ADAPTERS, BROWSERBASE_API_HOST,
  type BrowserAdapter,
} from './browser-adapters.js';
export {
  createJsonResponseRewriter, UninspectableResponseError, type JsonResponseRewriter, type JsonResponseRewriterOptions, type JsonTransform,
} from './json-response-rewriter.js';
