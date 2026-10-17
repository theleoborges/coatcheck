import http from 'node:http';
import { TokenStore } from './token-store.js';
import type { CertAuthority } from './ca.js';
import { isValidSecretName, type SecretProvider } from './secret-provider.js';
import { policyHostsFor, type Policy } from './policy.js';
import { matchesHost } from './host-matcher.js';
import { allowedHostsJson, parseSecretValue, resolveBinding, userFields, type Binding } from './secret-binding.js';

export interface VaultDeps {
  tokenStore: TokenStore;
  provider: SecretProvider;
  ca: Pick<CertAuthority, 'caCertPem'>;
  /** Where users manage secrets; returned as `vault_url` in 404s when set. */
  missingSecretUrl?: string;
  /** Operator policy: allowed hosts per secret; its `shared` section is the `/_secret/*` allowlist. */
  policy: Policy;
  /** `COATCHECK_ALLOW_UNBOUND_SECRETS`: mint unbound tickets instead of refusing with 403. */
  allowUnboundSecrets?: boolean;
}

/**
 * Handle vault API requests (/_health, /_ca, /_vault).
 * Returns true if the request was handled, false if it should be forwarded as a proxy request.
 */
export function handleVaultRequest(
  req: http.IncomingMessage,
  res: http.ServerResponse,
  deps: VaultDeps,
): boolean {
  const { tokenStore, provider, ca } = deps;
  const url = req.url ?? '';

  // Health check
  if (url === '/_health') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ status: 'ok', tokens_active: tokenStore.size }));
    return true;
  }

  // Serve CA certificate (for agent container to trust)
  if (url === '/_ca') {
    res.writeHead(200, { 'Content-Type': 'application/x-pem-file' });
    res.end(ca.caCertPem);
    return true;
  }

  // List integrations/secrets
  if (url === '/_vault' && req.method === 'GET') {
    provider.secrets.list().then(names => {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ secrets: names }));
    }).catch(err => {
      console.error('Error listing secrets:', err);
      res.writeHead(500, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Failed to list secrets' }));
    });
    return true;
  }

  // Get/check a secret
  const vaultMatch = url.match(/^\/_vault\/([^/?]+)(\?.*)?$/);
  if (vaultMatch && req.method === 'GET') {
    const secretName = decodeSecretName(vaultMatch[1], res);
    if (secretName === null) return true;
    const params = new URLSearchParams(vaultMatch[2] ?? '');

    if (params.get('check') === '1') {
      provider.secrets.exists(secretName).then(exists => {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ exists }));
      }).catch(err => {
        console.error('Error checking secret:', err);
        res.writeHead(500, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Failed to check secret' }));
      });
      return true;
    }

    // Issue a proxy token
    const field = params.get('field');

    provider.secrets.get(secretName).then(secret => {
      if (secret === null) {
        res.writeHead(404, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: `Secret '${secretName}' not found`, ...vaultUrlHint(deps) }));
        return;
      }
      const parsed = parseSecretValue(secret.value);

      if (parsed.kind === 'multi') {
        // Multi-value secret
        // _cleartext lists fields that are safe to return as raw values (URLs, domains, IDs)
        const cleartextFields: unknown[] = Array.isArray(parsed.fields._cleartext) ? parsed.fields._cleartext : [];
        // User-visible fields exclude `_`-prefixed metadata (_cleartext, _allowed_hosts)
        const fields = userFields(parsed.fields);

        if (!field) {
          // No field requested — return available fields so the agent knows what to ask for
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ type: 'multi', fields }));
          return;
        }
        if (!fields.includes(field)) {
          res.writeHead(400, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: `Field '${field}' not found. Available: ${fields.join(', ')}` }));
          return;
        }
        const fieldValue = parsed.fields[field];
        if (cleartextFields.includes(field)) {
          // Non-sensitive field — return raw value (no token) so it can be used directly in URLs
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ value: fieldValue, cleartext: true }));
          return;
        }
        // Every field shares the secret's binding.
        const binding = resolveBinding(secretName, policyHostsFor(deps.policy, secretName), parsed.inBand, !!deps.allowUnboundSecrets);
        if (!sendBindingError(res, binding)) return;
        issueTicket(res, deps, `${secretName}:${field}`, String(fieldValue), binding.allowedHosts);
      } else {
        // Simple secret — field param is ignored
        const binding = resolveBinding(secretName, policyHostsFor(deps.policy, secretName), parsed.inBand, !!deps.allowUnboundSecrets);
        if (!sendBindingError(res, binding)) return;
        issueTicket(res, deps, secretName, parsed.value, binding.allowedHosts);
      }
    }).catch(err => {
      console.error('Error fetching secret:', err);
      res.writeHead(500, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Failed to fetch secret' }));
    });
    return true;
  }

  // Shared secret issuance (e.g. a browser-service API key).
  // Per-agent secrets use /_vault/{name}; this is the parallel surface for
  // shared API keys in the provider's shared store.
  const sharedMatch = url.match(/^\/_secret\/([^/?]+)$/);
  if (sharedMatch && req.method === 'GET') {
    const secretName = decodeSecretName(sharedMatch[1], res);
    if (secretName === null) return true;
    // The policy file's `shared` section is the allowlist: listing a name there
    // grants every agent the ability to mint short-lived tickets for it.
    if (!deps.policy.shared.has(secretName)) {
      res.writeHead(403, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: `Secret '${secretName}' is not in the shared-secret allowlist` }));
      return true;
    }
    const shared = provider.shared;
    if (!shared) {
      res.writeHead(404, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: `Provider '${provider.name}' has no shared secrets` }));
      return true;
    }
    shared.get(secretName).then(secret => {
      if (secret === null) {
        res.writeHead(404, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: `Shared secret '${secretName}' not found` }));
        return;
      }
      // The allowlist entry always carries hosts, so a shared secret is never unbound.
      const parsed = parseSecretValue(secret.value);
      const binding = resolveBinding(secretName, deps.policy.shared.get(secretName), parsed.inBand, false);
      if (!sendBindingError(res, binding)) return;
      issueTicket(res, deps, `shared:${secretName}`, parsed.kind === 'simple' ? parsed.value : secret.value, binding.allowedHosts);
    }).catch(err => {
      console.error(`Error fetching shared secret '${secretName}':`, err);
      res.writeHead(500, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Failed to fetch shared secret' }));
    });
    return true;
  }

  // Mint session-scoped credential tokens for a web login (CDP injection).
  // The credential is an ordinary multi-value secret (short handle like `example-login`,
  // since vault names can't be FQDNs) with `username` and `password` fields.
  // Tokens are bound to the agent's CDP session so they only resolve on that
  // session's WebSocket frames.
  if (url === '/_vault/mint-tokens' && req.method === 'POST') {
    readJsonBody(req).then(body => {
      handleMintTokens(body, res, deps);
    }).catch(() => {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Invalid JSON body' }));
    });
    return true;
  }

  // Refresh an OAuth token
  const refreshMatch = url.match(/^\/_vault\/([^/?]+)\/refresh$/);
  if (refreshMatch && req.method === 'POST') {
    const secretName = decodeSecretName(refreshMatch[1], res);
    if (secretName === null) return true;
    handleOAuthRefresh(secretName, res, deps).catch(err => {
      console.error('Error refreshing token:', err);
      if (!res.writableEnded) {
        res.writeHead(500, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Failed to refresh token' }));
      }
    });
    return true;
  }

  return false;
}

/** Issue an HTTP(S) ticket and answer with it and its allowed hosts. */
function issueTicket(
  res: http.ServerResponse,
  deps: VaultDeps,
  label: string,
  value: string,
  allowedHosts: Parameters<typeof allowedHostsJson>[0],
  via?: string,
): void {
  const token = deps.tokenStore.issue(label, value, { allowedHosts });
  console.log(`[issue] secret=${label} ttl_s=${token.ttlSeconds}${allowedHosts ? '' : ' unbound=1'}${via ? ` via=${via}` : ''}`);
  res.writeHead(200, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify({ token: token.id, expires_in: token.ttlSeconds, allowed_hosts: allowedHostsJson(allowedHosts) }));
}

/** Answer a refused binding. Returns true (and sends nothing) when the binding is ok. */
function sendBindingError(res: http.ServerResponse, binding: Binding): binding is Extract<Binding, { ok: true }> {
  if (binding.ok) return true;
  res.writeHead(binding.status, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify({ error: binding.error }));
  return false;
}

function vaultUrlHint(deps: VaultDeps): { vault_url?: string } {
  return deps.missingSecretUrl ? { vault_url: deps.missingSecretUrl } : {};
}

/**
 * Decode a secret name from a URL path segment and validate it. On failure,
 * answers 400 and returns null. Names never reach a provider unvalidated.
 */
function decodeSecretName(segment: string, res: http.ServerResponse): string | null {
  let name: string;
  try {
    name = decodeURIComponent(segment);
  } catch {
    name = '';
  }
  if (!isValidSecretName(name)) {
    res.writeHead(400, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: 'Invalid secret name: use letters, digits, ".", "_" and "-" (max 128, starting with a letter or digit)' }));
    return null;
  }
  return name;
}

/** Collect and JSON-parse a request body (rejects on malformed JSON). */
function readJsonBody(req: http.IncomingMessage): Promise<Record<string, unknown>> {
  return new Promise((resolve, reject) => {
    let raw = '';
    req.on('data', chunk => { raw += chunk; });
    req.on('end', () => {
      if (raw.trim() === '') return resolve({});
      try {
        resolve(JSON.parse(raw));
      } catch {
        reject(new Error('invalid json'));
      }
    });
    req.on('error', reject);
  });
}

const MINT_DEFAULT_TTL_SECONDS = 600; // 10 minutes
const MINT_MAX_TTL_SECONDS = 1800; // 30 minutes — cap to bound credential exposure

/**
 * Mint session-scoped username/password tokens for a stored web login.
 *
 * The credential is a normal multi-value secret (vault names are alphanumeric +
 * dashes, so it's a short handle like `example-login`, NOT a domain) with `username` +
 * `password` fields. The user tells the agent which secret to use. Tokens are
 * bound to the caller's CDP session id so they only substitute on that session's
 * frames and are revoked when the session closes.
 */
function handleMintTokens(
  body: Record<string, unknown>,
  res: http.ServerResponse,
  deps: VaultDeps,
): void {
  const { tokenStore, provider } = deps;
  const secretName = typeof body.secretName === 'string' ? body.secretName : '';
  const sessionId = typeof body.sessionId === 'string' ? body.sessionId : '';

  if (!secretName || !sessionId) {
    res.writeHead(400, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: 'Both `secretName` and `sessionId` are required' }));
    return;
  }
  if (!isValidSecretName(secretName)) {
    res.writeHead(400, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: 'Invalid secret name' }));
    return;
  }

  let ttl = MINT_DEFAULT_TTL_SECONDS;
  if (typeof body.expires_in === 'number' && body.expires_in > 0) {
    ttl = Math.min(body.expires_in, MINT_MAX_TTL_SECONDS);
  }

  provider.secrets.get(secretName).then(secret => {
    if (secret === null) {
      res.writeHead(404, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({
        error: `No credential stored under '${secretName}'`,
        ...vaultUrlHint(deps),
      }));
      return;
    }

    const secretValue = parseSecretValue(secret.value);
    const parsed = secretValue.kind === 'multi' ? secretValue.fields : null;
    const username = parsed?.username;
    const password = parsed?.password;
    if (!parsed || typeof username !== 'string' || typeof password !== 'string' || !username || !password) {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({
        error: `Secret '${secretName}' is not a web login — it must be a multi-value secret with 'username' and 'password' fields`,
      }));
      return;
    }

    // Snapshot the login's hosts now; the CDP path enforces them from roadmap item 15.
    const binding = resolveBinding(secretName, policyHostsFor(deps.policy, secretName), secretValue.inBand, !!deps.allowUnboundSecrets);
    if (!sendBindingError(res, binding)) return;
    const opts = { sessionId, ttlSeconds: ttl, allowedHosts: binding.allowedHosts };
    const usernameToken = tokenStore.issue(`${secretName}:username`, username, opts);
    const passwordToken = tokenStore.issue(`${secretName}:password`, password, opts);
    console.log(`[mint] secret=${secretName} session=${sessionId} ttl_s=${ttl}${binding.allowedHosts ? '' : ' unbound=1'}`);
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({
      username_token: usernameToken.id,
      password_token: passwordToken.id,
      expires_in: ttl,
      allowed_hosts: allowedHostsJson(binding.allowedHosts),
    }));
  }).catch(err => {
    console.error(`Error minting tokens for '${secretName}':`, err);
    res.writeHead(500, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: 'Failed to mint tokens' }));
  });
}

/**
 * Handle OAuth token refresh server-side.
 * Reads refresh_token + credentials from vault, exchanges with provider,
 * stores new tokens back in vault, returns a cct_* to the agent.
 */
async function handleOAuthRefresh(
  secretName: string,
  res: http.ServerResponse,
  deps: VaultDeps,
): Promise<void> {
  const { provider } = deps;
  const store = provider.secrets;

  // Check before the token exchange: a rotated refresh token we cannot store
  // would be lost.
  if (!store.put) {
    res.writeHead(501, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: `Provider '${provider.name}' is read-only; OAuth refresh needs a writable store` }));
    return;
  }

  const secret = await store.get(secretName);
  if (secret === null) {
    res.writeHead(404, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: `Secret '${secretName}' not found` }));
    return;
  }
  const raw = secret.value;

  let parsed: Record<string, unknown>;
  try {
    parsed = JSON.parse(raw);
  } catch {
    res.writeHead(400, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: 'Secret is not a multi-value JSON secret' }));
    return;
  }

  const refreshToken = parsed.refresh_token as string | undefined;
  const tokenUrl = parsed.token_url as string | undefined;
  const clientId = parsed.client_id as string | undefined;
  const clientSecret = parsed.client_secret as string | undefined;

  if (!refreshToken || !tokenUrl || !clientId || !clientSecret) {
    res.writeHead(400, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({
      error: 'Secret missing required fields for refresh (refresh_token, token_url, client_id, client_secret)',
    }));
    return;
  }

  // client_secret is sent to token_url, so its host must be one the secret is
  // bound to; the refreshed access-token ticket inherits the same binding.
  const binding = resolveBinding(secretName, policyHostsFor(deps.policy, secretName), parseSecretValue(raw).inBand, !!deps.allowUnboundSecrets);
  if (!sendBindingError(res, binding)) return;
  let tokenHost: URL | null = null;
  try {
    tokenHost = new URL(tokenUrl);
  } catch {
    // handled below
  }
  if (!tokenHost || (tokenHost.protocol !== 'https:' && tokenHost.protocol !== 'http:')) {
    res.writeHead(400, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: 'token_url must be an http(s) URL' }));
    return;
  }
  const scheme = tokenHost.protocol === 'https:' ? 'https' : 'http';
  if (binding.allowedHosts && !matchesHost(binding.allowedHosts, { host: tokenHost.hostname, scheme })) {
    console.warn(`[refresh] secret=${secretName} result=denied token_url_host=${tokenHost.hostname}`);
    res.writeHead(403, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: `token_url host '${tokenHost.hostname}' is not an allowed host of secret '${secretName}'` }));
    return;
  }

  // Exchange refresh token for new access token
  const body = new URLSearchParams({
    refresh_token: refreshToken,
    client_id: clientId,
    client_secret: clientSecret,
    grant_type: 'refresh_token',
  });

  const tokenRes = await fetch(tokenUrl, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: body.toString(),
  });

  if (!tokenRes.ok) {
    // Never log the body: providers can echo client ids or fragments of the grant.
    const errorCode = oauthErrorCode(await tokenRes.text().catch(() => ''));
    console.error(`OAuth refresh failed for ${secretName}: status=${tokenRes.status} error=${errorCode}`);
    res.writeHead(502, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: 'Token refresh failed', status: tokenRes.status }));
    return;
  }

  const tokens = await tokenRes.json() as {
    access_token: string;
    refresh_token?: string;
    expires_in: number;
  };

  // Update vault secret with new tokens
  const updated = { ...parsed };
  updated.access_token = tokens.access_token;
  updated.expires_at = Math.floor(Date.now() / 1000) + tokens.expires_in;
  if (tokens.refresh_token) {
    updated.refresh_token = tokens.refresh_token;
  }

  await store.put(secretName, JSON.stringify(updated));

  // Issue a cct_* for the new access token
  issueTicket(res, deps, `${secretName}:access_token`, tokens.access_token, binding.allowedHosts, 'oauth_refresh');
}

const OAUTH_ERROR_CODE_MAX = 64;

/**
 * Extract the RFC 6749 `error` code from a token-endpoint error body, safe to
 * log: only `[A-Za-z0-9_.-]`, at most 64 chars. Anything else becomes `unknown`.
 */
export function oauthErrorCode(body: string): string {
  let code: unknown;
  try {
    code = (JSON.parse(body) as { error?: unknown })?.error;
  } catch {
    return 'unparseable';
  }
  if (typeof code !== 'string' || code.length === 0) return 'unknown';
  const safe = code.slice(0, OAUTH_ERROR_CODE_MAX);
  return /^[A-Za-z0-9_.-]+$/.test(safe) ? safe : 'unknown';
}
