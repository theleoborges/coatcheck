import http from 'node:http';
import { TokenStore } from './token-store.js';
import type { CertAuthority } from './ca.js';
import { isValidSecretName, type SecretProvider } from './secret-provider.js';

export interface VaultDeps {
  tokenStore: TokenStore;
  provider: SecretProvider;
  ca: Pick<CertAuthority, 'caCertPem'>;
  /** Where users manage secrets; returned as `vault_url` in 404s when set. */
  missingSecretUrl?: string;
}

/**
 * Shared secrets the agent is permitted to request via /_secret/{name}, read
 * from the provider's shared store. Adding a name here grants every agent the
 * ability to mint short-lived tokens for it — only add shared API keys consumed
 * by agent tooling.
 */
const SHARED_SECRET_ALLOWLIST = new Set<string>([
  'browserbase-api-key',
]);

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
      const value = secret.value;

      // Check if this is a multi-value (JSON) secret
      let parsed: Record<string, string> | null = null;
      try {
        const obj = JSON.parse(value);
        if (obj && typeof obj === 'object' && !Array.isArray(obj)) {
          parsed = obj;
        }
      } catch {
        // Not JSON — simple secret
      }

      if (parsed) {
        // Multi-value secret
        // _cleartext lists fields that are safe to return as raw values (URLs, domains, IDs)
        const cleartextFields: string[] = Array.isArray(parsed._cleartext) ? parsed._cleartext : [];
        // User-visible fields exclude the _cleartext metadata key
        const userFields = Object.keys(parsed).filter(k => k !== '_cleartext');

        if (!field) {
          // No field requested — return available fields so the agent knows what to ask for
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ type: 'multi', fields: userFields }));
          return;
        }
        if (field === '_cleartext' || parsed[field] === undefined) {
          res.writeHead(400, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: `Field '${field}' not found. Available: ${userFields.join(', ')}` }));
          return;
        }
        const fieldValue = parsed[field];
        if (cleartextFields.includes(field)) {
          // Non-sensitive field — return raw value (no token) so it can be used directly in URLs
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ value: fieldValue, cleartext: true }));
        } else {
          const token = tokenStore.issue(`${secretName}:${field}`, fieldValue);
          console.log(`[issue] secret=${secretName}:${field} ttl_s=${token.ttlSeconds}`);
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ token: token.id, expires_in: token.ttlSeconds }));
        }
      } else {
        // Simple secret — field param is ignored
        const token = tokenStore.issue(secretName, value);
        console.log(`[issue] secret=${secretName} ttl_s=${token.ttlSeconds}`);
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ token: token.id, expires_in: token.ttlSeconds }));
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
    if (!SHARED_SECRET_ALLOWLIST.has(secretName)) {
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
      const token = tokenStore.issue(`shared:${secretName}`, secret.value);
      console.log(`[issue] secret=shared:${secretName} ttl_s=${token.ttlSeconds}`);
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ token: token.id, expires_in: token.ttlSeconds }));
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

    let parsed: Record<string, unknown> | null = null;
    try {
      const obj = JSON.parse(secret.value);
      if (obj && typeof obj === 'object' && !Array.isArray(obj)) parsed = obj;
    } catch {
      // not JSON
    }

    const username = parsed?.username;
    const password = parsed?.password;
    if (!parsed || typeof username !== 'string' || typeof password !== 'string' || !username || !password) {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({
        error: `Secret '${secretName}' is not a web login — it must be a multi-value secret with 'username' and 'password' fields`,
      }));
      return;
    }

    const usernameToken = tokenStore.issueForSession(`${secretName}:username`, username, sessionId, ttl);
    const passwordToken = tokenStore.issueForSession(`${secretName}:password`, password, sessionId, ttl);
    console.log(`[mint] secret=${secretName} session=${sessionId} ttl_s=${ttl}`);
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({
      username_token: usernameToken.id,
      password_token: passwordToken.id,
      expires_in: ttl,
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
  const { tokenStore, provider } = deps;
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
  const tok = tokenStore.issue(`${secretName}:access_token`, tokens.access_token);
  console.log(`[issue] secret=${secretName}:access_token ttl_s=${tok.ttlSeconds} via=oauth_refresh`);
  res.writeHead(200, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify({ token: tok.id, expires_in: tok.ttlSeconds }));
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
