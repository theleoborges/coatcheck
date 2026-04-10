import http from 'node:http';
import { TokenStore } from './token-store.js';
import { SecretFetcher } from './secret-fetcher.js';
import { CertAuthority } from './ca.js';

export interface VaultDeps {
  tokenStore: TokenStore;
  secretFetcher: SecretFetcher;
  ca: CertAuthority;
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
  const { tokenStore, secretFetcher, ca } = deps;
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
    secretFetcher.listSecrets().then(names => {
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
    const secretName = decodeURIComponent(vaultMatch[1]);
    const params = new URLSearchParams(vaultMatch[2] ?? '');

    if (params.get('check') === '1') {
      secretFetcher.exists(secretName).then(exists => {
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

    secretFetcher.get(secretName).then(value => {
      if (value === null) {
        res.writeHead(404, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: `Secret '${secretName}' not found`, vault_url: 'https://example.com/dashboard/integrations' }));
        return;
      }

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
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ token: token.id, expires_in: token.ttlSeconds }));
        }
      } else {
        // Simple secret — field param is ignored
        const token = tokenStore.issue(secretName, value);
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

  // Refresh an OAuth token
  const refreshMatch = url.match(/^\/_vault\/([^/?]+)\/refresh$/);
  if (refreshMatch && req.method === 'POST') {
    const secretName = decodeURIComponent(refreshMatch[1]);
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

/**
 * Handle OAuth token refresh server-side.
 * Reads refresh_token + credentials from vault, exchanges with provider,
 * stores new tokens back in vault, returns a tok_* to the agent.
 */
async function handleOAuthRefresh(
  secretName: string,
  res: http.ServerResponse,
  deps: VaultDeps,
): Promise<void> {
  const { tokenStore, secretFetcher } = deps;

  const raw = await secretFetcher.get(secretName);
  if (raw === null) {
    res.writeHead(404, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: `Secret '${secretName}' not found` }));
    return;
  }

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
    const errorText = await tokenRes.text();
    console.error(`OAuth refresh failed for ${secretName}:`, tokenRes.status, errorText);
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

  await secretFetcher.put(secretName, JSON.stringify(updated));

  // Issue a tok_* for the new access token
  const tok = tokenStore.issue(`${secretName}:access_token`, tokens.access_token);
  res.writeHead(200, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify({ token: tok.id, expires_in: tok.ttlSeconds }));
}
