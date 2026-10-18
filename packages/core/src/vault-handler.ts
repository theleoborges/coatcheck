import http from 'node:http';
import { TokenStore } from './token-store.js';
import type { CertAuthority } from './ca.js';
import type { CdpSessionStore, LoginRequest, LoginResult } from './cdp-session-store.js';
import { InvalidSecretNameError, isValidSecretName, type SecretProvider } from './secret-provider.js';
import { policyRuleFor, type Policy } from './policy.js';
import { matchesHost, type HostPattern } from './host-matcher.js';
import { allowedHostsJson, parseSecretValue, resolveBinding, userFields, type Binding, type InBandMetadata, type Placement, type SecretValue } from './secret-binding.js';
import { keyFields, signingCredentialFrom, signingSpecJson } from './signing/spec.js';

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
  /** Live CDP sessions: `login` refuses a session with no attached controller with 404. */
  cdpSessionStore: Pick<CdpSessionStore, 'controller'>;
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
      sendProviderError(res, err, 'Error listing secrets:', 'Failed to list secrets');
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
        sendProviderError(res, err, 'Error checking secret:', 'Failed to check secret');
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

      // A signing secret mints one credential ticket (docs/design/signing-processors.md §3).
      const rule = policyRuleFor(deps.policy, secretName);
      if (rule?.signing || ('signing' in parsed.inBand && parsed.inBand.signing)) {
        mintSigning(res, deps, secretName, parsed, bindingFor(deps, secretName, parsed.inBand), field);
        return;
      }

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
        const binding = bindingFor(deps, secretName, parsed.inBand);
        if (!sendBindingError(res, binding)) return;
        issueTicket(res, deps, `${secretName}:${field}`, String(fieldValue), binding);
      } else {
        // Simple secret — field param is ignored
        const binding = bindingFor(deps, secretName, parsed.inBand);
        if (!sendBindingError(res, binding)) return;
        issueTicket(res, deps, secretName, parsed.value, binding);
      }
    }).catch(err => {
      sendProviderError(res, err, 'Error fetching secret:', 'Failed to fetch secret');
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
      const rule = deps.policy.shared.get(secretName);
      const binding = resolveBinding(secretName, rule?.allowedHosts, parsed.inBand, false, rule);
      if (binding.ok && binding.signing) {
        mintSigning(res, deps, `shared:${secretName}`, parsed, binding, null);
        return;
      }
      if (!sendBindingError(res, binding)) return;
      issueTicket(res, deps, `shared:${secretName}`, parsed.kind === 'simple' ? parsed.value : secret.value, binding);
    }).catch(err => {
      sendProviderError(res, err, `Error fetching shared secret '${secretName}':`, 'Failed to fetch shared secret');
    });
    return true;
  }

  // Broker-performed browser login (CDP injection). coatcheck fills and submits
  // the login form itself over the agent's CDP connection; no credential ticket
  // ever enters the browser. Replaces mint-tokens.
  const loginMatch = url.match(/^\/_vault\/([^/?]+)\/login$/);
  if (loginMatch && req.method === 'POST') {
    const secretName = decodeSecretName(loginMatch[1], res);
    if (secretName === null) return true;
    readJsonBody(req).then(body => {
      handleLogin(secretName, body, res, deps);
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
      if (!res.writableEnded) sendProviderError(res, err, 'Error refreshing token:', 'Failed to refresh token');
      else console.error('Error refreshing token:', err);
    });
    return true;
  }

  return false;
}

/** Issue an HTTP(S) ticket and answer with it, its allowed hosts and any opt-in swap placements. */
function issueTicket(
  res: http.ServerResponse,
  deps: VaultDeps,
  label: string,
  value: string,
  binding: { allowedHosts: readonly HostPattern[] | undefined } & Placement,
  via?: string,
): void {
  const { allowedHosts, swapBody, swapUrl, swapHeaders } = binding;
  const token = deps.tokenStore.issue(label, value, { allowedHosts, swapBody, swapUrl, swapHeaders });
  const flags = `${allowedHosts ? '' : ' unbound=1'}${swapBody ? ' swap_body=1' : ''}${swapUrl ? ' swap_url=1' : ''}` +
    (swapHeaders.length > 0 ? ` swap_headers=${swapHeaders.join(',')}` : '');
  console.log(`[issue] secret=${label} ttl_s=${token.ttlSeconds}${flags}${via ? ` via=${via}` : ''}`);
  res.writeHead(200, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify({
    token: token.id,
    expires_in: token.ttlSeconds,
    allowed_hosts: allowedHostsJson(allowedHosts),
    ...(swapBody ? { swap_body: true } : {}),
    ...(swapUrl ? { swap_url: true } : {}),
    ...(swapHeaders.length > 0 ? { swap_headers: swapHeaders } : {}),
  }));
}

/**
 * Mint for a signing secret: without `?field=`, one credential ticket (used
 * as a key, re-signed on the wire, never swapped) and the public recipe.
 * `?field=` on the key field is refused (a literal ticket would be a copy of
 * the key); `_cleartext` fields return values, other fields get ordinary
 * literal tickets with the secret's binding and placement. A secret missing
 * its key fails with 500 whatever is asked, so no partial ticket is issued.
 */
function mintSigning(res: http.ServerResponse, deps: VaultDeps, label: string, parsed: SecretValue, binding: Binding, field: string | null): void {
  if (!sendBindingError(res, binding)) return;
  const spec = binding.signing!;
  const fields = parsed.kind === 'multi' ? parsed.fields : null;
  const credential = signingCredentialFrom(spec, fields);
  if (typeof credential === 'string') {
    console.warn(`[issue] secret=${label} result=refused (invalid ${spec.type} secret)`);
    return send(res, 500, { error: `Secret '${label}' is not a valid ${spec.type} signing secret: ${credential}` });
  }

  if (field) {
    if (keyFields(spec).includes(field)) {
      return send(res, 400, { error: `Field '${field}' is the signing key: use the credential ticket (GET without ?field=)` });
    }
    const names = fields ? userFields(fields) : [];
    if (!fields || !names.includes(field)) {
      return send(res, 400, { error: `Field '${field}' not found. Available: ${names.join(', ')}` });
    }
    const cleartext: unknown[] = Array.isArray(fields._cleartext) ? fields._cleartext : [];
    if (cleartext.includes(field)) return send(res, 200, { value: fields[field], cleartext: true });
    issueTicket(res, deps, `${label}:${field}`, String(fields[field]), binding);
    return;
  }

  const { allowedHosts } = binding;
  const token = deps.tokenStore.issue(label, '', { allowedHosts, signing: credential });
  console.log(`[issue] secret=${label} ttl_s=${token.ttlSeconds}${allowedHosts ? '' : ' unbound=1'} signing=${spec.type}`);
  send(res, 200, {
    token: token.id,
    expires_in: token.ttlSeconds,
    allowed_hosts: allowedHostsJson(allowedHosts),
    signing: signingSpecJson(spec),
  });
}

/** A per-agent secret's binding: its policy rule intersected with its in-band hosts. */
function bindingFor(deps: VaultDeps, secretName: string, inBand: InBandMetadata): Binding {
  const rule = policyRuleFor(deps.policy, secretName);
  return resolveBinding(secretName, rule?.allowedHosts, inBand, !!deps.allowUnboundSecrets, rule);
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
 * Answer a failed provider call: 400 for a name the provider can't map, else
 * log and 500. Never echoes provider error details to the client.
 */
function sendProviderError(res: http.ServerResponse, err: unknown, logMessage: string, publicMessage: string): void {
  if (err instanceof InvalidSecretNameError) {
    res.writeHead(400, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: err.message }));
    return;
  }
  console.error(logMessage, err);
  res.writeHead(500, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify({ error: publicMessage }));
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

const LOGIN_DEFAULT_TIMEOUT_MS = 15_000;
const LOGIN_MAX_TIMEOUT_MS = 60_000;

/**
 * Drive a broker-performed browser login (design: docs/design/cdp-broker-login.md).
 * coatcheck fills the stored credential and submits the form itself over the
 * agent's CDP connection, on a freshly reloaded document, while the agent's
 * frames are held. No ticket for the credential ever reaches the browser.
 */
function handleLogin(
  secretName: string,
  body: Record<string, unknown>,
  res: http.ServerResponse,
  deps: VaultDeps,
): void {
  const sessionId = typeof body.sessionId === 'string' ? body.sessionId : '';
  const fields = isRecord(body.fields) ? body.fields : null;
  if (!sessionId || !fields || Object.keys(fields).length === 0) {
    return send(res, 400, { error: '`sessionId` and a non-empty `fields` object are required' });
  }
  // Every field selector must be a string.
  const selectors: Record<string, string> = {};
  for (const [field, sel] of Object.entries(fields)) {
    if (typeof sel !== 'string' || sel === '') return send(res, 400, { error: `field '${field}' must map to a non-empty CSS selector` });
    selectors[field] = sel;
  }

  const submit = parseSubmit(body.submit);
  if (!submit) return send(res, 400, { error: '`submit` must be a selector string or {"press":"Enter"}' });
  const until = parseUntil(body.until);
  if (!until) return send(res, 400, { error: '`until` must be "navigation", {"selector":"…"} or {"urlPrefix":"…"}' });

  let timeoutMs = LOGIN_DEFAULT_TIMEOUT_MS;
  if (typeof body.timeoutMs === 'number' && body.timeoutMs > 0) timeoutMs = Math.min(body.timeoutMs, LOGIN_MAX_TIMEOUT_MS);

  const pageUrlPrefix = isRecord(body.page) && typeof body.page.url === 'string' ? body.page.url : undefined;

  // "Connected" means a controller is attached for the sid (design decision 1).
  const controller = deps.cdpSessionStore.controller(sessionId);
  if (!controller) {
    console.warn(`[login] secret=${secretName} rejected: no live CDP connection for session`);
    return send(res, 404, { status: 'unknown-sid-or-secret', error: 'Unknown or not-connected CDP session' });
  }

  deps.provider.secrets.get(secretName).then(secret => {
    if (secret === null) return send(res, 404, { status: 'unknown-sid-or-secret', error: `No credential stored under '${secretName}'`, ...vaultUrlHint(deps) });

    const parsedSecret = parseSecretValue(secret.value);
    if (parsedSecret.kind !== 'multi') return send(res, 501, { error: `Secret '${secretName}' is not a multi-value web login` });
    const cleartextFields: string[] = (Array.isArray(parsedSecret.fields._cleartext) ? parsedSecret.fields._cleartext : []).filter((f): f is string => typeof f === 'string');
    const userFieldNames = userFields(parsedSecret.fields);
    const fillable = new Set([...userFieldNames, ...cleartextFields]);

    // Every requested field must exist on the secret.
    const values: Record<string, string> = {};
    for (const field of Object.keys(selectors)) {
      const fieldValue = parsedSecret.fields[field];
      // A `_cleartext` entry can name a field that isn't actually present; don't
      // fill the literal string "undefined".
      if (!fillable.has(field) || fieldValue === undefined) return send(res, 501, { error: `Secret '${secretName}' has no field '${field}'` });
      values[field] = String(fieldValue);
    }

    const binding = bindingFor(deps, secretName, parsedSecret.inBand);
    if (!sendBindingError(res, binding)) return;

    // Register the sensitive field values (not `_cleartext`) for inbound
    // redaction for the life of the window; dropped at session teardown.
    const redactValues = Object.keys(selectors)
      .filter(f => !cleartextFields.includes(f))
      .map(f => ({ value: values[f], secretName: `${secretName}:${f}` }));
    deps.tokenStore.registerSessionValues(sessionId, redactValues);

    controller.login({
      fields: selectors,
      values,
      cleartextFields,
      secretName,
      allowedHosts: binding.allowedHosts,
      pageUrlPrefix,
      submit,
      until,
      timeoutMs,
    }).then(result => sendLoginResult(res, result))
      .catch(err => sendProviderError(res, err, `Error during login for '${secretName}':`, 'Login failed'));
  }).catch(err => sendProviderError(res, err, `Error fetching credential '${secretName}':`, 'Failed to fetch credential'));
}

function parseSubmit(raw: unknown): LoginRequest['submit'] | null {
  if (typeof raw === 'string' && raw !== '') return { selector: raw };
  if (isRecord(raw) && raw.press === 'Enter') return { press: 'Enter' };
  return null;
}

function parseUntil(raw: unknown): LoginRequest['until'] | null {
  if (raw === undefined || raw === 'navigation') return { kind: 'navigation' };
  if (isRecord(raw)) {
    if (typeof raw.selector === 'string' && raw.selector !== '') return { kind: 'selector', selector: raw.selector };
    if (typeof raw.urlPrefix === 'string' && raw.urlPrefix !== '') return { kind: 'urlPrefix', urlPrefix: raw.urlPrefix };
  }
  return null;
}

/** Map a driver `LoginResult` to its HTTP response (design status table). */
function sendLoginResult(res: http.ServerResponse, result: LoginResult): void {
  switch (result.status) {
    case 200: return send(res, 200, { status: 'ok', url: result.url });
    case 403: return send(res, 403, { error: result.error });
    case 404: return send(res, 404, { status: 'selector-not-found', ...(result.field ? { field: result.field } : {}) });
    case 409: return send(res, 409, { status: result.reason, ...(result.cleared ? { cleared: true } : {}) });
    case 501: return send(res, 501, { error: 'Secret is not a multi-value login with the requested fields' });
    case 502: return send(res, 502, { status: result.reason, ...(result.cleared ? { cleared: true } : {}) });
  }
}

function isRecord(v: unknown): v is Record<string, unknown> {
  return v !== null && typeof v === 'object' && !Array.isArray(v);
}

function send(res: http.ServerResponse, status: number, body: unknown): void {
  res.writeHead(status, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify(body));
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

  const secretValue = parseSecretValue(raw);
  if (secretValue.kind !== 'multi') {
    res.writeHead(400, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: 'Secret is not a multi-value JSON secret' }));
    return;
  }
  const parsed = secretValue.fields;

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
  const binding = bindingFor(deps, secretName, secretValue.inBand);
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
    // A 307/308 would re-POST client_secret to a host the check above never saw.
    redirect: 'error',
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
  issueTicket(res, deps, `${secretName}:access_token`, tokens.access_token, binding, 'oauth_refresh');
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
