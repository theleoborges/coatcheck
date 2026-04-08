import http from 'node:http';
import { describe, it, expect, afterEach, vi } from 'vitest';
import { handleVaultRequest, VaultDeps } from './vault-handler.js';
import { TokenStore } from './token-store.js';

// --- Helpers ---

function mockSecretFetcher(secrets: Record<string, string>) {
  return {
    get: vi.fn(async (name: string) => secrets[name] ?? null),
    exists: vi.fn(async (name: string) => name in secrets),
    listSecrets: vi.fn(async () => Object.keys(secrets)),
  };
}

function mockCa() {
  return { caCertPem: '-----BEGIN CERTIFICATE-----\nFAKE\n-----END CERTIFICATE-----\n', getCertForHost: vi.fn() };
}

/** Spin up a tiny HTTP server that delegates to handleVaultRequest */
function createTestServer(deps: VaultDeps): http.Server {
  return http.createServer((req, res) => {
    if (!handleVaultRequest(req, res, deps)) {
      res.writeHead(404);
      res.end('Not a vault request');
    }
  });
}

async function listen(server: http.Server): Promise<number> {
  return new Promise((resolve) => {
    server.listen(0, '127.0.0.1', () => {
      const addr = server.address() as { port: number };
      resolve(addr.port);
    });
  });
}

async function fetchJSON(port: number, path: string): Promise<{ status: number; body: Record<string, unknown> }> {
  const res = await fetch(`http://127.0.0.1:${port}${path}`);
  const body = await res.json();
  return { status: res.status, body: body as Record<string, unknown> };
}

async function fetchText(port: number, path: string): Promise<{ status: number; body: string; contentType: string }> {
  const res = await fetch(`http://127.0.0.1:${port}${path}`);
  const body = await res.text();
  return { status: res.status, body, contentType: res.headers.get('content-type') ?? '' };
}

// --- Tests ---

describe('Vault Handler', () => {
  let tokenStore: TokenStore;
  let server: http.Server;
  let port: number;

  afterEach(() => {
    tokenStore?.destroy();
    server?.close();
  });

  async function setup(secrets: Record<string, string>) {
    tokenStore = new TokenStore();
    const deps: VaultDeps = {
      tokenStore,
      secretFetcher: mockSecretFetcher(secrets) as unknown as VaultDeps['secretFetcher'],
      ca: mockCa() as unknown as VaultDeps['ca'],
    };
    server = createTestServer(deps);
    port = await listen(server);
    return deps;
  }

  // --- Health & CA ---

  it('returns health check', async () => {
    await setup({});
    const { status, body } = await fetchJSON(port, '/_health');
    expect(status).toBe(200);
    expect(body).toEqual({ status: 'ok', tokens_active: 0 });
  });

  it('serves CA certificate', async () => {
    await setup({});
    const { status, body, contentType } = await fetchText(port, '/_ca');
    expect(status).toBe(200);
    expect(contentType).toBe('application/x-pem-file');
    expect(body).toContain('BEGIN CERTIFICATE');
  });

  // --- List ---

  it('lists secret names', async () => {
    await setup({ github: 'ghp_xxx', supabase: '{"url":"x","key":"y"}' });
    const { status, body } = await fetchJSON(port, '/_vault');
    expect(status).toBe(200);
    expect(body.secrets).toEqual(['github', 'supabase']);
  });

  // --- Check ---

  it('checks existing secret', async () => {
    await setup({ github: 'ghp_xxx' });
    const { status, body } = await fetchJSON(port, '/_vault/github?check=1');
    expect(status).toBe(200);
    expect(body.exists).toBe(true);
  });

  it('checks missing secret', async () => {
    await setup({});
    const { status, body } = await fetchJSON(port, '/_vault/nope?check=1');
    expect(status).toBe(200);
    expect(body.exists).toBe(false);
  });

  // --- Simple secret ---

  it('issues token for simple secret', async () => {
    await setup({ github: 'ghp_real_token_123' });
    const { status, body } = await fetchJSON(port, '/_vault/github');
    expect(status).toBe(200);
    expect(body.token).toMatch(/^tok_/);
    expect(body.expires_in).toBe(300);

    // Token resolves to the real value
    const resolved = tokenStore.resolve(body.token as string);
    expect(resolved).toBe('ghp_real_token_123');
  });

  it('simple secret ignores field param', async () => {
    await setup({ github: 'ghp_real_token_123' });
    const { status, body } = await fetchJSON(port, '/_vault/github?field=whatever');
    expect(status).toBe(200);
    expect(body.token).toMatch(/^tok_/);

    const resolved = tokenStore.resolve(body.token as string);
    expect(resolved).toBe('ghp_real_token_123');
  });

  it('returns 404 for missing secret', async () => {
    await setup({});
    const { status, body } = await fetchJSON(port, '/_vault/nope');
    expect(status).toBe(404);
    expect(body.error).toContain('not found');
    expect(body.vault_url).toContain('integrations');
  });

  // --- Multi-value secret ---

  it('returns fields list for multi-value secret without field param', async () => {
    await setup({ supabase: JSON.stringify({ 'project-url': 'https://proj.supabase.co', 'service-role-key': 'sbp_secret', _cleartext: ['project-url'] }) });
    const { status, body } = await fetchJSON(port, '/_vault/supabase');
    expect(status).toBe(200);
    expect(body.type).toBe('multi');
    expect(body.fields).toEqual(['project-url', 'service-role-key']);
    // _cleartext should not appear in fields list
    expect(body.fields).not.toContain('_cleartext');
    // No token should be issued
    expect(body.token).toBeUndefined();
    expect(tokenStore.size).toBe(0);
  });

  it('returns raw value for cleartext field (no token)', async () => {
    await setup({ supabase: JSON.stringify({ 'project-url': 'https://proj.supabase.co', 'service-role-key': 'sbp_secret', _cleartext: ['project-url'] }) });

    const { status, body } = await fetchJSON(port, '/_vault/supabase?field=project-url');
    expect(status).toBe(200);
    expect(body.value).toBe('https://proj.supabase.co');
    expect(body.cleartext).toBe(true);
    // No token issued for cleartext fields
    expect(body.token).toBeUndefined();
    expect(tokenStore.size).toBe(0);
  });

  it('issues token for sensitive field even when _cleartext is present', async () => {
    await setup({ supabase: JSON.stringify({ 'project-url': 'https://proj.supabase.co', 'service-role-key': 'sbp_secret', _cleartext: ['project-url'] }) });

    const { status, body } = await fetchJSON(port, '/_vault/supabase?field=service-role-key');
    expect(status).toBe(200);
    expect(body.token).toMatch(/^tok_/);
    expect(tokenStore.resolve(body.token as string)).toBe('sbp_secret');
    expect(body.value).toBeUndefined();
    expect(tokenStore.size).toBe(1);
  });

  it('issues tokens for all fields when no _cleartext metadata', async () => {
    await setup({ supabase: JSON.stringify({ 'project-url': 'https://proj.supabase.co', 'service-role-key': 'sbp_secret' }) });

    const { status: s1, body: b1 } = await fetchJSON(port, '/_vault/supabase?field=project-url');
    expect(s1).toBe(200);
    expect(b1.token).toMatch(/^tok_/);
    expect(tokenStore.resolve(b1.token as string)).toBe('https://proj.supabase.co');

    const { status: s2, body: b2 } = await fetchJSON(port, '/_vault/supabase?field=service-role-key');
    expect(s2).toBe(200);
    expect(b2.token).toMatch(/^tok_/);
    expect(tokenStore.resolve(b2.token as string)).toBe('sbp_secret');

    expect(tokenStore.size).toBe(2);
  });

  it('returns 400 for invalid field on multi-value secret', async () => {
    await setup({ supabase: JSON.stringify({ 'project-url': 'x', 'service-role-key': 'y', _cleartext: ['project-url'] }) });
    const { status, body } = await fetchJSON(port, '/_vault/supabase?field=bogus');
    expect(status).toBe(400);
    expect(body.error).toContain("Field 'bogus' not found");
    expect(body.error).toContain('project-url');
    expect(body.error).toContain('service-role-key');
    // _cleartext should not appear in error message
    expect(body.error).not.toContain('_cleartext');
  });

  it('returns 400 when requesting _cleartext as a field', async () => {
    await setup({ supabase: JSON.stringify({ 'project-url': 'x', 'service-role-key': 'y', _cleartext: ['project-url'] }) });
    const { status, body } = await fetchJSON(port, '/_vault/supabase?field=_cleartext');
    expect(status).toBe(400);
    expect(body.error).toContain('not found');
  });

  // --- Edge cases ---

  it('treats JSON arrays as simple secrets (not multi-value)', async () => {
    await setup({ 'my-list': '["a","b","c"]' });
    const { status, body } = await fetchJSON(port, '/_vault/my-list');
    expect(status).toBe(200);
    expect(body.token).toMatch(/^tok_/);
    expect(tokenStore.resolve(body.token as string)).toBe('["a","b","c"]');
  });

  it('treats non-JSON strings as simple secrets', async () => {
    await setup({ 'api-key': 'not-json-at-all' });
    const { status, body } = await fetchJSON(port, '/_vault/api-key');
    expect(status).toBe(200);
    expect(body.token).toMatch(/^tok_/);
    expect(tokenStore.resolve(body.token as string)).toBe('not-json-at-all');
  });

  it('URL-decodes secret names', async () => {
    await setup({ 'my integration': 'secret-val' });
    const { status, body } = await fetchJSON(port, '/_vault/my%20integration');
    expect(status).toBe(200);
    expect(body.token).toMatch(/^tok_/);
  });

  it('returns false for non-vault paths', async () => {
    await setup({});
    const res = await fetch(`http://127.0.0.1:${port}/not-vault`);
    expect(res.status).toBe(404);
    const text = await res.text();
    expect(text).toBe('Not a vault request');
  });

  it('issued multi-field tokens are swappable in strings', async () => {
    await setup({ trello: JSON.stringify({ 'api-key': 'trello-key-123', 'token': 'trello-tok-456' }) });

    const { body: b1 } = await fetchJSON(port, '/_vault/trello?field=api-key');
    const { body: b2 } = await fetchJSON(port, '/_vault/trello?field=token');

    const url = `https://api.trello.com/1/boards?key=${b1.token}&token=${b2.token}`;
    const swapped = tokenStore.replaceAll(url);
    expect(swapped).toBe('https://api.trello.com/1/boards?key=trello-key-123&token=trello-tok-456');
  });
});
