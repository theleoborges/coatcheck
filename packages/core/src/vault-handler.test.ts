import http from 'node:http';
import { describe, it, expect, afterEach, vi } from 'vitest';
import { oauthErrorCode, handleVaultRequest, VaultDeps } from './vault-handler.js';
import { TokenStore } from './token-store.js';

const AUTH = { kind: 'header', name: 'authorization' } as const;
import { CdpSessionStore, type LoginRequest, type LoginResult } from './cdp-session-store.js';
import { createMemoryProvider, type MemoryProviderInit } from './memory-provider.js';
import { EMPTY_POLICY, parsePolicy, type Policy } from './policy.js';

/** The policy these tests run under: the per-agent secrets they use are bound, plus one allowlisted shared secret. */
const TEST_POLICY: Policy = parsePolicy(JSON.stringify({
  secrets: {
    github: { allowed_hosts: ['api.github.com'] },
    supabase: { allowed_hosts: ['*.supabase.co'] },
    trello: { allowed_hosts: ['api.trello.com'] },
    google: { allowed_hosts: ['*.googleapis.com'] },
    'example-login': { allowed_hosts: ['login.example.com'] },
    'my-*': { allowed_hosts: ['api.example.com'] },
    'api-key': { allowed_hosts: ['api.example.com'] },
  },
  shared: { 'browserbase-api-key': { allowed_hosts: ['api.browserbase.com'] } },
}), []);

const https = (host: string) => ({ host, scheme: 'https' as const });

// Save real fetch before any tests can mock it
const realFetch = globalThis.fetch;

// --- Helpers ---

function mockCa() {
  return { caCertPem: '-----BEGIN CERTIFICATE-----\nFAKE\n-----END CERTIFICATE-----\n' };
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

async function fetchJSON(port: number, path: string, method = 'GET'): Promise<{ status: number; body: Record<string, unknown> }> {
  // Always use the real fetch (not a mock) for test server requests
  const res = await realFetch(`http://127.0.0.1:${port}${path}`, { method });
  const body = await res.json();
  return { status: res.status, body: body as Record<string, unknown> };
}

/** GET with the path sent verbatim (fetch would normalise `%2E%2E` segments away). */
function rawGetJSON(port: number, path: string): Promise<{ status: number; body: Record<string, unknown> }> {
  return new Promise((resolve, reject) => {
    http.get({ host: '127.0.0.1', port, path }, res => {
      let raw = '';
      res.on('data', d => { raw += d; });
      res.on('end', () => resolve({ status: res.statusCode ?? 0, body: JSON.parse(raw) as Record<string, unknown> }));
    }).on('error', reject);
  });
}

async function postJSON(port: number, path: string, body: unknown): Promise<{ status: number; body: Record<string, unknown> }> {
  const res = await realFetch(`http://127.0.0.1:${port}${path}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  const json = await res.json();
  return { status: res.status, body: json as Record<string, unknown> };
}

async function fetchText(port: number, path: string): Promise<{ status: number; body: string; contentType: string }> {
  const res = await realFetch(`http://127.0.0.1:${port}${path}`);
  const body = await res.text();
  return { status: res.status, body, contentType: res.headers.get('content-type') ?? '' };
}

// --- Tests ---

describe('Vault Handler', () => {
  let tokenStore: TokenStore;
  let cdpSessionStore: CdpSessionStore;
  /** A live CDP session, as an adapter rewrite would register it. */
  let sid: string;
  let server: http.Server;
  let port: number;

  afterEach(() => {
    tokenStore?.destroy();
    cdpSessionStore?.destroy();
    server?.close();
  });

  async function setup(
    secrets: Record<string, string>,
    sharedSecrets: Record<string, string> = {},
    opts: Pick<MemoryProviderInit, 'writable'> & { noShared?: boolean; missingSecretUrl?: string; policy?: Policy; allowUnbound?: boolean } = {},
  ) {
    tokenStore = new TokenStore();
    cdpSessionStore = new CdpSessionStore();
    sid = cdpSessionStore.register('wss://browser.test/session', 'test');
    const provider = createMemoryProvider({
      secrets,
      shared: opts.noShared ? undefined : sharedSecrets,
      writable: opts.writable,
    });
    if (provider.secrets.put) vi.spyOn(provider.secrets, 'put');
    const deps: VaultDeps = {
      tokenStore,
      provider,
      ca: mockCa(),
      missingSecretUrl: opts.missingSecretUrl,
      policy: opts.policy ?? TEST_POLICY,
      allowUnboundSecrets: opts.allowUnbound,
      cdpSessionStore,
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
    expect(body.token).toMatch(/^cct_/);
    expect(body.expires_in).toBe(900);

    // Token resolves to the real value
    const resolved = tokenStore.resolve(body.token as string);
    expect(resolved).toBe('ghp_real_token_123');
  });

  it('simple secret ignores field param', async () => {
    await setup({ github: 'ghp_real_token_123' });
    const { status, body } = await fetchJSON(port, '/_vault/github?field=whatever');
    expect(status).toBe(200);
    expect(body.token).toMatch(/^cct_/);

    const resolved = tokenStore.resolve(body.token as string);
    expect(resolved).toBe('ghp_real_token_123');
  });

  it('returns 404 for missing secret', async () => {
    await setup({}, {}, { missingSecretUrl: 'https://dashboard.example.com/integrations' });
    const { status, body } = await fetchJSON(port, '/_vault/nope');
    expect(status).toBe(404);
    expect(body.error).toContain('not found');
    expect(body.vault_url).toBe('https://dashboard.example.com/integrations');
  });

  it('omits vault_url when no missing-secret URL is configured', async () => {
    await setup({});
    const { status, body } = await fetchJSON(port, '/_vault/nope');
    expect(status).toBe(404);
    expect(body).not.toHaveProperty('vault_url');
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
    expect(body.token).toMatch(/^cct_/);
    expect(tokenStore.resolve(body.token as string)).toBe('sbp_secret');
    expect(body.value).toBeUndefined();
    expect(tokenStore.size).toBe(1);
  });

  it('issues tokens for all fields when no _cleartext metadata', async () => {
    await setup({ supabase: JSON.stringify({ 'project-url': 'https://proj.supabase.co', 'service-role-key': 'sbp_secret' }) });

    const { status: s1, body: b1 } = await fetchJSON(port, '/_vault/supabase?field=project-url');
    expect(s1).toBe(200);
    expect(b1.token).toMatch(/^cct_/);
    expect(tokenStore.resolve(b1.token as string)).toBe('https://proj.supabase.co');

    const { status: s2, body: b2 } = await fetchJSON(port, '/_vault/supabase?field=service-role-key');
    expect(s2).toBe(200);
    expect(b2.token).toMatch(/^cct_/);
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
    expect(body.token).toMatch(/^cct_/);
    expect(tokenStore.resolve(body.token as string)).toBe('["a","b","c"]');
  });

  it('treats non-JSON strings as simple secrets', async () => {
    await setup({ 'api-key': 'not-json-at-all' });
    const { status, body } = await fetchJSON(port, '/_vault/api-key');
    expect(status).toBe(200);
    expect(body.token).toMatch(/^cct_/);
    expect(tokenStore.resolve(body.token as string)).toBe('not-json-at-all');
  });

  it('URL-decodes secret names', async () => {
    await setup({ 'my-integration': 'secret-val' });
    const { status, body } = await fetchJSON(port, '/_vault/my%2Dintegration');
    expect(status).toBe(200);
    expect(body.token).toMatch(/^cct_/);
  });

  it('rejects invalid secret names with 400 before reaching the provider', async () => {
    const deps = await setup({ 'my integration': 'secret-val' });
    const get = vi.spyOn(deps.provider.secrets, 'get');
    const exists = vi.spyOn(deps.provider.secrets, 'exists');
    for (const path of [
      '/_vault/my%20integration',
      '/_vault/..%2F..%2Fetc%2Fpasswd',
      '/_vault/%2E%2E',
      '/_vault/.hidden',
      '/_vault/a%2Fb?check=1',
      `/_vault/${'a'.repeat(129)}`,
      '/_vault/%E0%A4%A',
    ]) {
      const { status, body } = await rawGetJSON(port, path);
      expect(status, path).toBe(400);
      expect(String(body.error), path).toContain('Invalid secret name');
    }
    expect(get).not.toHaveBeenCalled();
    expect(exists).not.toHaveBeenCalled();
    expect(tokenStore.size).toBe(0);
  });

  it('accepts names at the length limit', async () => {
    const name = 'a'.repeat(128);
    await setup({ [name]: 'v' }, {}, { allowUnbound: true });
    expect((await fetchJSON(port, `/_vault/${name}`)).status).toBe(200);
  });

  it('returns false for non-vault paths', async () => {
    await setup({});
    const res = await realFetch(`http://127.0.0.1:${port}/not-vault`);
    expect(res.status).toBe(404);
    const text = await res.text();
    expect(text).toBe('Not a vault request');
  });

  it('issued multi-field tokens are swappable in strings', async () => {
    await setup({ trello: JSON.stringify({ 'api-key': 'trello-key-123', 'token': 'trello-tok-456', _swap_url: true }) });

    const { body: b1 } = await fetchJSON(port, '/_vault/trello?field=api-key');
    const { body: b2 } = await fetchJSON(port, '/_vault/trello?field=token');

    const url = `https://api.trello.com/1/boards?key=${b1.token}&token=${b2.token}`;
    const swapped = tokenStore.replaceAll(url, https('api.trello.com'), { kind: 'url' });
    expect(swapped.output).toBe('https://api.trello.com/1/boards?key=trello-key-123&token=trello-tok-456');
  });

  // --- Host binding at mint time ---

  describe('host binding', () => {
    it('refuses to mint a ticket for an unbound secret (403, nothing issued)', async () => {
      await setup({ 'unlisted-key': 'sk-real' });
      const { status, body } = await fetchJSON(port, '/_vault/unlisted-key');
      expect(status).toBe(403);
      expect(body.error).toContain("'unlisted-key' is not bound to any host");
      expect(JSON.stringify(body)).not.toContain('sk-real');
      expect(tokenStore.size).toBe(0);
    });

    it('mints an unbound ticket only when unbound secrets are allowed', async () => {
      await setup({ 'unlisted-key': 'sk-real' }, {}, { allowUnbound: true });
      const { status, body } = await fetchJSON(port, '/_vault/unlisted-key');
      expect(status).toBe(200);
      expect(body.allowed_hosts).toBeNull();
      expect(tokenStore.replaceAll(body.token as string, https('anything.example'), AUTH).swaps).toEqual([
        { secretName: 'unlisted-key', ageMs: expect.any(Number), unbound: true },
      ]);
    });

    it('includes allowed_hosts in the mint response and snapshots them on the ticket', async () => {
      await setup({ github: 'ghp_real' });
      const { status, body } = await fetchJSON(port, '/_vault/github');
      expect(status).toBe(200);
      expect(body.allowed_hosts).toEqual(['api.github.com']);
      expect(tokenStore.replaceAll(`${body.token}`, https('api.github.com'), AUTH).output).toBe('ghp_real');
      expect(tokenStore.replaceAll(`${body.token}`, https('attacker.example'), AUTH).denied).toHaveLength(1);
    });

    it('binds a secret by its in-band _allowed_hosts alone, as a simple secret', async () => {
      await setup({ 'runtime-key': JSON.stringify({ value: 'sk-runtime', _allowed_hosts: ['api.runtime.example'] }) });
      const { status, body } = await fetchJSON(port, '/_vault/runtime-key');
      expect(status).toBe(200);
      expect(body.allowed_hosts).toEqual(['api.runtime.example']);
      expect(tokenStore.resolve(body.token as string)).toBe('sk-runtime');
    });

    it('intersects in-band hosts with the policy, so a secret cannot widen the operator\'s list', async () => {
      await setup({ supabase: JSON.stringify({ key: 'k', _allowed_hosts: ['proj.supabase.co', 'attacker.example'] }) });
      const { body } = await fetchJSON(port, '/_vault/supabase?field=key');
      expect(body.allowed_hosts).toEqual(['proj.supabase.co']);
      expect(tokenStore.replaceAll(`${body.token}`, https('attacker.example'), AUTH).denied).toHaveLength(1);
    });

    it('refuses an empty intersection with 403 and an invalid _allowed_hosts with 500', async () => {
      await setup({
        github: JSON.stringify({ value: 'g', _allowed_hosts: ['attacker.example'] }),
        'runtime-key': JSON.stringify({ value: 'r', _allowed_hosts: ['*'] }),
      });
      const empty = await fetchJSON(port, '/_vault/github');
      expect(empty.status).toBe(403);
      expect(empty.body.error).toContain('no host allowed by both');
      const invalid = await fetchJSON(port, '/_vault/runtime-key');
      expect(invalid.status).toBe(500);
      expect(invalid.body.error).toContain('invalid _allowed_hosts');
      expect(tokenStore.size).toBe(0);
    });

    it('hides _allowed_hosts from the field list and refuses it as a field', async () => {
      await setup({ supabase: JSON.stringify({ key: 'k', _allowed_hosts: ['proj.supabase.co'] }) });
      expect((await fetchJSON(port, '/_vault/supabase')).body.fields).toEqual(['key']);
      expect((await fetchJSON(port, '/_vault/supabase?field=_allowed_hosts')).status).toBe(400);
    });

    it('still returns cleartext fields of an unbound secret (they are not tickets)', async () => {
      await setup({ 'unlisted-db': JSON.stringify({ url: 'https://db.example', key: 'k', _cleartext: ['url'] }) });
      expect((await fetchJSON(port, '/_vault/unlisted-db?field=url')).body).toEqual({ value: 'https://db.example', cleartext: true });
      expect((await fetchJSON(port, '/_vault/unlisted-db?field=key')).status).toBe(403);
    });

    it('binds shared-secret tickets to the policy\'s shared hosts', async () => {
      await setup({}, { 'browserbase-api-key': 'bb_real' });
      const { body } = await fetchJSON(port, '/_secret/browserbase-api-key');
      expect(body.allowed_hosts).toEqual(['api.browserbase.com']);
      expect(tokenStore.replaceAll(`${body.token}`, https('attacker.example'), AUTH).denied).toHaveLength(1);
    });

    it('binds a web login to the policy hosts and refuses an unbound login', async () => {
      const login = JSON.stringify({ username: 'alice', password: 'pw' });
      await setup({ 'example-login': login, 'other-login': login });
      let seen: import('./cdp-session-store.js').LoginRequest | undefined;
      cdpSessionStore.attach(sid, { login: async req => { seen = req; return { status: 200, url: 'https://login.example.com/' }; } });
      const body = { sessionId: sid, fields: { username: '#u', password: '#p' }, submit: '#go', until: 'navigation' };

      const ok = await postJSON(port, '/_vault/example-login/login', body);
      expect(ok.status).toBe(200);
      expect(seen?.allowedHosts?.length).toBeGreaterThan(0);
      // other-login has no policy rule → unbound → refused at binding (403), never reaches the driver.
      const refused = await postJSON(port, '/_vault/other-login/login', body);
      expect(refused.status).toBe(403);
    });

    it('refuses to fill a signing secret\'s key field into a page (400, never reaches the driver)', async () => {
      const policy = parsePolicy(JSON.stringify({
        secrets: { 'aws-console': { allowed_hosts: ['signin.aws.amazon.com'], signing: 'aws-sigv4' } },
      }), []);
      await setup({ 'aws-console': JSON.stringify({ access_key_id: 'AKIAREAL', secret_access_key: 'real-key', SecretAccessKey: 'real-key' }) }, {}, { policy });
      let calls = 0;
      cdpSessionStore.attach(sid, { login: async () => { calls++; return { status: 200, url: 'https://signin.aws.amazon.com/' }; } });
      for (const field of ['secret_access_key', 'SecretAccessKey']) {
        const res = await postJSON(port, '/_vault/aws-console/login', { sessionId: sid, fields: { access_key_id: '#u', [field]: '#p' }, submit: '#go', until: 'navigation' });
        expect(res.status, field).toBe(400);
        expect(res.body.error).toContain('signing key');
      }
      expect(calls).toBe(0);
    });
  });

  // --- Shared secrets (/_secret/{name}) ---

  describe('signing secrets', () => {
    const SIGNING_POLICY = parsePolicy(JSON.stringify({
      secrets: {
        'aws-reports': { allowed_hosts: ['reports.s3.us-east-1.amazonaws.com'], signing: 'aws-sigv4' },
        'aws-inband': { allowed_hosts: ['sts.us-east-1.amazonaws.com'] },
      },
      shared: { 'aws-shared': { allowed_hosts: ['sts.us-east-1.amazonaws.com'], signing: 'aws-sigv4' } },
    }), []);
    const KEY = 'wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY';
    const snake = JSON.stringify({ access_key_id: 'AKIAREAL', secret_access_key: KEY, passphrase: 'pp-secret', region: 'us-east-1', _cleartext: ['region'] });
    const pascal = JSON.stringify({ Version: 1, AccessKeyId: 'ASIAREAL', SecretAccessKey: KEY, SessionToken: 'tok-secret', Expiration: '2026-01-01T00:00:00Z' });

    function captureLog() {
      const lines: string[] = [];
      const spies = (['log', 'warn', 'error'] as const).map(m => vi.spyOn(console, m).mockImplementation((...a: unknown[]) => { lines.push(a.map(String).join(' ')); }));
      return { lines, restore: () => spies.forEach(s => s.mockRestore()) };
    }

    it('mints one credential ticket with the public scheme, and logs signing=… and nothing else new', async () => {
      await setup({ 'aws-reports': snake }, {}, { policy: SIGNING_POLICY });
      const log = captureLog();
      const { status, body } = await fetchJSON(port, '/_vault/aws-reports');
      log.restore();
      expect(status).toBe(200);
      expect(Object.keys(body).sort()).toEqual(['allowed_hosts', 'expires_in', 'signing', 'token']);
      expect(body).toEqual(expect.objectContaining({ expires_in: 900, allowed_hosts: ['reports.s3.us-east-1.amazonaws.com'], signing: 'aws-sigv4' }));
      const ticket = tokenStore.signingTicket(body.token as string);
      expect(ticket?.credential).toEqual({ scheme: 'aws-sigv4', accessKeyId: 'AKIAREAL', secretAccessKey: KEY });
      expect(tokenStore.resolve(body.token as string)).toBeNull();
      expect(log.lines).toEqual(['[issue] secret=aws-reports ttl_s=900 signing=aws-sigv4']);
    });

    it('accepts `aws configure export-credentials` casing, session token included', async () => {
      await setup({ 'aws-reports': pascal }, {}, { policy: SIGNING_POLICY });
      const { status, body } = await fetchJSON(port, '/_vault/aws-reports');
      expect(status).toBe(200);
      expect(tokenStore.signingTicket(body.token as string)?.credential)
        .toEqual({ scheme: 'aws-sigv4', accessKeyId: 'ASIAREAL', secretAccessKey: KEY, sessionToken: 'tok-secret' });
      expect(JSON.stringify(body)).not.toContain('tok-secret');
    });

    it('enables signing from an in-band _signing alone', async () => {
      await setup({ 'aws-inband': JSON.stringify({ access_key_id: 'AKIAREAL', secret_access_key: KEY, _signing: 'aws-sigv4' }) }, {}, { policy: SIGNING_POLICY });
      const { status, body } = await fetchJSON(port, '/_vault/aws-inband');
      expect(status).toBe(200);
      expect(body.signing).toBe('aws-sigv4');
    });

    it('refuses ?field= on the key field (either casing) with 400', async () => {
      await setup({ 'aws-reports': snake, 'aws-pascal': pascal }, {}, { policy: parsePolicy(JSON.stringify({ secrets: { 'aws-*': { allowed_hosts: ['reports.s3.us-east-1.amazonaws.com'], signing: 'aws-sigv4' } } }), []) });
      for (const path of ['/_vault/aws-reports?field=secret_access_key', '/_vault/aws-pascal?field=SecretAccessKey']) {
        const { status, body } = await fetchJSON(port, path);
        expect(status, path).toBe(400);
        expect(body.error).toContain('use the credential ticket');
      }
      expect(tokenStore.size).toBe(0);
    });

    it('issues a normal literal ticket for another field, and returns a _cleartext field', async () => {
      await setup({ 'aws-reports': snake }, {}, { policy: SIGNING_POLICY });
      const pp = await fetchJSON(port, '/_vault/aws-reports?field=passphrase');
      expect(pp.status).toBe(200);
      expect(tokenStore.resolve(pp.body.token as string)).toBe('pp-secret');
      expect(pp.body.signing).toBeUndefined();
      const region = await fetchJSON(port, '/_vault/aws-reports?field=region');
      expect(region.body).toEqual({ value: 'us-east-1', cleartext: true });
    });

    it('fails with 500 and issues nothing when the key is missing, whatever is asked', async () => {
      await setup({
        'aws-reports': JSON.stringify({ access_key_id: 'AKIAREAL', passphrase: 'pp' }),
      }, {}, { policy: SIGNING_POLICY });
      for (const path of ['/_vault/aws-reports', '/_vault/aws-reports?field=passphrase']) {
        const { status, body } = await fetchJSON(port, path);
        expect(status, path).toBe(500);
        expect(body.error).toContain('secret_access_key');
      }
      expect(tokenStore.size).toBe(0);
    });

    it('refuses an access key id that cannot sit in a credential scope', async () => {
      await setup({ 'aws-reports': JSON.stringify({ access_key_id: 'AKIA/REAL', secret_access_key: KEY }) }, {}, { policy: SIGNING_POLICY });
      expect((await fetchJSON(port, '/_vault/aws-reports')).status).toBe(500);
    });

    it('fails with 500 on an invalid in-band _signing', async () => {
      await setup({ 'aws-reports': JSON.stringify({ access_key_id: 'AKIAREAL', secret_access_key: KEY, _signing: 'sigv2' }) }, {}, { policy: SIGNING_POLICY });
      expect((await fetchJSON(port, '/_vault/aws-reports')).status).toBe(500);
      expect(tokenStore.size).toBe(0);
    });

    it('mints a signing ticket for an allowlisted shared secret', async () => {
      await setup({}, { 'aws-shared': snake }, { policy: SIGNING_POLICY });
      const { status, body } = await fetchJSON(port, '/_secret/aws-shared');
      expect(status).toBe(200);
      expect(body.signing).toBe('aws-sigv4');
      expect(tokenStore.signingTicket(body.token as string)?.secretName).toBe('shared:aws-shared');
    });
  });

  describe('/_secret/{name}', () => {
    it('issues token for allowlisted shared secret', async () => {
      await setup({}, { 'browserbase-api-key': 'bb_live_real_key_xyz' });
      const { status, body } = await fetchJSON(port, '/_secret/browserbase-api-key');
      expect(status).toBe(200);
      expect(body.token).toMatch(/^cct_/);
      expect(body.expires_in).toBe(900);
      expect(tokenStore.resolve(body.token as string)).toBe('bb_live_real_key_xyz');
    });

    it('returns 403 for non-allowlisted secret name', async () => {
      await setup({}, { 'internal-admin-key': 'sk-master-xxx' });
      const { status, body } = await fetchJSON(port, '/_secret/internal-admin-key');
      expect(status).toBe(403);
      expect(body.error).toContain('not in the shared-secret allowlist');
      // No token issued — even though the upstream secret exists, the proxy refuses to mint
      expect(tokenStore.size).toBe(0);
    });

    it('allowlists only the policy file\'s shared section (none without a policy)', async () => {
      await setup({}, { 'browserbase-api-key': 'k' }, { policy: EMPTY_POLICY });
      const { status, body } = await fetchJSON(port, '/_secret/browserbase-api-key');
      expect(status).toBe(403);
      expect(body.error).toContain('not in the shared-secret allowlist');
      expect(tokenStore.size).toBe(0);
    });

    it('allowlists any shared secret the policy names', async () => {
      const policy = parsePolicy(JSON.stringify({ shared: { 'search-api-key': { allowed_hosts: ['api.search.example'] } } }), []);
      await setup({}, { 'search-api-key': 'sk-search', 'browserbase-api-key': 'k' }, { policy });
      expect((await fetchJSON(port, '/_secret/search-api-key')).status).toBe(200);
      expect((await fetchJSON(port, '/_secret/browserbase-api-key')).status).toBe(403);
    });

    it('rejects invalid shared-secret names with 400', async () => {
      await setup({}, { 'browserbase-api-key': 'k' });
      expect((await fetchJSON(port, '/_secret/..%2Fbrowserbase-api-key')).status).toBe(400);
    });

    it('returns 404 when the provider has no shared store', async () => {
      await setup({}, {}, { noShared: true });
      const { status, body } = await fetchJSON(port, '/_secret/browserbase-api-key');
      expect(status).toBe(404);
      expect(body.error).toContain('has no shared secrets');
    });

    it('returns 404 when secret is not in the shared store', async () => {
      await setup({}, {});
      const { status, body } = await fetchJSON(port, '/_secret/browserbase-api-key');
      expect(status).toBe(404);
      expect(body.error).toContain('not found');
    });

    it('issued shared-secret tokens are swappable in headers', async () => {
      await setup({}, { 'browserbase-api-key': JSON.stringify({ value: 'bb_live_xyz_real', _swap_headers: ['X-BB-API-Key'] }) });
      const { body } = await fetchJSON(port, '/_secret/browserbase-api-key');
      expect(body.swap_headers).toEqual(['x-bb-api-key']);
      const header = `x-bb-api-key: ${body.token}\r\n`;
      const swapped = tokenStore.replaceAll(header, https('api.browserbase.com'), { kind: 'header', name: 'x-bb-api-key' });
      expect(swapped.output).toBe('x-bb-api-key: bb_live_xyz_real\r\n');
    });
  });

  // --- Provider capabilities and name validation on POST routes ---

  describe('provider capabilities', () => {
    it('rejects a login with an invalid secret name in the path', async () => {
      await setup({});
      const { status, body } = await postJSON(port, '/_vault/..%2Fexample-login/login', { sessionId: 'abc', fields: { u: '#u' }, submit: '#go' });
      expect(status).toBe(400);
      expect(body.error).toContain('Invalid secret name');
    });

    it('rejects refresh with an invalid secret name', async () => {
      await setup({});
      const { status } = await fetchJSON(port, '/_vault/..%2Fgoogle/refresh', 'POST');
      expect(status).toBe(400);
    });

    it('returns 501 for refresh on a read-only provider without calling the token endpoint', async () => {
      const originalFetch = globalThis.fetch;
      globalThis.fetch = vi.fn() as unknown as typeof fetch;
      try {
        await setup({ google: JSON.stringify({ refresh_token: 'r', token_url: 'https://oauth2.example.test/token', client_id: 'c', client_secret: 's' }) }, {}, { writable: false });
        const { status, body } = await fetchJSON(port, '/_vault/google/refresh', 'POST');
        expect(status).toBe(501);
        expect(body.error).toContain('read-only');
        expect(globalThis.fetch).not.toHaveBeenCalled();
      } finally {
        globalThis.fetch = originalFetch;
      }
    });
  });

  // --- Broker-performed login (/_vault/{name}/login) ---

  describe('/_vault/{name}/login', () => {
    const login = JSON.stringify({ username: 'alice@example.com', password: 'hunter2', _cleartext: ['username'] });
    const okReq = { sessionId: '', fields: { username: '#user', password: '#pass' }, submit: '#go', until: 'navigation' };

    /** Attach a fake controller that records the request and returns `result`. */
    function attachController(result: LoginResult): { calls: LoginRequest[] } {
      const calls: LoginRequest[] = [];
      cdpSessionStore.attach(sid, { login: async req => { calls.push(req); return result; } });
      return { calls };
    }

    it('fills from the stored secret and maps 200 → ok (the agent never supplies values)', async () => {
      await setup({ 'example-login': login });
      const { calls } = attachController({ status: 200, url: 'https://login.example.com/home' });
      const { status, body } = await postJSON(port, '/_vault/example-login/login', { ...okReq, sessionId: sid });
      expect(status).toBe(200);
      expect(body).toEqual({ status: 'ok', url: 'https://login.example.com/home' });
      // Values come from the secret, not the request body.
      expect(calls[0].values).toEqual({ username: 'alice@example.com', password: 'hunter2' });
      expect(calls[0].allowedHosts?.length).toBeGreaterThan(0);
      // The sensitive field is registered for inbound redaction; the cleartext one isn't.
      const vals = tokenStore.sessionValues(sid).map(v => v.value);
      expect(vals).toContain('hunter2');
      expect(vals).not.toContain('alice@example.com');
    });

    it.each([
      ['403', { status: 403, error: 'credential-origin violation: x' } as LoginResult, 403, { error: 'credential-origin violation: x' }],
      ['404 selector-not-found', { status: 404, reason: 'selector-not-found', field: 'password' } as LoginResult, 404, { status: 'selector-not-found', field: 'password' }],
      ['409 no-success', { status: 409, reason: 'no-success', cleared: true } as LoginResult, 409, { status: 'no-success', cleared: true }],
      ['409 interception-active', { status: 409, reason: 'interception-active' } as LoginResult, 409, { status: 'interception-active' }],
      ['409 busy', { status: 409, reason: 'busy' } as LoginResult, 409, { status: 'busy' }],
      ['409 page-ambiguous', { status: 409, reason: 'page-ambiguous' } as LoginResult, 409, { status: 'page-ambiguous' }],
      ['502 driver-error', { status: 502, reason: 'driver-error', cleared: true } as LoginResult, 502, { status: 'driver-error', cleared: true }],
      ['502 upstream-closed', { status: 502, reason: 'upstream-closed' } as LoginResult, 502, { status: 'upstream-closed' }],
    ])('maps the driver result %s to its HTTP response', async (_label, result, expectStatus, expectBody) => {
      await setup({ 'example-login': login });
      attachController(result);
      const { status, body } = await postJSON(port, '/_vault/example-login/login', { ...okReq, sessionId: sid });
      expect(status).toBe(expectStatus);
      expect(body).toEqual(expectBody);
    });

    it('404s when no controller is attached (session not connected), before reading the secret', async () => {
      const deps = await setup({ 'example-login': login });
      const get = vi.spyOn(deps.provider.secrets, 'get');
      const { status, body } = await postJSON(port, '/_vault/example-login/login', { ...okReq, sessionId: sid });
      expect(status).toBe(404);
      expect(body.error).toContain('not-connected');
      expect(get).not.toHaveBeenCalled();
    });

    it('404s when the secret does not exist', async () => {
      await setup({});
      attachController({ status: 200, url: 'x' });
      const { status } = await postJSON(port, '/_vault/example-login/login', { ...okReq, sessionId: sid });
      expect(status).toBe(404);
    });

    it('501s when the secret is not a multi-value login', async () => {
      await setup({ 'example-login': 'just-a-string' });
      attachController({ status: 200, url: 'x' });
      const { status } = await postJSON(port, '/_vault/example-login/login', { ...okReq, sessionId: sid });
      expect(status).toBe(501);
    });

    it('501s when a requested field is not on the secret', async () => {
      await setup({ 'example-login': JSON.stringify({ username: 'a', password: 'b' }) });
      attachController({ status: 200, url: 'x' });
      const { status, body } = await postJSON(port, '/_vault/example-login/login', { ...okReq, sessionId: sid, fields: { username: '#u', otp: '#o' } });
      expect(status).toBe(501);
      expect(body.error).toContain("no field 'otp'");
    });

    it('400s on a missing fields object or bad submit/until', async () => {
      await setup({ 'example-login': login });
      attachController({ status: 200, url: 'x' });
      expect((await postJSON(port, '/_vault/example-login/login', { sessionId: sid })).status).toBe(400);
      expect((await postJSON(port, '/_vault/example-login/login', { ...okReq, sessionId: sid, submit: 42 })).status).toBe(400);
      expect((await postJSON(port, '/_vault/example-login/login', { ...okReq, sessionId: sid, until: { nope: 1 } })).status).toBe(400);
    });
  });

  // --- mint-tokens is gone (replaced by /login) ---

  describe('/_vault/mint-tokens (removed)', () => {
    it('returns 404: the route no longer exists', async () => {
      await setup({ 'example-login': JSON.stringify({ username: 'a', password: 'b' }) });
      const res = await realFetch(`http://127.0.0.1:${port}/_vault/mint-tokens`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ secretName: 'example-login', sessionId: sid }),
      });
      expect(res.status).toBe(404);
    });
  });

  // --- OAuth Refresh ---

  describe('/_vault/{name}/refresh', () => {
    const googleSecret = JSON.stringify({
      access_token: 'ya29.old-token',
      refresh_token: '1//old-refresh',
      expires_at: 1000,
      token_url: 'https://oauth2.googleapis.com/token',
      client_id: 'test-client-id',
      client_secret: 'test-client-secret',
      provider: 'google',
      _cleartext: ['provider', 'token_url', 'client_id'],
    });

    it('returns 404 for missing secret', async () => {
      await setup({});
      const { status, body } = await fetchJSON(port, '/_vault/google/refresh', 'POST');
      expect(status).toBe(404);
      expect(body.error).toContain('not found');
    });

    it('returns 400 for non-JSON secret', async () => {
      await setup({ google: 'simple-string' });
      const { status, body } = await fetchJSON(port, '/_vault/google/refresh', 'POST');
      expect(status).toBe(400);
      expect(body.error).toContain('not a multi-value');
    });

    it('returns 400 for secret missing required refresh fields', async () => {
      await setup({ google: JSON.stringify({ access_token: 'ya29.tok' }) });
      const { status, body } = await fetchJSON(port, '/_vault/google/refresh', 'POST');
      expect(status).toBe(400);
      expect(body.error).toContain('missing required fields');
    });

    it('returns 502 when upstream refresh fails', async () => {
      const originalFetch = globalThis.fetch;
      globalThis.fetch = vi.fn().mockResolvedValue({
        ok: false,
        status: 400,
        text: async () => '{"error":"invalid_grant"}',
      }) as unknown as typeof fetch;

      try {
        await setup({ google: googleSecret });
        const { status, body } = await fetchJSON(port, '/_vault/google/refresh', 'POST');
        expect(status).toBe(502);
        expect(body.error).toContain('refresh failed');
      } finally {
        globalThis.fetch = originalFetch;
      }
    });

    it('logs only the status and a sanitised error code when refresh fails', async () => {
      const originalFetch = globalThis.fetch;
      const echoed = JSON.stringify({
        error: 'invalid_grant',
        error_description: 'Bad refresh token 1//0g-real-refresh-token for client 123-secret.apps',
        client_secret: 'echoed-client-secret',
      });
      globalThis.fetch = vi.fn().mockResolvedValue({ ok: false, status: 400, text: async () => echoed }) as unknown as typeof fetch;
      const errors = vi.spyOn(console, 'error').mockImplementation(() => {});

      try {
        await setup({ google: googleSecret });
        const { status } = await fetchJSON(port, '/_vault/google/refresh', 'POST');
        expect(status).toBe(502);
        const logged = errors.mock.calls.map(c => c.map(String).join(' ')).join('\n');
        expect(logged).toContain('status=400 error=invalid_grant');
        expect(logged).not.toContain('real-refresh-token');
        expect(logged).not.toContain('echoed-client-secret');
        expect(logged).not.toContain('error_description');
      } finally {
        errors.mockRestore();
        globalThis.fetch = originalFetch;
      }
    });

    it('refreshes token, updates vault, and returns cct_*', async () => {
      const originalFetch = globalThis.fetch;
      globalThis.fetch = vi.fn().mockResolvedValue({
        ok: true,
        json: async () => ({
          access_token: 'ya29.new-token',
          expires_in: 3600,
          token_type: 'Bearer',
        }),
      }) as unknown as typeof fetch;

      try {
        const secrets: Record<string, string> = { google: googleSecret };
        const deps = await setup(secrets);
        const { status, body } = await fetchJSON(port, '/_vault/google/refresh', 'POST');

        expect(status).toBe(200);
        expect(body.token).toMatch(/^cct_/);
        expect(body.expires_in).toBe(900);

        // The cct_* should resolve to the new access token
        expect(tokenStore.resolve(body.token as string)).toBe('ya29.new-token');

        // Vault should have been updated
        const putMock = vi.mocked(deps.provider.secrets.put!);
        expect(putMock).toHaveBeenCalledOnce();
        const [name, value] = putMock.mock.calls[0];
        expect(name).toBe('google');
        const updated = JSON.parse(value);
        expect(updated.access_token).toBe('ya29.new-token');
        expect(updated.refresh_token).toBe('1//old-refresh'); // unchanged
        expect(updated.expires_at).toBeGreaterThan(Math.floor(Date.now() / 1000));

        // Verify the fetch call to Google token endpoint
        const fetchCall = vi.mocked(globalThis.fetch).mock.calls[0];
        expect(fetchCall[0]).toBe('https://oauth2.googleapis.com/token');
        const fetchBody = fetchCall[1]?.body as string;
        expect(fetchBody).toContain('refresh_token=1%2F%2Fold-refresh');
        expect(fetchBody).toContain('client_id=test-client-id');
        expect(fetchBody).toContain('grant_type=refresh_token');
        // A redirect from token_url would re-POST client_secret to an unchecked host.
        expect(fetchCall[1]?.redirect).toBe('error');
      } finally {
        globalThis.fetch = originalFetch;
      }
    });

    it('refuses to send client_secret to a token_url outside the secret\'s allowed hosts', async () => {
      const originalFetch = globalThis.fetch;
      globalThis.fetch = vi.fn() as unknown as typeof fetch;
      try {
        const hijacked = JSON.stringify({ ...JSON.parse(googleSecret), token_url: 'https://attacker.example/token' });
        await setup({ google: hijacked });
        const { status, body } = await fetchJSON(port, '/_vault/google/refresh', 'POST');
        expect(status).toBe(403);
        expect(body.error).toContain("token_url host 'attacker.example'");
        expect(globalThis.fetch).not.toHaveBeenCalled();
        expect(tokenStore.size).toBe(0);
      } finally {
        globalThis.fetch = originalFetch;
      }
    });

    it('refuses refresh for an unbound secret before calling the token endpoint', async () => {
      const originalFetch = globalThis.fetch;
      globalThis.fetch = vi.fn() as unknown as typeof fetch;
      try {
        await setup({ 'unlisted-oauth': googleSecret });
        const { status } = await fetchJSON(port, '/_vault/unlisted-oauth/refresh', 'POST');
        expect(status).toBe(403);
        expect(globalThis.fetch).not.toHaveBeenCalled();
      } finally {
        globalThis.fetch = originalFetch;
      }
    });

    it('gives the refreshed access-token ticket the secret\'s binding', async () => {
      const originalFetch = globalThis.fetch;
      globalThis.fetch = vi.fn().mockResolvedValue({
        ok: true,
        json: async () => ({ access_token: 'ya29.new-token', expires_in: 3600 }),
      }) as unknown as typeof fetch;
      try {
        await setup({ google: googleSecret });
        const { body } = await fetchJSON(port, '/_vault/google/refresh', 'POST');
        expect(body.allowed_hosts).toEqual(['*.googleapis.com']);
        expect(tokenStore.replaceAll(`${body.token}`, https('www.googleapis.com'), AUTH).output).toBe('ya29.new-token');
        expect(tokenStore.replaceAll(`${body.token}`, https('attacker.example'), AUTH).denied).toHaveLength(1);
      } finally {
        globalThis.fetch = originalFetch;
      }
    });

    it('handles refresh token rotation (new refresh_token in response)', async () => {
      const originalFetch = globalThis.fetch;
      globalThis.fetch = vi.fn().mockResolvedValue({
        ok: true,
        json: async () => ({
          access_token: 'ya29.rotated-token',
          refresh_token: '1//new-refresh',
          expires_in: 3600,
          token_type: 'Bearer',
        }),
      }) as unknown as typeof fetch;

      try {
        const secrets: Record<string, string> = { google: googleSecret };
        const deps = await setup(secrets);
        const { status } = await fetchJSON(port, '/_vault/google/refresh', 'POST');
        expect(status).toBe(200);

        // Vault should have the rotated refresh token
        const putMock = vi.mocked(deps.provider.secrets.put!);
        const updated = JSON.parse(putMock.mock.calls[0][1]);
        expect(updated.refresh_token).toBe('1//new-refresh');
      } finally {
        globalThis.fetch = originalFetch;
      }
    });
  });
});

describe('oauthErrorCode', () => {
  it('returns the RFC 6749 error code', () => {
    expect(oauthErrorCode('{"error":"invalid_grant","error_description":"x"}')).toBe('invalid_grant');
  });

  it('never returns free text from the body', () => {
    expect(oauthErrorCode('not json, maybe a token 1//abc')).toBe('unparseable');
    expect(oauthErrorCode('{"error_description":"secret"}')).toBe('unknown');
    expect(oauthErrorCode('{"error":"bad grant 1//0g-secret"}')).toBe('unknown');
    expect(oauthErrorCode('{"error":{"code":1}}')).toBe('unknown');
    expect(oauthErrorCode(`{"error":"${'a'.repeat(200)}"}`)).toBe('a'.repeat(64));
  });
});
