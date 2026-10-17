import { describe, it, expect } from 'vitest';
import { ConfigError, LEGACY_ENV_NAMES, loadConfig, type Env } from './config.js';
import { EMPTY_POLICY } from './policy.js';

const base: Env = { COATCHECK_PROVIDER: 'aws' };

function problems(env: Env): string[] {
  try {
    loadConfig(env);
  } catch (err) {
    if (err instanceof ConfigError) return err.problems;
    throw err;
  }
  return [];
}

describe('loadConfig', () => {
  it('applies defaults', () => {
    expect(loadConfig(base)).toEqual({
      provider: 'aws',
      agentId: undefined,
      bindHost: '127.0.0.1',
      port: 3128,
      ticketTtlSeconds: 900,
      secretCacheTtlSeconds: 300,
      ca: { dir: undefined, subject: 'CN=coatcheck CA, O=coatcheck' },
      missingSecretUrl: undefined,
      cdp: undefined,
      browserAdapters: ['browserbase'],
      policy: EMPTY_POLICY,
      policyFile: undefined,
      allowUnboundSecrets: false,
      mitm: 'bound',
      passthroughHosts: [],
      maxSwapBodyBytes: 1024 * 1024,
    });
  });

  it('reads every core setting', () => {
    const config = loadConfig({
      ...base,
      COATCHECK_AGENT_ID: 'agent-7',
      COATCHECK_BIND_HOST: '0.0.0.0',
      COATCHECK_PORT: '4000',
      COATCHECK_TICKET_TTL_SECONDS: '60',
      COATCHECK_SECRET_CACHE_TTL_SECONDS: '0',
      COATCHECK_CA_DIR: '/var/lib/coatcheck/ca',
      COATCHECK_CA_SUBJECT: 'CN=Example CA',
      COATCHECK_MISSING_SECRET_URL: 'https://dashboard.example.com/secrets',
      COATCHECK_CDP_ENABLED: '1',
      COATCHECK_CDP_PORT: '9444',
      COATCHECK_CDP_ADVERTISE_HOST: 'coatcheck',
      COATCHECK_BROWSER_ADAPTERS: ' browserbase ,',
      COATCHECK_ALLOW_UNBOUND_SECRETS: '1',
      COATCHECK_MITM: 'always',
      COATCHECK_PASSTHROUGH_HOSTS: 'pinned.example.com, *.Pinned.example.org',
      COATCHECK_API_TOKEN: 'a'.repeat(64),
      COATCHECK_MAX_SWAP_BODY_BYTES: '4096',
    });
    expect(config).toEqual({
      provider: 'aws',
      agentId: 'agent-7',
      bindHost: '0.0.0.0',
      port: 4000,
      ticketTtlSeconds: 60,
      secretCacheTtlSeconds: 0,
      ca: { dir: '/var/lib/coatcheck/ca', subject: 'CN=Example CA' },
      missingSecretUrl: 'https://dashboard.example.com/secrets',
      cdp: { port: 9444, advertiseHost: 'coatcheck' },
      browserAdapters: ['browserbase'],
      policy: EMPTY_POLICY,
      policyFile: undefined,
      allowUnboundSecrets: true,
      mitm: 'always',
      passthroughHosts: [
        { kind: 'exact', host: 'pinned.example.com', plaintext: false },
        { kind: 'wildcard', host: 'pinned.example.org', plaintext: false },
      ],
      apiToken: 'a'.repeat(64),
      maxSwapBodyBytes: 4096,
    });
  });

  it('bounds COATCHECK_MAX_SWAP_BODY_BYTES', () => {
    expect(problems({ ...base, COATCHECK_MAX_SWAP_BODY_BYTES: '100' })).toEqual([expect.stringContaining('COATCHECK_MAX_SWAP_BODY_BYTES must be an integer from 1024')]);
    expect(problems({ ...base, COATCHECK_MAX_SWAP_BODY_BYTES: String(65 * 1024 * 1024) })).toHaveLength(1);
  });

  it('rejects unknown browser adapters', () => {
    expect(problems({ ...base, COATCHECK_BROWSER_ADAPTERS: 'browserbase,steel' })).toEqual([expect.stringContaining("unknown adapter 'steel'")]);
  });

  it('treats empty values as unset', () => {
    expect(loadConfig({ ...base, COATCHECK_PORT: '', COATCHECK_AGENT_ID: '' }).port).toBe(3128);
  });

  it('requires a provider; any value is a built-in name or a module specifier (resolved by loadProvider)', () => {
    expect(problems({})).toEqual([expect.stringContaining('COATCHECK_PROVIDER is required')]);
    for (const p of ['aws', 'env', 'file', '@acme/coatcheck-provider-vault', './my-provider.js']) {
      expect(loadConfig({ COATCHECK_PROVIDER: p }).provider).toBe(p);
    }
  });

  it('fails on every legacy name with a pointer to the new one', () => {
    const env: Record<string, string | undefined> = { ...base };
    for (const legacy of Object.keys(LEGACY_ENV_NAMES)) env[legacy] = 'x';
    const found = problems(env);
    for (const [legacy, current] of Object.entries(LEGACY_ENV_NAMES)) {
      expect(found).toContain(`${legacy} was renamed to ${current}`);
    }
    expect(LEGACY_ENV_NAMES.AGENT_LABEL).toBe('COATCHECK_AGENT_ID');
  });

  it('rejects malformed numbers and booleans, reporting all problems at once', () => {
    const found = problems({
      ...base,
      COATCHECK_PORT: '70000',
      COATCHECK_TICKET_TTL_SECONDS: '0',
      COATCHECK_SECRET_CACHE_TTL_SECONDS: '-1',
      COATCHECK_CDP_ENABLED: 'yes',
      COATCHECK_CDP_PORT: '84a4',
      COATCHECK_ALLOW_UNBOUND_SECRETS: 'maybe',
      COATCHECK_MITM: 'sometimes',
      COATCHECK_PASSTHROUGH_HOSTS: 'ok.example.com,*,http://x.example.com,host:443',
    });
    expect(found).toHaveLength(10);
    expect(found).toContain("COATCHECK_MITM must be 'bound' or 'always' (got 'sometimes')");
    expect(found).toContainEqual(expect.stringContaining("COATCHECK_PASSTHROUGH_HOSTS entry 'http://x.example.com': must not have a scheme"));
  });

  it('refuses a non-loopback bind without an API token', () => {
    for (const host of ['0.0.0.0', '::', '[::]', '10.0.0.5', 'coatcheck', '128.0.0.1']) {
      expect(problems({ ...base, COATCHECK_BIND_HOST: host }), host)
        .toEqual([expect.stringContaining('COATCHECK_API_TOKEN is required when COATCHECK_BIND_HOST is not loopback')]);
      expect(loadConfig({ ...base, COATCHECK_BIND_HOST: host, COATCHECK_API_TOKEN: 'x'.repeat(32) }).apiToken).toBe('x'.repeat(32));
    }
    for (const host of ['127.0.0.1', '127.1.2.3', '::1', '[::1]', 'localhost', 'LOCALHOST']) {
      expect(loadConfig({ ...base, COATCHECK_BIND_HOST: host }).apiToken, host).toBeUndefined();
    }
  });

  it('rejects weak API tokens without echoing them', () => {
    for (const token of ['short-token', `${'a'.repeat(32)} b`]) {
      const found = problems({ ...base, COATCHECK_API_TOKEN: token });
      expect(found, token).toEqual([expect.stringContaining('COATCHECK_API_TOKEN must be at least 32 characters')]);
      expect(found.join('\n')).not.toContain(token);
    }
  });

  it('rejects an agent id that could escape a store path', () => {
    for (const id of ['../other', 'a/b', '.hidden']) {
      expect(problems({ ...base, COATCHECK_AGENT_ID: id }), id).toEqual([expect.stringContaining('COATCHECK_AGENT_ID')]);
    }
  });

  it('rejects a non-http missing-secret URL', () => {
    expect(problems({ ...base, COATCHECK_MISSING_SECRET_URL: 'javascript:alert(1)' })).toHaveLength(1);
  });

  it('formats a readable error', () => {
    expect(() => loadConfig({ AGENT_LABEL: 'x' })).toThrow(/Invalid configuration:\n {2}- AGENT_LABEL was renamed to COATCHECK_AGENT_ID/);
  });

  it('loads the policy file through the injected reader', () => {
    const files: Record<string, string> = {
      '/etc/coatcheck/policy.json': JSON.stringify({
        secrets: { 'github-token': { allowed_hosts: ['api.github.com'] } },
        shared: { 'browserbase-api-key': { allowed_hosts: ['api.browserbase.com'] } },
      }),
    };
    const config = loadConfig({ ...base, COATCHECK_POLICY_FILE: '/etc/coatcheck/policy.json' }, p => files[p]);
    expect(config.policyFile).toBe('/etc/coatcheck/policy.json');
    expect(config.policy.secrets).toHaveLength(1);
    expect([...config.policy.shared.keys()]).toEqual(['browserbase-api-key']);
  });

  it('fails startup on an unreadable or invalid policy file', () => {
    const missing = problems({ ...base, COATCHECK_POLICY_FILE: '/nope.json' });
    expect(missing).toEqual([expect.stringContaining("cannot read '/nope.json'")]);
    try {
      loadConfig({ ...base, COATCHECK_POLICY_FILE: '/p.json' }, () => '{"secrets":{"a":{"allowed_hosts":["*"]}}}');
      expect.unreachable();
    } catch (err) {
      expect((err as ConfigError).problems).toEqual([expect.stringContaining('secrets["a"].allowed_hosts[0]')]);
    }
  });
});
