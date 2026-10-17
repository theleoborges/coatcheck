import { describe, it, expect } from 'vitest';
import { ConfigError, LEGACY_ENV_NAMES, loadConfig, type Env } from './config.js';

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
    });
  });

  it('treats empty values as unset', () => {
    expect(loadConfig({ ...base, COATCHECK_PORT: '', COATCHECK_AGENT_ID: '' }).port).toBe(3128);
  });

  it('requires a known provider', () => {
    expect(problems({})).toEqual([expect.stringContaining('COATCHECK_PROVIDER is required')]);
    expect(problems({ COATCHECK_PROVIDER: 'vault' })).toEqual([expect.stringContaining("'vault' is not available")]);
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
    });
    expect(found).toHaveLength(5);
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
});
