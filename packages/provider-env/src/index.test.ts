import { describe, it, expect } from 'vitest';
import { ConfigError, InvalidSecretNameError, createCoatcheck, TokenStore, CertAuthority, CdpSessionStore } from '@coatcheck/core';
import createProvider, { createEnvProvider, envSuffixFor, loadEnvConfig, nameForEnvSuffix } from './index.js';

describe('env name mapping', () => {
  it('is reversible for [a-z0-9-]+ names', () => {
    expect(envSuffixFor('github-token')).toBe('GITHUB_TOKEN');
    expect(nameForEnvSuffix('GITHUB_TOKEN')).toBe('github-token');
    for (const n of ['a', 'x1', 'my-long-name-2']) expect(nameForEnvSuffix(envSuffixFor(n))).toBe(n);
  });

  it('rejects names outside [a-z0-9-]+ (they would not map back)', () => {
    for (const n of ['GitHub', 'a_b', 'a.b', '']) expect(() => envSuffixFor(n)).toThrow(InvalidSecretNameError);
  });

  it('ignores variables whose names do not map back', () => {
    expect(nameForEnvSuffix('lower')).toBeNull();
    expect(nameForEnvSuffix('A.B')).toBeNull();
  });
});

describe('env provider', () => {
  const env = {
    COATCHECK_SECRET_GITHUB_TOKEN: 'gh-value',
    COATCHECK_SECRET_EMPTY: '',
    COATCHECK_SECRET_weird: 'ignored',
    COATCHECK_SHARED_SECRET_BROWSERBASE_API_KEY: 'bb-value',
    UNRELATED: 'x',
  };

  it('reads per-agent and shared secrets', async () => {
    const p = await createProvider({ env });
    expect(await p.secrets.get('github-token')).toEqual({ value: 'gh-value' });
    expect(await p.secrets.get('missing')).toBeNull();
    expect(await p.secrets.get('empty')).toBeNull();
    expect(await p.secrets.exists('github-token')).toBe(true);
    expect(await p.shared!.get('browserbase-api-key')).toEqual({ value: 'bb-value' });
    expect(await p.shared!.get('github-token')).toBeNull();
  });

  it('lists only names that map back, and never shared ones', async () => {
    const p = await createProvider({ env });
    expect(await p.secrets.list()).toEqual(['github-token']);
  });

  it('is read-only', async () => {
    expect((await createProvider({ env })).secrets.put).toBeUndefined();
  });

  it('honours COATCHECK_ENV_PREFIX and rejects bad or overlapping prefixes', () => {
    const p = createEnvProvider({ MY_GITHUB_TOKEN: 'v' }, loadEnvConfig({ env: { COATCHECK_ENV_PREFIX: 'MY_' } }));
    return expect(p.secrets.get('github-token')).resolves.toEqual({ value: 'v' }).then(() => {
      expect(() => loadEnvConfig({ env: { COATCHECK_ENV_PREFIX: 'my_' } })).toThrow(ConfigError);
      expect(() => loadEnvConfig({ env: { COATCHECK_ENV_PREFIX: 'COATCHECK_SHARED_' } })).toThrow(/overlap/);
    });
  });

  it('a name core accepts but the env provider cannot map gets 400 from the vault API', async () => {
    const coatcheck = createCoatcheck({
      tokenStore: new TokenStore(),
      provider: await createProvider({ env }),
      ca: await CertAuthority.create({}),
      cdpSessionStore: new CdpSessionStore(),
      allowUnboundSecrets: true,
    });
    const { port } = await coatcheck.listen(0, '127.0.0.1');
    try {
      const bad = await fetch(`http://127.0.0.1:${port}/_vault/GitHub_Token`);
      expect(bad.status).toBe(400);
      expect(await bad.json()).toEqual({ error: expect.stringContaining('[a-z0-9-]+') });
      const ok = await fetch(`http://127.0.0.1:${port}/_vault/github-token`);
      expect(ok.status).toBe(200);
    } finally {
      await coatcheck.close();
    }
  });
});
