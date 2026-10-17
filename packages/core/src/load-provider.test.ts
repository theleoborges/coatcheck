import { describe, it, expect } from 'vitest';
import { loadProvider, BUILTIN_PROVIDERS } from './load-provider.js';
import { ConfigError } from './config.js';
import { createMemoryProvider } from './memory-provider.js';

const ctx = { env: {} };
const notFound = () => Promise.reject(Object.assign(new Error('Cannot find package'), { code: 'ERR_MODULE_NOT_FOUND' }));

describe('loadProvider', () => {
  it('maps built-in names to their packages and other values to module specifiers', async () => {
    const seen: string[] = [];
    const importModule = async (s: string) => {
      seen.push(s);
      return { default: async () => createMemoryProvider() };
    };
    for (const name of ['aws', 'env', 'file', '@acme/provider-vault']) await loadProvider(name, ctx, importModule);
    expect(seen).toEqual([
      '@coatcheck/provider-aws', '@coatcheck/provider-env', '@coatcheck/provider-env/file', '@acme/provider-vault',
    ]);
    expect(Object.keys(BUILTIN_PROVIDERS)).toEqual(['aws', 'env', 'file']);
  });

  it('passes the context to the default export', async () => {
    let got: unknown;
    const p = await loadProvider('x', { env: { A: '1' }, agentId: 'a1' }, async () => ({
      default: async (c: unknown) => { got = c; return createMemoryProvider(); },
    }));
    expect(p.name).toBe('memory');
    expect(got).toEqual({ env: { A: '1' }, agentId: 'a1' });
  });

  it('names the package to install when a built-in is missing', async () => {
    await expect(loadProvider('file', ctx, notFound)).rejects.toThrow(/needs @coatcheck\/provider-env: npm install @coatcheck\/provider-env/);
    await expect(loadProvider('aws', ctx, notFound)).rejects.toBeInstanceOf(ConfigError);
    await expect(loadProvider('./nope.js', ctx, notFound)).rejects.toThrow(/'\.\/nope\.js': module not found/);
  });

  it('rejects a module without a function default export', async () => {
    await expect(loadProvider('m', ctx, async () => ({ createProvider: () => null }))).rejects.toThrow(/no default-exported createProvider/);
  });

  it('rethrows other import failures unchanged', async () => {
    const boom = new SyntaxError('bad module');
    await expect(loadProvider('m', ctx, () => Promise.reject(boom))).rejects.toBe(boom);
  });

  it('loads the real workspace providers through import()', async () => {
    const env = await loadProvider('env', { env: { COATCHECK_SECRET_GITHUB_TOKEN: 'v' } });
    expect(env.name).toBe('env');
    expect(await env.secrets.get('github-token')).toEqual({ value: 'v' });
  });
});
