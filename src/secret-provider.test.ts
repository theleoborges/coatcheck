import { describe, it, expect, vi } from 'vitest';
import { isValidSecretName, withCache, type SecretStore } from './secret-provider.js';
import { createMemoryProvider } from './providers/memory.js';

describe('isValidSecretName', () => {
  it('accepts letters, digits, dot, underscore and dash', () => {
    for (const n of ['github', 'example-login', 'GOOGLE_OAUTH', 'v1.2', '0abc', 'a'.repeat(128)]) {
      expect(isValidSecretName(n), n).toBe(true);
    }
  });

  it('rejects separators, traversal and other characters', () => {
    for (const n of ['', '.', '..', '../x', 'a/b', 'a\\b', '.hidden', '-x', '_x', 'a b', 'a%2Fb', 'naïve', 'a'.repeat(129), 'a\n']) {
      expect(isValidSecretName(n), JSON.stringify(n)).toBe(false);
    }
  });
});

function countingStore(values: Record<string, string>) {
  const store: SecretStore = {
    get: vi.fn(async (n: string) => (n in values ? { value: values[n] } : null)),
    exists: vi.fn(async (n: string) => n in values),
    list: vi.fn(async () => Object.keys(values)),
    put: vi.fn(async (n: string, v: string) => { values[n] = v; }),
  };
  return store;
}

describe('withCache', () => {
  it('caches found secrets for the TTL', async () => {
    vi.useFakeTimers();
    try {
      const inner = countingStore({ a: '1' });
      const cached = withCache(inner, 1000);
      expect(await cached.get('a')).toEqual({ value: '1' });
      expect(await cached.get('a')).toEqual({ value: '1' });
      expect(inner.get).toHaveBeenCalledTimes(1);
      vi.advanceTimersByTime(1001);
      await cached.get('a');
      expect(inner.get).toHaveBeenCalledTimes(2);
    } finally {
      vi.useRealTimers();
    }
  });

  it('does not cache misses', async () => {
    const inner = countingStore({});
    const cached = withCache(inner, 60_000);
    expect(await cached.get('missing')).toBeNull();
    expect(await cached.get('missing')).toBeNull();
    expect(inner.get).toHaveBeenCalledTimes(2);
  });

  it('writes through on put and invalidates the entry', async () => {
    const inner = countingStore({ a: '1' });
    const cached = withCache(inner, 60_000);
    await cached.get('a');
    await cached.put!('a', '2');
    expect(inner.put).toHaveBeenCalledWith('a', '2');
    expect(await cached.get('a')).toEqual({ value: '2' });
  });

  it('passes exists and list through uncached', async () => {
    const inner = countingStore({ a: '1' });
    const cached = withCache(inner, 60_000);
    await cached.exists('a');
    await cached.exists('a');
    expect(inner.exists).toHaveBeenCalledTimes(2);
    expect(await cached.list()).toEqual(['a']);
  });

  it('keeps a read-only store read-only', () => {
    const readOnly: SecretStore = countingStore({});
    delete readOnly.put;
    expect(withCache(readOnly, 1000).put).toBeUndefined();
  });
});

describe('createMemoryProvider', () => {
  it('serves secrets and shared secrets', async () => {
    const p = createMemoryProvider({ secrets: { b: '2', a: '1' }, shared: { s: 'x' } });
    expect(await p.secrets.get('a')).toEqual({ value: '1' });
    expect(await p.secrets.get('zzz')).toBeNull();
    expect(await p.secrets.list()).toEqual(['a', 'b']);
    expect(await p.shared!.get('s')).toEqual({ value: 'x' });
  });

  it('can be read-only and without shared secrets', () => {
    const p = createMemoryProvider({ writable: false });
    expect(p.secrets.put).toBeUndefined();
    expect(p.shared).toBeUndefined();
  });
});
