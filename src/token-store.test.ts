import { describe, it, expect, afterEach } from 'vitest';
import { TokenStore } from './token-store.js';

describe('TokenStore', () => {
  let store: TokenStore;

  afterEach(() => {
    store?.destroy();
  });

  it('issues tokens with tok_ prefix', () => {
    store = new TokenStore();
    const token = store.issue('my-secret', 'real-value-123');
    expect(token.id).toMatch(/^tok_[a-f0-9]{64}$/);
    expect(token.ttlSeconds).toBe(900);
  });

  it('resolves a valid token to its real value', () => {
    store = new TokenStore();
    const token = store.issue('my-secret', 'real-value-123');
    expect(store.resolve(token.id)).toBe('real-value-123');
  });

  it('returns null for unknown tokens', () => {
    store = new TokenStore();
    expect(store.resolve('tok_unknown')).toBeNull();
  });

  it('replaces tokens in strings', () => {
    store = new TokenStore();
    const t1 = store.issue('api-key', 'sk-real-key');
    const t2 = store.issue('token', 'usr-real-token');

    const input = `https://api.trello.com/1/boards?key=${t1.id}&token=${t2.id}`;
    const result = store.replaceAll(input);
    expect(result.output).toBe('https://api.trello.com/1/boards?key=sk-real-key&token=usr-real-token');
    expect(result.swaps.map(s => s.secretName).sort()).toEqual(['api-key', 'token']);
  });

  it('replaces tokens in headers', () => {
    store = new TokenStore();
    const token = store.issue('notion-key', 'secret_abc123');

    const header = `Authorization: Bearer ${token.id}`;
    const result = store.replaceAll(header);
    expect(result.output).toBe('Authorization: Bearer secret_abc123');
    expect(result.swaps).toEqual([{ secretName: 'notion-key', ageMs: expect.any(Number) }]);
  });

  it('returns input unchanged when no tokens match', () => {
    store = new TokenStore();
    store.issue('key', 'value');

    const input = 'no tokens here';
    const result = store.replaceAll(input);
    expect(result.output).toBe(input);
    expect(result.swaps).toEqual([]);
  });

  it('returns input unchanged when store is empty', () => {
    store = new TokenStore();
    const input = 'Authorization: Bearer tok_fake';
    const result = store.replaceAll(input);
    expect(result.output).toBe(input);
    expect(result.swaps).toEqual([]);
  });

  it('does not resolve expired tokens', async () => {
    store = new TokenStore();
    const token = store.issue('key', 'value', 0); // 0 second TTL = immediately expired

    // Small delay to ensure expiry
    await new Promise(r => setTimeout(r, 10));

    expect(store.resolve(token.id)).toBeNull();
  });

  it('does not replace expired tokens in strings', async () => {
    store = new TokenStore();
    const token = store.issue('key', 'real-value', 0);

    await new Promise(r => setTimeout(r, 10));

    const input = `key=${token.id}`;
    const result = store.replaceAll(input);
    expect(result.output).toBe(input);
    expect(result.swaps).toEqual([]);
  });

  it('tracks active token count', () => {
    store = new TokenStore();
    expect(store.size).toBe(0);

    store.issue('a', 'val-a');
    store.issue('b', 'val-b');
    expect(store.size).toBe(2);
  });

  it('handles multiple replacements of the same token', () => {
    store = new TokenStore();
    const token = store.issue('key', 'real');

    const input = `${token.id} and ${token.id}`;
    const result = store.replaceAll(input);
    expect(result.output).toBe('real and real');
    expect(result.swaps).toEqual([{ secretName: 'key', ageMs: expect.any(Number) }]);
  });

  it('uses custom TTL', () => {
    store = new TokenStore();
    const token = store.issue('key', 'val', 60);
    expect(token.ttlSeconds).toBe(60);
    expect(store.resolve(token.id)).toBe('val');
  });

  // --- Session-scoped tokens (CDP credential injection) ---

  describe('session-scoped tokens', () => {
    it('replaceAllForSession substitutes only its own session tokens', () => {
      store = new TokenStore();
      const a = store.issueForSession('site:password', 'pw-a', 'sess-1');
      const b = store.issueForSession('site:password', 'pw-b', 'sess-2');

      const input = `${a.id} ${b.id}`;
      const r1 = store.replaceAllForSession(input, 'sess-1');
      expect(r1.output).toBe(`pw-a ${b.id}`);
      expect(r1.swaps.map(s => s.secretName)).toEqual(['site:password']);
    });

    it('replaceAll (HTTP path) never substitutes session-scoped tokens', () => {
      store = new TokenStore();
      const scoped = store.issueForSession('site:password', 'pw', 'sess-1');
      const unscoped = store.issue('api-key', 'real-key');

      const input = `${scoped.id} and ${unscoped.id}`;
      const r = store.replaceAll(input);
      // scoped token passes through untouched; only the unscoped one swaps
      expect(r.output).toBe(`${scoped.id} and real-key`);
      expect(r.swaps.map(s => s.secretName)).toEqual(['api-key']);
    });

    it('sessionValues returns active real values for the session only', () => {
      store = new TokenStore();
      store.issueForSession('site:username', 'alice', 'sess-1');
      store.issueForSession('site:password', 'hunter2', 'sess-1');
      store.issueForSession('other:password', 'nope', 'sess-2');

      const values = store.sessionValues('sess-1').map(v => v.value).sort();
      expect(values).toEqual(['alice', 'hunter2']);
    });

    it('sessionTokenIds returns active token ids for the session only', () => {
      store = new TokenStore();
      const a = store.issueForSession('site:username', 'alice', 'sess-1');
      store.issueForSession('other:password', 'nope', 'sess-2');

      expect(store.sessionTokenIds('sess-1')).toEqual([a.id]);
    });

    it('revokeSession evicts all of a session\'s tokens', () => {
      store = new TokenStore();
      const a = store.issueForSession('site:username', 'alice', 'sess-1');
      const b = store.issueForSession('site:password', 'hunter2', 'sess-1');
      const other = store.issueForSession('other:password', 'keep', 'sess-2');

      const revoked = store.revokeSession('sess-1');
      expect(revoked).toBe(2);
      expect(store.resolve(a.id)).toBeNull();
      expect(store.resolve(b.id)).toBeNull();
      expect(store.resolve(other.id)).toBe('keep');
    });

    it('does not substitute expired session tokens', async () => {
      store = new TokenStore();
      const t = store.issueForSession('site:password', 'pw', 'sess-1', 0);
      await new Promise(r => setTimeout(r, 10));
      const r = store.replaceAllForSession(`x ${t.id}`, 'sess-1');
      expect(r.output).toBe(`x ${t.id}`);
      expect(store.sessionValues('sess-1')).toEqual([]);
    });
  });
});
