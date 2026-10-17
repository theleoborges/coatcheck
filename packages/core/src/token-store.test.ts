import { describe, it, expect, afterEach } from 'vitest';
import { TokenStore, TICKET_PREFIX, TICKET_PATTERN } from './token-store.js';
import { parseHostPattern, type HostPattern } from './host-matcher.js';

/** Most tests use unbound tickets, which swap for any target. */
const ANY_HOST = { host: 'api.example.com', scheme: 'https' as const };

function hosts(...entries: string[]): HostPattern[] {
  return entries.map(e => parseHostPattern(e) as HostPattern);
}

describe('TokenStore', () => {
  let store: TokenStore;

  afterEach(() => {
    store?.destroy();
  });

  it('issues tokens with cct_ prefix', () => {
    store = new TokenStore();
    const token = store.issue('my-secret', 'real-value-123');
    expect(token.id).toMatch(/^cct_[a-f0-9]{64}$/);
    expect(token.ttlSeconds).toBe(900);
  });

  it('exports one prefix and pattern that match issued tickets', () => {
    store = new TokenStore();
    const { id } = store.issue('my-secret', 'v');
    const sessionId = store.issue('login:password', 'p', { sessionId: 'sid1' }).id;
    expect(TICKET_PREFIX).toBe('cct_');
    for (const t of [id, sessionId]) {
      TICKET_PATTERN.lastIndex = 0;
      expect(t.startsWith(TICKET_PREFIX)).toBe(true);
      expect(`x ${t} y`.match(TICKET_PATTERN)).toEqual([t]);
    }
  });

  it('does not treat the old tok_ prefix as a ticket', () => {
    store = new TokenStore();
    const { id } = store.issue('my-secret', 'real-value');
    const legacy = 'tok_' + id.slice(TICKET_PREFIX.length);
    expect(store.replaceAll(`Bearer ${legacy}`, ANY_HOST).swaps).toEqual([]);
    TICKET_PATTERN.lastIndex = 0;
    expect(legacy.match(TICKET_PATTERN)).toBeNull();
  });

  it('uses the configured default TTL', () => {
    store = new TokenStore({ defaultTtlSeconds: 60 });
    expect(store.issue('k', 'v').ttlSeconds).toBe(60);
    expect(store.issue('k', 'v', { ttlSeconds: 5 }).ttlSeconds).toBe(5);
  });

  it('resolves a valid token to its real value', () => {
    store = new TokenStore();
    const token = store.issue('my-secret', 'real-value-123');
    expect(store.resolve(token.id)).toBe('real-value-123');
  });

  it('returns null for unknown tokens', () => {
    store = new TokenStore();
    expect(store.resolve('cct_unknown')).toBeNull();
  });

  it('replaces tokens in strings', () => {
    store = new TokenStore();
    const t1 = store.issue('api-key', 'sk-real-key');
    const t2 = store.issue('token', 'usr-real-token');

    const input = `https://api.trello.com/1/boards?key=${t1.id}&token=${t2.id}`;
    const result = store.replaceAll(input, ANY_HOST);
    expect(result.output).toBe('https://api.trello.com/1/boards?key=sk-real-key&token=usr-real-token');
    expect(result.swaps.map(s => s.secretName).sort()).toEqual(['api-key', 'token']);
  });

  it('replaces tokens in headers', () => {
    store = new TokenStore();
    const token = store.issue('notion-key', 'secret_abc123');

    const header = `Authorization: Bearer ${token.id}`;
    const result = store.replaceAll(header, ANY_HOST);
    expect(result.output).toBe('Authorization: Bearer secret_abc123');
    expect(result.swaps).toEqual([{ secretName: 'notion-key', ageMs: expect.any(Number), unbound: true }]);
  });

  it('returns input unchanged when no tokens match', () => {
    store = new TokenStore();
    store.issue('key', 'value');

    const input = 'no tokens here';
    const result = store.replaceAll(input, ANY_HOST);
    expect(result.output).toBe(input);
    expect(result.swaps).toEqual([]);
  });

  it('returns input unchanged when store is empty', () => {
    store = new TokenStore();
    const input = 'Authorization: Bearer cct_fake';
    const result = store.replaceAll(input, ANY_HOST);
    expect(result.output).toBe(input);
    expect(result.swaps).toEqual([]);
  });

  it('does not resolve expired tokens', async () => {
    store = new TokenStore();
    const token = store.issue('key', 'value', { ttlSeconds: 0 }); // 0 second TTL = immediately expired

    // Small delay to ensure expiry
    await new Promise(r => setTimeout(r, 10));

    expect(store.resolve(token.id)).toBeNull();
  });

  it('does not replace expired tokens in strings', async () => {
    store = new TokenStore();
    const token = store.issue('key', 'real-value', { ttlSeconds: 0 });

    await new Promise(r => setTimeout(r, 10));

    const input = `key=${token.id}`;
    const result = store.replaceAll(input, ANY_HOST);
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
    const result = store.replaceAll(input, ANY_HOST);
    expect(result.output).toBe('real and real');
    expect(result.swaps).toEqual([{ secretName: 'key', ageMs: expect.any(Number), unbound: true }]);
  });

  it('uses custom TTL', () => {
    store = new TokenStore();
    const token = store.issue('key', 'val', { ttlSeconds: 60 });
    expect(token.ttlSeconds).toBe(60);
    expect(store.resolve(token.id)).toBe('val');
  });

  // --- Host binding ---

  describe('host-bound tickets', () => {
    it('swaps a bound ticket only for its allowed hosts', () => {
      store = new TokenStore();
      const t = store.issue('github', 'ghp_real', { allowedHosts: hosts('api.github.com') });
      const ok = store.replaceAll(`Bearer ${t.id}`, { host: 'api.github.com', scheme: 'https' });
      expect(ok.output).toBe('Bearer ghp_real');
      expect(ok.swaps).toEqual([{ secretName: 'github', ageMs: expect.any(Number) }]);
      expect(ok.denied).toEqual([]);
    });

    it('denies (and swaps nothing) when the target is not an allowed host', () => {
      store = new TokenStore();
      const t = store.issue('github', 'ghp_real', { allowedHosts: hosts('api.github.com') });
      for (const target of [
        { host: 'attacker.example', scheme: 'https' as const },
        { host: 'api.github.com.attacker.example', scheme: 'https' as const },
        { host: 'api.github.com', scheme: 'http' as const }, // plaintext needs an http:// entry
        { host: '127.0.0.1', scheme: 'http' as const },
      ]) {
        const r = store.replaceAll(`Bearer ${t.id}`, target);
        expect(r.output, target.host).toBe(`Bearer ${t.id}`);
        expect(r.output).not.toContain('ghp_real');
        expect(r.swaps).toEqual([]);
        expect(r.denied.map(d => d.secretName)).toEqual(['github']);
      }
    });

    it('denies the whole request when any one ticket is bound elsewhere', () => {
      store = new TokenStore();
      const good = store.issue('a', 'real-a', { allowedHosts: hosts('api.example.com') });
      const bad = store.issue('b', 'real-b', { allowedHosts: hosts('other.example.com') });
      const r = store.replaceAll(`${good.id} ${bad.id}`, ANY_HOST);
      expect(r.output).toBe(`${good.id} ${bad.id}`);
      expect(r.swaps).toEqual([]);
      expect(r.denied.map(d => d.secretName)).toEqual(['b']);
    });

    it('ignores bound tickets that are not in the input', () => {
      store = new TokenStore();
      store.issue('elsewhere', 'x', { allowedHosts: hosts('other.example.com') });
      const t = store.issue('k', 'real', { allowedHosts: hosts('api.example.com') });
      expect(store.replaceAll(t.id, ANY_HOST)).toMatchObject({ output: 'real', denied: [] });
    });
  });

  // --- Session-scoped tokens (CDP credential injection) ---

  describe('session-scoped tokens', () => {
    it('replaceAllForSession substitutes only its own session tokens', () => {
      store = new TokenStore();
      const a = store.issue('site:password', 'pw-a', { sessionId: 'sess-1' });
      const b = store.issue('site:password', 'pw-b', { sessionId: 'sess-2' });

      const input = `${a.id} ${b.id}`;
      const r1 = store.replaceAllForSession(input, 'sess-1');
      expect(r1.output).toBe(`pw-a ${b.id}`);
      expect(r1.swaps.map(s => s.secretName)).toEqual(['site:password']);
    });

    it('replaceAll (HTTP path) never substitutes session-scoped tokens', () => {
      store = new TokenStore();
      const scoped = store.issue('site:password', 'pw', { sessionId: 'sess-1' });
      const unscoped = store.issue('api-key', 'real-key');

      const input = `${scoped.id} and ${unscoped.id}`;
      const r = store.replaceAll(input, ANY_HOST);
      // scoped token passes through untouched; only the unscoped one swaps
      expect(r.output).toBe(`${scoped.id} and real-key`);
      expect(r.swaps.map(s => s.secretName)).toEqual(['api-key']);
    });

    it('sessionValues returns active real values for the session only', () => {
      store = new TokenStore();
      store.issue('site:username', 'alice', { sessionId: 'sess-1' });
      store.issue('site:password', 'hunter2', { sessionId: 'sess-1' });
      store.issue('other:password', 'nope', { sessionId: 'sess-2' });

      const values = store.sessionValues('sess-1').map(v => v.value).sort();
      expect(values).toEqual(['alice', 'hunter2']);
    });

    it('sessionTokenIds returns active token ids for the session only', () => {
      store = new TokenStore();
      const a = store.issue('site:username', 'alice', { sessionId: 'sess-1' });
      store.issue('other:password', 'nope', { sessionId: 'sess-2' });

      expect(store.sessionTokenIds('sess-1')).toEqual([a.id]);
    });

    it('revokeSession evicts all of a session\'s tokens', () => {
      store = new TokenStore();
      const a = store.issue('site:username', 'alice', { sessionId: 'sess-1' });
      const b = store.issue('site:password', 'hunter2', { sessionId: 'sess-1' });
      const other = store.issue('other:password', 'keep', { sessionId: 'sess-2' });

      const revoked = store.revokeSession('sess-1');
      expect(revoked).toBe(2);
      expect(store.resolve(a.id)).toBeNull();
      expect(store.resolve(b.id)).toBeNull();
      expect(store.resolve(other.id)).toBe('keep');
    });

    it('does not substitute expired session tokens', async () => {
      store = new TokenStore();
      const t = store.issue('site:password', 'pw', { sessionId: 'sess-1', ttlSeconds: 0 });
      await new Promise(r => setTimeout(r, 10));
      const r = store.replaceAllForSession(`x ${t.id}`, 'sess-1');
      expect(r.output).toBe(`x ${t.id}`);
      expect(store.sessionValues('sess-1')).toEqual([]);
    });
  });
});
