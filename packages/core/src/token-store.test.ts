import { describe, it, expect, afterEach } from 'vitest';
import { TokenStore, TICKET_PREFIX, TICKET_PATTERN } from './token-store.js';
import { parseHostPattern, type HostPattern } from './host-matcher.js';

/** Most tests use unbound tickets, which swap for any target. */
const ANY_HOST = { host: 'api.example.com', scheme: 'https' as const };
const AUTH = { kind: 'header', name: 'authorization' } as const;

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
    const other = store.issue('login-password', 'p').id;
    expect(TICKET_PREFIX).toBe('cct_');
    for (const t of [id, other]) {
      TICKET_PATTERN.lastIndex = 0;
      expect(t.startsWith(TICKET_PREFIX)).toBe(true);
      expect(`x ${t} y`.match(TICKET_PATTERN)).toEqual([t]);
    }
  });

  it('does not treat the old tok_ prefix as a ticket', () => {
    store = new TokenStore();
    const { id } = store.issue('my-secret', 'real-value');
    const legacy = 'tok_' + id.slice(TICKET_PREFIX.length);
    expect(store.replaceAll(`Bearer ${legacy}`, ANY_HOST, AUTH).swaps).toEqual([]);
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
    const result = store.replaceAll(input, ANY_HOST, AUTH);
    expect(result.output).toBe('https://api.trello.com/1/boards?key=sk-real-key&token=usr-real-token');
    expect(result.swaps.map(s => s.secretName).sort()).toEqual(['api-key', 'token']);
  });

  it('substitutes in one pass: a value holding another ticket literal is not swapped again', () => {
    store = new TokenStore();
    const t2 = store.issue('token', 'usr-real-token');
    const t1 = store.issue('api-key', `prefix-${t2.id}`);
    const result = store.replaceAll(`a=${t1.id}&b=${t2.id}`, ANY_HOST, AUTH);
    expect(result.output).toBe(`a=prefix-${t2.id}&b=usr-real-token`);
  });

  it('replaces tokens in headers', () => {
    store = new TokenStore();
    const token = store.issue('notion-key', 'secret_abc123');

    const header = `Authorization: Bearer ${token.id}`;
    const result = store.replaceAll(header, ANY_HOST, AUTH);
    expect(result.output).toBe('Authorization: Bearer secret_abc123');
    expect(result.swaps).toEqual([{ secretName: 'notion-key', ageMs: expect.any(Number), unbound: true }]);
  });

  it('returns input unchanged when no tokens match', () => {
    store = new TokenStore();
    store.issue('key', 'value');

    const input = 'no tokens here';
    const result = store.replaceAll(input, ANY_HOST, AUTH);
    expect(result.output).toBe(input);
    expect(result.swaps).toEqual([]);
  });

  it('returns input unchanged when store is empty', () => {
    store = new TokenStore();
    const input = 'Authorization: Bearer cct_fake';
    const result = store.replaceAll(input, ANY_HOST, AUTH);
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
    const result = store.replaceAll(input, ANY_HOST, AUTH);
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
    const result = store.replaceAll(input, ANY_HOST, AUTH);
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
      const ok = store.replaceAll(`Bearer ${t.id}`, { host: 'api.github.com', scheme: 'https' }, AUTH);
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
        const r = store.replaceAll(`Bearer ${t.id}`, target, AUTH);
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
      const r = store.replaceAll(`${good.id} ${bad.id}`, ANY_HOST, AUTH);
      expect(r.output).toBe(`${good.id} ${bad.id}`);
      expect(r.swaps).toEqual([]);
      expect(r.denied.map(d => d.secretName)).toEqual(['b']);
    });

    it('ignores bound tickets that are not in the input', () => {
      store = new TokenStore();
      store.issue('elsewhere', 'x', { allowedHosts: hosts('other.example.com') });
      const t = store.issue('k', 'real', { allowedHosts: hosts('api.example.com') });
      expect(store.replaceAll(t.id, ANY_HOST, AUTH)).toMatchObject({ output: 'real', denied: [] });
    });
  });

  it('inserts values literally, never expanding $ replacement patterns', () => {
    store = new TokenStore();
    const t = store.issue('k', "a$&b$'c$`d$$e");
    expect(store.replaceAll(`x ${t.id} y`, ANY_HOST, AUTH).output).toBe("x a$&b$'c$`d$$e y");
  });

  it('finds tickets by pattern: only live ids present in the input are considered', () => {
    store = new TokenStore();
    for (let i = 0; i < 500; i++) store.issue(`n${i}`, `v${i}`);
    const t = store.issue('k', 'real');
    const r = store.replaceAll(`a ${t.id} b ${t.id} ${TICKET_PREFIX}${'0'.repeat(64)}`, ANY_HOST, AUTH);
    expect(r.output).toBe(`a real b real ${TICKET_PREFIX}${'0'.repeat(64)}`);
    expect(r.swaps.map(s => s.secretName)).toEqual(['k']);
  });

  it('reports values an encoder refuses as invalid and swaps nothing', () => {
    store = new TokenStore();
    const good = store.issue('good', 'ok');
    const bad = store.issue('bad', 'x\r\ny');
    const r = store.replaceAll(`${good.id} ${bad.id}`, ANY_HOST, AUTH, v => (v.includes('\r') ? null : v));
    expect(r.output).toBe(`${good.id} ${bad.id}`);
    expect(r.swaps).toEqual([]);
    expect(r.invalid?.map(s => s.secretName)).toEqual(['bad']);
  });

  it('knows when a body ticket could be swapped for a target', () => {
    store = new TokenStore();
    store.issue('plain', 'x', { allowedHosts: hosts('api.example.com') });
    expect(store.hasLiveBodyTicketFor(ANY_HOST)).toBe(false);
    store.issue('elsewhere', 'x', { allowedHosts: hosts('other.example.com'), swapBody: true });
    expect(store.hasLiveBodyTicketFor(ANY_HOST)).toBe(false);
    store.issue('body', 'x', { allowedHosts: hosts('api.example.com'), swapBody: true });
    expect(store.hasLiveBodyTicketFor(ANY_HOST)).toBe(true);
  });

  describe('swap placement', () => {
    const header = (name: string) => ({ kind: 'header', name }) as const;

    it('swaps by default only in Authorization and Proxy-Authorization values, in any case', () => {
      store = new TokenStore();
      const t = store.issue('k', 'real');
      for (const name of ['authorization', 'Authorization', 'PROXY-AUTHORIZATION']) {
        expect(store.replaceAll(`Bearer ${t.id}`, ANY_HOST, header(name)).output).toBe('Bearer real');
      }
      for (const [location, where] of [[{ kind: 'url' } as const, 'url'], [header('X-Api-Key'), 'header:x-api-key'], [header('cookie'), 'header:cookie']] as const) {
        const r = store.replaceAll(`/p?k=${t.id}`, ANY_HOST, location);
        expect(r).toMatchObject({ output: `/p?k=${t.id}`, swaps: [], denied: [], skipped: [{ secretName: 'k', where }] });
      }
    });

    it('swaps in the request line and named headers only for secrets that opt in', () => {
      store = new TokenStore();
      const url = store.issue('url', 'u', { swapUrl: true });
      const hdr = store.issue('hdr', 'h', { swapHeaders: ['X-Api-Key'] });
      const both = `${url.id} ${hdr.id}`;
      expect(store.replaceAll(both, ANY_HOST, { kind: 'url' })).toMatchObject({ output: `u ${hdr.id}`, skipped: [{ secretName: 'hdr' }] });
      expect(store.replaceAll(both, ANY_HOST, header('x-api-key'))).toMatchObject({ output: `${url.id} h`, skipped: [{ secretName: 'url' }] });
      expect(store.replaceAll(both, ANY_HOST, AUTH).output).toBe('u h');
    });

    it('still denies a ticket bound to another host wherever it sits', () => {
      store = new TokenStore();
      const t = store.issue('gh', 'ghp_real', { allowedHosts: hosts('api.github.com') });
      const r = store.replaceAll(`/collect?k=${t.id}`, ANY_HOST, { kind: 'url' });
      expect(r).toMatchObject({ output: `/collect?k=${t.id}`, swaps: [], denied: [{ secretName: 'gh' }] });
    });
  });

  describe('body swapping', () => {
    it('swaps only opted-in tickets, encoding the value, and reports the rest as skipped', () => {
      store = new TokenStore();
      const body = store.issue('body', 'v"1', { swapBody: true });
      const header = store.issue('header', 'v2');
      const r = store.replaceAllInBody(`${body.id} ${header.id}`, ANY_HOST, v => JSON.stringify(v).slice(1, -1));
      expect(r.output).toBe(`v\\"1 ${header.id}`);
      expect(r.swaps.map(s => s.secretName)).toEqual(['body']);
      expect(r.skipped?.map(s => s.secretName)).toEqual(['header']);
      // Headers are unaffected by the flag.
      expect(store.replaceAll(`${body.id} ${header.id}`, ANY_HOST, AUTH).output).toBe('v"1 v2');
    });

    it('applies host binding to opted-in tickets, but never denies on a skipped one', () => {
      store = new TokenStore();
      const bound = store.issue('gh', 'ghp_real', { allowedHosts: hosts('api.github.com'), swapBody: true });
      const r = store.replaceAllInBody(bound.id, ANY_HOST, v => v);
      expect(r).toMatchObject({ output: bound.id, swaps: [], denied: [{ secretName: 'gh' }] });

      const plain = store.issue('plain', 'x', { allowedHosts: hosts('api.github.com') });
      expect(store.replaceAllInBody(plain.id, ANY_HOST, v => v)).toMatchObject({ output: plain.id, denied: [], skipped: [{ secretName: 'plain' }] });
    });

  });

  // --- Session redaction values (CDP broker-performed login) ---
  //
  // Since broker login (roadmap item 20) coatcheck no longer mints session-bound
  // tickets. Instead a login window registers the credential's real values for
  // the session's inbound-redaction set; they never substitute anywhere and are
  // dropped at teardown.

  describe('session redaction values', () => {
    it('registerSessionValues / sessionValues return a session\'s registered values', () => {
      store = new TokenStore();
      store.registerSessionValues('sess-1', [{ value: 'alice', secretName: 'site:username' }, { value: 'hunter2', secretName: 'site:password' }]);
      store.registerSessionValues('sess-2', [{ value: 'nope', secretName: 'other:password' }]);
      expect(store.sessionValues('sess-1').map(v => v.value).sort()).toEqual(['alice', 'hunter2']);
      expect(store.sessionValues('sess-2').map(v => v.value)).toEqual(['nope']);
      expect(store.sessionValues('unknown')).toEqual([]);
    });

    it('registerSessionValues ignores empty values and appends on repeat', () => {
      store = new TokenStore();
      store.registerSessionValues('s', [{ value: '', secretName: 'x' }]);
      expect(store.sessionValues('s')).toEqual([]);
      store.registerSessionValues('s', [{ value: 'a', secretName: 'x' }]);
      store.registerSessionValues('s', [{ value: 'b', secretName: 'y' }]);
      expect(store.sessionValues('s').map(v => v.value)).toEqual(['a', 'b']);
    });

    it('registered values never substitute on the HTTP path', () => {
      store = new TokenStore();
      store.registerSessionValues('s', [{ value: 'hunter2', secretName: 'site:password' }]);
      const unscoped = store.issue('api-key', 'real-key');
      const r = store.replaceAll(`hunter2 ${unscoped.id}`, ANY_HOST, AUTH);
      // The registered value is not a ticket, so it isn't matched; only the real ticket swaps.
      expect(r.output).toBe('hunter2 real-key');
    });

    it('revokeSession drops a session\'s registered values and returns the count', () => {
      store = new TokenStore();
      store.registerSessionValues('sess-1', [{ value: 'alice', secretName: 'u' }, { value: 'hunter2', secretName: 'p' }]);
      store.registerSessionValues('sess-2', [{ value: 'keep', secretName: 'k' }]);
      expect(store.revokeSession('sess-1')).toBe(2);
      expect(store.sessionValues('sess-1')).toEqual([]);
      expect(store.sessionValues('sess-2').map(v => v.value)).toEqual(['keep']);
    });
  });
});
