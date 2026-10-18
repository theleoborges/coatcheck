import { describe, it, expect, afterEach } from 'vitest';
import { TokenStore } from './token-store.js';
import { swapBasicCredentials, swapBasicFieldLine } from './basic-auth.js';
import { parseHostPattern, type HostPattern } from './host-matcher.js';

const GITHUB = { host: 'api.github.com', scheme: 'https' as const };
const EVIL = { host: 'attacker.example', scheme: 'https' as const };
const allowedHosts = [parseHostPattern('api.github.com') as HostPattern];

const b64 = (s: string) => Buffer.from(s, 'utf8').toString('base64');
const unb64 = (s: string) => Buffer.from(s, 'base64').toString('utf8');

describe('swapBasicCredentials', () => {
  let store: TokenStore;
  afterEach(() => store?.destroy());

  it('swaps a ticket in the password, the user-id, or both, and re-encodes', () => {
    store = new TokenStore();
    const pass = store.issue('pat', 'ghp_REAL', { allowedHosts }).id;
    const user = store.issue('sid', 'AC123', { allowedHosts }).id;

    const r = swapBasicCredentials(store, `Basic ${b64(`x-access-token:${pass}`)}`, GITHUB);
    expect(r?.output).toBe(`Basic ${b64('x-access-token:ghp_REAL')}`);
    expect(r?.swaps.map(s => s.secretName)).toEqual(['pat']);

    const both = swapBasicCredentials(store, `basic  ${b64(`${user}:${pass}`)} `, GITHUB);
    expect(both?.output).toBe(`basic  ${b64('AC123:ghp_REAL')} `);
    expect(both?.swaps.map(s => s.secretName)).toEqual(['sid', 'pat']);
  });

  it('keeps a real password containing ":" and non-ASCII intact', () => {
    store = new TokenStore();
    const tok = store.issue('pw', 'p:ä:ss', { allowedHosts }).id;
    const r = swapBasicCredentials(store, `Basic ${b64(`me@example.com:${tok}`)}`, GITHUB);
    expect(unb64(r!.output.slice(6))).toBe('me@example.com:p:ä:ss');
  });

  it('denies the whole credential when a ticket is bound to another host (exfiltration)', () => {
    store = new TokenStore();
    const tok = store.issue('pat', 'ghp_REAL', { allowedHosts }).id;
    const value = `Basic ${b64(`u:${tok}`)}`;
    const r = swapBasicCredentials(store, value, EVIL);
    expect(r?.denied.map(d => d.secretName)).toEqual(['pat']);
    expect(r?.swaps).toEqual([]);
    expect(r?.output).toBe(value);
    expect(unb64(r!.output.slice(6))).not.toContain('ghp_REAL');
  });

  it('refuses a value with ":" in the user-id slot, which would move the user/password split', () => {
    store = new TokenStore();
    const tok = store.issue('user', 'admin:extra', { allowedHosts }).id;
    const value = `Basic ${b64(`${tok}:pw`)}`;
    const r = swapBasicCredentials(store, value, GITHUB);
    expect(r?.invalid?.map(i => i.secretName)).toEqual(['user']);
    expect(r?.output).toBe(value);
  });

  it('refuses a value with a control character', () => {
    store = new TokenStore();
    const tok = store.issue('pw', 'a\r\nb', { allowedHosts }).id;
    expect(swapBasicCredentials(store, `Basic ${b64(`u:${tok}`)}`, GITHUB)?.invalid).toHaveLength(1);
  });

  it('leaves non-Basic, ticket-free and non-canonical credentials alone', () => {
    store = new TokenStore();
    const tok = store.issue('pw', 'real', { allowedHosts }).id;
    const canonical = b64(`u:${tok}`);
    expect(swapBasicCredentials(store, `Bearer ${canonical}`, GITHUB)).toBeNull();
    expect(swapBasicCredentials(store, `Basic ${b64('u:plain')}`, GITHUB)).toBeNull();
    // Node would decode these the same, but the upstream may not: never open them.
    expect(swapBasicCredentials(store, `Basic ${canonical.replace(/=+$/, '')}`, GITHUB)).toBeNull();
    expect(swapBasicCredentials(store, `Basic ${canonical.slice(0, 8)}!${canonical.slice(8)}`, GITHUB)).toBeNull();
    expect(swapBasicCredentials(store, `Basic ${canonical} extra`, GITHUB)).toBeNull();
  });
});

describe('swapBasicFieldLine', () => {
  let store: TokenStore;
  afterEach(() => store?.destroy());

  it('only opens Authorization, never Proxy-Authorization or other fields', () => {
    store = new TokenStore();
    const tok = store.issue('pw', 'real', { allowedHosts }).id;
    const cred = `Basic ${b64(`u:${tok}`)}`;
    expect(swapBasicFieldLine(store, `AUTHORIZATION:${cred}`, GITHUB)?.output).toBe(`AUTHORIZATION:Basic ${b64('u:real')}`);
    expect(swapBasicFieldLine(store, `Proxy-Authorization: ${cred}`, GITHUB)).toBeNull();
    expect(swapBasicFieldLine(store, `X-Authorization: ${cred}`, GITHUB)).toBeNull();
  });
});
