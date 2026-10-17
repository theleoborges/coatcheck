import { describe, it, expect } from 'vitest';
import { parseHostPattern, type HostPattern } from './host-matcher.js';
import { allowedHostsJson, parseSecretValue, resolveBinding, userFields } from './secret-binding.js';

const hosts = (...entries: string[]) => entries.map(e => parseHostPattern(e) as HostPattern);

describe('parseSecretValue', () => {
  it('treats plain strings, arrays and scalars as simple secrets', () => {
    expect(parseSecretValue('ghp_x')).toEqual({ kind: 'simple', value: 'ghp_x', inBand: {} });
    expect(parseSecretValue('["a"]')).toEqual({ kind: 'simple', value: '["a"]', inBand: {} });
    expect(parseSecretValue('42')).toEqual({ kind: 'simple', value: '42', inBand: {} });
  });

  it('treats an object whose only non-underscore key is value as a simple secret with metadata', () => {
    const v = parseSecretValue(JSON.stringify({ value: 'ghp_x', _allowed_hosts: ['api.github.com'] }));
    expect(v).toEqual({ kind: 'simple', value: 'ghp_x', inBand: { hosts: hosts('api.github.com') } });
  });

  it('treats other objects as multi-value secrets and parses _allowed_hosts', () => {
    const v = parseSecretValue(JSON.stringify({ value: 'a', other: 'b', _allowed_hosts: ['*.example.com'] }));
    expect(v).toMatchObject({ kind: 'multi', inBand: { hosts: hosts('*.example.com') } });
  });

  it('reports an invalid _allowed_hosts instead of ignoring it', () => {
    for (const bad of ['api.github.com', [], ['*'], [42], ['api.github.com', 'https://x.com']]) {
      const v = parseSecretValue(JSON.stringify({ value: 'x', _allowed_hosts: bad }));
      expect('error' in v.inBand, JSON.stringify(bad)).toBe(true);
    }
  });
});

describe('parseSecretValue: _swap_body', () => {
  it('parses a boolean _swap_body and refuses anything else', () => {
    expect(parseSecretValue(JSON.stringify({ value: 'x', _swap_body: true }))).toEqual({ kind: 'simple', value: 'x', inBand: { swapBody: true } });
    for (const bad of ['true', 1, null, []]) {
      const v = parseSecretValue(JSON.stringify({ value: 'x', _swap_body: bad }));
      expect('error' in v.inBand, JSON.stringify(bad)).toBe(true);
    }
  });
});

describe('userFields', () => {
  it('hides every underscore-prefixed key', () => {
    expect(userFields({ a: 1, _cleartext: [], _allowed_hosts: [], _future: 1, b: 2 })).toEqual(['a', 'b']);
  });
});

describe('resolveBinding', () => {
  it('refuses an unbound secret unless unbound secrets are allowed', () => {
    expect(resolveBinding('k', undefined, {}, false)).toMatchObject({ ok: false, status: 403, error: expect.stringContaining("'k' is not bound") });
    expect(resolveBinding('k', undefined, {}, true)).toEqual({ ok: true, allowedHosts: undefined, swapBody: false });
  });

  it('uses whichever source is present', () => {
    expect(resolveBinding('k', hosts('a.example.com'), {}, false)).toEqual({ ok: true, allowedHosts: hosts('a.example.com'), swapBody: false });
    expect(resolveBinding('k', undefined, { hosts: hosts('b.example.com') }, false)).toEqual({ ok: true, allowedHosts: hosts('b.example.com'), swapBody: false });
  });

  it('intersects the policy and in-band hosts: the secret can only narrow the operator', () => {
    const b = resolveBinding('k', hosts('*.example.com'), { hosts: hosts('api.example.com', 'attacker.example') }, false);
    expect(b).toEqual({ ok: true, allowedHosts: hosts('api.example.com'), swapBody: false });
  });

  it('refuses an empty intersection with 403 and an invalid in-band list with 500', () => {
    expect(resolveBinding('k', hosts('a.example.com'), { hosts: hosts('b.example.com') }, true)).toMatchObject({ ok: false, status: 403 });
    expect(resolveBinding('k', hosts('a.example.com'), { error: 'bad' }, true)).toMatchObject({ ok: false, status: 500 });
  });

  it('enables body swapping when either source opts in and neither opts out', () => {
    const swap = (policy: boolean | undefined, inBand: boolean | undefined) => {
      const b = resolveBinding('k', hosts('a.example.com'), inBand === undefined ? {} : { swapBody: inBand }, false, policy);
      return b.ok && b.swapBody;
    };
    expect(swap(undefined, undefined)).toBe(false);
    expect(swap(true, undefined)).toBe(true);
    expect(swap(undefined, true)).toBe(true);
    expect(swap(true, true)).toBe(true);
    expect(swap(true, false)).toBe(false);
    expect(swap(false, true)).toBe(false);
  });
});

describe('allowedHostsJson', () => {
  it('formats entries, or null when unbound', () => {
    expect(allowedHostsJson(hosts('api.github.com', 'http://*.svc.example.com'))).toEqual(['api.github.com', 'http://*.svc.example.com']);
    expect(allowedHostsJson(undefined)).toBeNull();
  });
});
