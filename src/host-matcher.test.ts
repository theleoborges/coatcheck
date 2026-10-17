import { describe, it, expect } from 'vitest';
import { matchesHost, parseHostPattern, type HostPattern } from './host-matcher.js';

function patterns(...entries: string[]): HostPattern[] {
  return entries.map(e => {
    const p = parseHostPattern(e);
    if (typeof p === 'string') throw new Error(`${e}: ${p}`);
    return p;
  });
}
const https = (host: string) => ({ host, scheme: 'https' as const });
const http = (host: string) => ({ host, scheme: 'http' as const });

describe('parseHostPattern', () => {
  it('parses exact, wildcard, plaintext and IP entries', () => {
    expect(parseHostPattern('api.github.com')).toEqual({ kind: 'exact', host: 'api.github.com', plaintext: false });
    expect(parseHostPattern('*.googleapis.com')).toEqual({ kind: 'wildcard', host: 'googleapis.com', plaintext: false });
    expect(parseHostPattern('http://internal.example.com')).toEqual({ kind: 'exact', host: 'internal.example.com', plaintext: true });
    expect(parseHostPattern('HTTP://*.svc.example.com')).toEqual({ kind: 'wildcard', host: 'svc.example.com', plaintext: true });
    expect(parseHostPattern('10.0.0.5')).toEqual({ kind: 'exact', host: '10.0.0.5', plaintext: false });
    expect(parseHostPattern('[2001:DB8::1]')).toEqual({ kind: 'exact', host: '2001:db8::1', plaintext: false });
  });

  it('normalises case, trailing dots and IDNs', () => {
    expect(parseHostPattern('API.Example.COM.')).toMatchObject({ host: 'api.example.com' });
    expect(parseHostPattern('bücher.example')).toMatchObject({ host: 'xn--bcher-kva.example' });
    expect(parseHostPattern('*.BÜCHER.example')).toMatchObject({ kind: 'wildcard', host: 'xn--bcher-kva.example' });
  });

  it('rejects bare and too-broad wildcards', () => {
    for (const e of ['*', '*.', '*.com', 'http://*', '*.*.example.com', 'a.*.example.com', '*example.com', 'api.*']) {
      expect(typeof parseHostPattern(e), e).toBe('string');
    }
  });

  it('rejects schemes other than http://, ports, paths and junk', () => {
    for (const e of ['https://api.github.com', 'ftp://x.com', 'api.github.com:443', 'api.github.com/path',
      '[::1]:443', ' api.github.com', '', 'a b.com', '$(id).com', '*.10.0.0.1', '-bad.com']) {
      expect(typeof parseHostPattern(e), JSON.stringify(e)).toBe('string');
    }
  });
});

describe('matchesHost', () => {
  it('matches exact hosts only', () => {
    const p = patterns('api.github.com');
    expect(matchesHost(p, https('api.github.com'))).toBe(true);
    expect(matchesHost(p, https('API.GitHub.com.'))).toBe(true);
    expect(matchesHost(p, https('github.com'))).toBe(false);
    expect(matchesHost(p, https('evil.api.github.com'))).toBe(false);
    expect(matchesHost(p, https('api.github.com.evil.example'))).toBe(false);
    expect(matchesHost(p, https('apiXgithub.com'))).toBe(false);
  });

  it('matches wildcard subdomains at any depth but not the apex or look-alikes', () => {
    const p = patterns('*.googleapis.com');
    expect(matchesHost(p, https('www.googleapis.com'))).toBe(true);
    expect(matchesHost(p, https('a.b.googleapis.com'))).toBe(true);
    expect(matchesHost(p, https('googleapis.com'))).toBe(false);
    expect(matchesHost(p, https('evilgoogleapis.com'))).toBe(false);
    expect(matchesHost(p, https('googleapis.com.evil.example'))).toBe(false);
  });

  it('allows plaintext only for http:// entries, which also allow HTTPS', () => {
    expect(matchesHost(patterns('api.example.com'), http('api.example.com'))).toBe(false);
    const p = patterns('http://internal.example.com');
    expect(matchesHost(p, http('internal.example.com'))).toBe(true);
    expect(matchesHost(p, https('internal.example.com'))).toBe(true);
  });

  it('never matches loopback or IPs unless listed exactly', () => {
    const p = patterns('api.example.com', '*.example.com');
    for (const h of ['127.0.0.1', 'localhost', '::1', '[::1]', '169.254.169.254']) {
      expect(matchesHost(p, https(h)), h).toBe(false);
      expect(matchesHost(p, http(h)), h).toBe(false);
    }
    expect(matchesHost(patterns('10.0.0.5'), https('10.0.0.5'))).toBe(true);
    expect(matchesHost(patterns('10.0.0.5'), https('10.0.0.50'))).toBe(false);
    expect(matchesHost(patterns('[::1]'), https('[::1]'))).toBe(true);
  });

  it('canonicalises IPv6 on both sides so equivalent spellings match', () => {
    expect(parseHostPattern('2001:0DB8:0:0::0001')).toMatchObject({ host: '2001:db8::1' });
    expect(matchesHost(patterns('2001:0db8::0001'), https('[2001:db8::1]'))).toBe(true);
    expect(matchesHost(patterns('2001:db8::1'), https('2001:0db8:0::1'))).toBe(true);
    expect(matchesHost(patterns('::ffff:1.2.3.4'), https('[::ffff:102:304]'))).toBe(true);
  });

  it('rejects IPv6 zone IDs and bracketed non-IPv6 entries', () => {
    for (const e of ['fe80::1%eth0', '[fe80::1%eth0]', '[api.example.com]', '[10.0.0.5]']) {
      expect(typeof parseHostPattern(e), e).toBe('string');
    }
    expect(matchesHost(patterns('fe80::1'), https('fe80::1%eth0'))).toBe(false);
  });

  it('matches IDN targets against punycode patterns', () => {
    expect(matchesHost(patterns('bücher.example'), https('xn--bcher-kva.example'))).toBe(true);
    expect(matchesHost(patterns('xn--bcher-kva.example'), https('bücher.example'))).toBe(true);
  });

  it('rejects invalid targets and empty pattern lists', () => {
    const p = patterns('api.example.com');
    for (const h of ['api.example.com/evil', 'api.example.com?x', 'api.example.com#x', 'user@api.example.com',
      'api.example.com:443', 'api.example.com\\x', 'api%2eexample.com', 'api.example.com x']) {
      expect(matchesHost(p, https(h)), h).toBe(false);
    }
    expect(matchesHost([], https('api.example.com'))).toBe(false);
  });
});
