import { describe, it, expect } from 'vitest';
import { parseConnectTarget } from './connect-target.js';

describe('parseConnectTarget', () => {
  it('accepts DNS names with a port', () => {
    expect(parseConnectTarget('api.github.com:443')).toEqual({ hostname: 'api.github.com', port: 443 });
    expect(parseConnectTarget('localhost:8080')).toEqual({ hostname: 'localhost', port: 8080 });
    expect(parseConnectTarget('xn--bcher-kva.example:443')).toEqual({ hostname: 'xn--bcher-kva.example', port: 443 });
  });

  it('lowercases and strips a trailing dot', () => {
    expect(parseConnectTarget('API.Example.COM.:443')).toEqual({ hostname: 'api.example.com', port: 443 });
  });

  it('accepts IP literals', () => {
    expect(parseConnectTarget('127.0.0.1:3128')).toEqual({ hostname: '127.0.0.1', port: 3128 });
    expect(parseConnectTarget('[::1]:443')).toEqual({ hostname: '::1', port: 443 });
    expect(parseConnectTarget('[2001:DB8::1]:443')).toEqual({ hostname: '2001:db8::1', port: 443 });
  });

  it('rejects a missing or out-of-range port', () => {
    for (const t of ['example.com', 'example.com:', 'example.com:0', 'example.com:65536', 'example.com:44a', 'example.com:+443', 'example.com:123456']) {
      expect(parseConnectTarget(t), t).toBeNull();
    }
  });

  it('rejects shell metacharacters (command injection attempts)', () => {
    const attacks = [
      '$(touch /tmp/pwned).com:443',
      '`id`.example.com:443',
      'example.com;id:443',
      'a.com|id:443',
      'a.com&id:443',
      'a.com" -out /tmp/x ":443',
      "a.com'x:443",
      'a.com\nid:443',
      'a b.com:443',
      'a.com>x:443',
    ];
    for (const t of attacks) expect(parseConnectTarget(t), JSON.stringify(t)).toBeNull();
  });

  it('rejects path traversal and separators', () => {
    for (const t of ['../../etc/passwd:443', '..:443', 'a/b.com:443', 'a\\b.com:443', '.:443']) {
      expect(parseConnectTarget(t), t).toBeNull();
    }
  });

  it('rejects empty and over-long labels', () => {
    expect(parseConnectTarget(':443')).toBeNull();
    expect(parseConnectTarget('a..b.com:443')).toBeNull();
    expect(parseConnectTarget('.example.com:443')).toBeNull();
    expect(parseConnectTarget(`${'a'.repeat(64)}.com:443`)).toBeNull();
    expect(parseConnectTarget(`${'a'.repeat(63)}.com:443`)).not.toBeNull();
    const long = Array.from({ length: 64 }, () => 'abc').join('.'); // 255 chars
    expect(parseConnectTarget(`${long}:443`)).toBeNull();
  });

  it('rejects labels with leading/trailing hyphens and underscores', () => {
    for (const t of ['-a.com:443', 'a-.com:443', '_dmarc.example.com:443']) {
      expect(parseConnectTarget(t), t).toBeNull();
    }
  });

  it('rejects malformed IP literals', () => {
    for (const t of ['999.1.1.1:443', '[::1:443', '[::1]443', '[not-ip]:443', '::1:443', '[127.0.0.1]:443']) {
      expect(parseConnectTarget(t), t).toBeNull();
    }
  });

  it('rejects undefined and empty input', () => {
    expect(parseConnectTarget(undefined)).toBeNull();
    expect(parseConnectTarget('')).toBeNull();
  });
});
