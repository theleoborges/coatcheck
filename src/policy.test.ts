import { describe, it, expect } from 'vitest';
import { parsePolicy, policyHostsFor } from './policy.js';

function parse(obj: unknown) {
  const problems: string[] = [];
  const policy = parsePolicy(JSON.stringify(obj), problems, 'policy');
  return { policy, problems };
}

describe('parsePolicy', () => {
  it('parses secrets and shared sections', () => {
    const { policy, problems } = parse({
      secrets: {
        'github-token': { allowed_hosts: ['api.github.com'] },
        'google-*': { allowed_hosts: ['*.googleapis.com', 'oauth2.googleapis.com'] },
      },
      shared: { 'browserbase-api-key': { allowed_hosts: ['api.browserbase.com'] } },
    });
    expect(problems).toEqual([]);
    expect(policy.secrets.map(r => [r.name, r.wildcard])).toEqual([['github-token', false], ['google-', true]]);
    expect(policy.shared.get('browserbase-api-key')).toEqual([{ kind: 'exact', host: 'api.browserbase.com', plaintext: false }]);
  });

  it('accepts an empty object', () => {
    expect(parse({}).problems).toEqual([]);
  });

  it('rejects malformed JSON and non-objects', () => {
    const problems: string[] = [];
    parsePolicy('{', problems);
    parsePolicy('[]', problems);
    expect(problems).toHaveLength(2);
  });

  it('is strict about keys, so typos cannot leave a secret unbound', () => {
    const { problems } = parse({
      secret: {},
      secrets: { a: { allowed_host: ['x.example.com'] } },
    });
    expect(problems).toEqual(expect.arrayContaining([
      expect.stringContaining("unknown key 'secret'"),
      expect.stringContaining("unknown key 'allowed_host'"),
      expect.stringContaining('secrets["a"].allowed_hosts must be a non-empty array'),
    ]));
  });

  it('rejects empty host lists, bad patterns and non-strings, reporting each', () => {
    const { policy, problems } = parse({
      secrets: {
        a: { allowed_hosts: [] },
        b: { allowed_hosts: ['*', 'ok.example.com', 42] },
      },
    });
    expect(problems).toHaveLength(3);
    expect(problems[1]).toContain('secrets["b"].allowed_hosts[0] "*"');
    expect(problems[2]).toContain('allowed_hosts[2] 42: must be a string');
    expect(policy.secrets).toEqual([]);
  });

  it('rejects bad secret names and patterns', () => {
    const { problems } = parse({
      secrets: {
        '*': { allowed_hosts: ['a.example.com'] },
        '../x': { allowed_hosts: ['a.example.com'] },
        'a*b': { allowed_hosts: ['a.example.com'] },
        '*suffix': { allowed_hosts: ['a.example.com'] },
      },
      shared: { 'shared-*': { allowed_hosts: ['a.example.com'] } },
    });
    expect(problems).toHaveLength(5);
  });
});

describe('policyHostsFor', () => {
  const { policy } = parse({
    secrets: {
      'google-*': { allowed_hosts: ['*.googleapis.com'] },
      'google-ads-*': { allowed_hosts: ['googleads.googleapis.com'] },
      'google-ads-legacy': { allowed_hosts: ['legacy.example.com'] },
      'github-token': { allowed_hosts: ['api.github.com'] },
    },
  });
  const hosts = (name: string) => policyHostsFor(policy, name)?.map(p => p.host);

  it('prefers an exact name, then the longest prefix, regardless of key order', () => {
    expect(hosts('github-token')).toEqual(['api.github.com']);
    expect(hosts('google-ads-legacy')).toEqual(['legacy.example.com']);
    expect(hosts('google-ads-main')).toEqual(['googleads.googleapis.com']);
    expect(hosts('google-drive')).toEqual(['googleapis.com']);
  });

  it('returns undefined when nothing matches', () => {
    expect(hosts('github-token-2')).toBeUndefined();
    expect(hosts('slack')).toBeUndefined();
  });
});
