import { describe, it, expect } from 'vitest';
import { parsePolicy, policyHostsFor, policyRuleFor } from './policy.js';

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
    expect(policy.shared.get('browserbase-api-key')).toEqual({ allowedHosts: [{ kind: 'exact', host: 'api.browserbase.com', plaintext: false }] });
  });

  it('parses swap_body on secrets and shared entries, and only booleans', () => {
    const { policy, problems } = parse({
      secrets: { a: { allowed_hosts: ['a.example.com'], swap_body: true }, b: { allowed_hosts: ['b.example.com'] } },
      shared: { s: { allowed_hosts: ['s.example.com'], swap_body: false } },
    });
    expect(problems).toEqual([]);
    expect(policyRuleFor(policy, 'a')?.swapBody).toBe(true);
    expect(policyRuleFor(policy, 'b')?.swapBody).toBeUndefined();
    expect(policy.shared.get('s')?.swapBody).toBe(false);
    expect(parse({ secrets: { a: { allowed_hosts: ['a.example.com'], swap_body: 'yes' } } }).problems)
      .toEqual([expect.stringContaining('secrets["a"].swap_body must be true or false')]);
  });

  it('parses swap_url and swap_headers, lowercasing header names, and refuses bad values', () => {
    const { policy, problems } = parse({
      secrets: { a: { allowed_hosts: ['a.example.com'], swap_url: true, swap_headers: ['X-Api-Key', 'x-api-key'] } },
      shared: { s: { allowed_hosts: ['s.example.com'], swap_headers: ['X-BB-API-Key'] } },
    });
    expect(problems).toEqual([]);
    expect(policyRuleFor(policy, 'a')).toMatchObject({ swapUrl: true, swapHeaders: ['x-api-key'] });
    expect(policy.shared.get('s')).toMatchObject({ swapHeaders: ['x-bb-api-key'] });
    expect(parse({
      secrets: {
        a: { allowed_hosts: ['a.example.com'], swap_url: 'yes' },
        b: { allowed_hosts: ['b.example.com'], swap_headers: [] },
        c: { allowed_hosts: ['c.example.com'], swap_headers: ['bad name'] },
        d: { allowed_hosts: ['d.example.com'], swap_headers: ['Host'] },
      },
    }).problems).toEqual([
      expect.stringContaining('secrets["a"].swap_url must be true or false'),
      expect.stringContaining('secrets["b"].swap_headers must be a non-empty array'),
      expect.stringContaining('secrets["c"].swap_headers [0] "bad name": not a header name'),
      expect.stringContaining('secrets["d"].swap_headers [0] "host": a value can\'t be swapped into Host'),
    ]);
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
        // A prefix longer than any valid name could never match.
        [`${'a'.repeat(129)}*`]: { allowed_hosts: ['a.example.com'] },
      },
      shared: { 'shared-*': { allowed_hosts: ['a.example.com'] } },
    });
    expect(problems).toHaveLength(6);
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

describe('parsePolicy: signing', () => {
  it('parses signing on secrets and shared entries', () => {
    const problems: string[] = [];
    const p = parsePolicy(JSON.stringify({
      secrets: { 'aws-reports': { allowed_hosts: ['bucket.s3.us-east-1.amazonaws.com'], signing: 'aws-sigv4' } },
      shared: { 'aws-shared': { allowed_hosts: ['sts.us-east-1.amazonaws.com'], signing: 'aws-sigv4' } },
    }), problems);
    expect(problems).toEqual([]);
    expect(p.secrets[0].signing).toEqual({ type: 'aws-sigv4' });
    expect(p.shared.get('aws-shared')?.signing).toEqual({ type: 'aws-sigv4' });
  });

  it('fails startup on an invalid signing value', () => {
    for (const signing of ['sigv4', true, {}, { type: 'aws-sigv4' }]) {
      const problems: string[] = [];
      parsePolicy(JSON.stringify({ secrets: { x: { allowed_hosts: ['a.example'], signing } } }), problems);
      expect(problems, JSON.stringify(signing)).toEqual([expect.stringContaining('secrets["x"].signing')]);
    }
  });
});

describe('parsePolicy: HMAC recipes', () => {
  const ledger = { type: 'hmac', hash: 'sha256', key_header: 'X-Ledger-Key', signature_header: 'X-Ledger-Signature', encoding: 'base64', message: ['header:X-Ledger-Timestamp', 'method', 'path_query', 'body'] };

  it('parses the ledger recipe', () => {
    const { policy, problems } = parse({ secrets: { ledger: { allowed_hosts: ['ledger'], signing: ledger } } });
    expect(problems).toEqual([]);
    expect(policy.secrets[0].signing).toEqual(expect.objectContaining({ type: 'hmac', keyHeader: 'x-ledger-key', encoding: 'base64' }));
  });

  it.each([
    ['unknown key', { ...ledger, nonce: true }],
    ['missing key_header', { ...ledger, key_header: undefined }],
    ['key_header host', { ...ledger, key_header: 'host' }],
    ['missing signature_header', { ...ledger, signature_header: undefined }],
    ['bad hash', { ...ledger, hash: 'md5' }],
    ['bad encoding', { ...ledger, encoding: 'hex64' }],
    ['base64 key with verify', { ...ledger, key_encoding: 'base64' }],
    ['empty message', { ...ledger, message: [] }],
    ['bad part', { ...ledger, message: ['headers'] }],
    ['verify not boolean', { ...ledger, verify: 1 }],
    ['wrong type', { ...ledger, type: 'hmac-sha256' }],
  ])('fails startup on a malformed recipe: %s', (_label, signing) => {
    const { problems } = parse({ secrets: { ledger: { allowed_hosts: ['ledger'], signing: JSON.parse(JSON.stringify(signing)) } } });
    expect(problems).toEqual([expect.stringContaining('secrets["ledger"].signing (hmac recipe)')]);
  });
});
