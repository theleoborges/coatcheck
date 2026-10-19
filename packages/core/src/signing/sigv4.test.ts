import { describe, it, expect } from 'vitest';
import fs from 'node:fs';
import { createHash } from 'node:crypto';
import { SignatureV4 } from '@smithy/signature-v4';
import { HttpRequest } from '@smithy/protocol-http';
import {
  amzDateOf, canonicalQuery, canonicalRequest, canonicalUri, deriveSigningKey, finalizeSigV4, parseSigV4Authorization,
  payloadMode, signatureFor, stringToSign, uriEncode, type SigV4Authorization, type SigV4Credential,
} from './sigv4.js';
import { firstHeader, type SignableRequest } from './request.js';
import { planSigning, type SigningPlan } from './processor.js';
import { TokenStore } from '../token-store.js';
import { parseHostPattern, type HostPattern } from '../host-matcher.js';
import { Sha256 } from '../test-helpers.js';

const SUITE = new URL('./__fixtures__/aws-sigv4-test-suite/', import.meta.url);
const SECRET = 'wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY';
const EXAMPLE: SigV4Credential = { scheme: 'aws-sigv4', accessKeyId: 'AKIDEXAMPLE', secretAccessKey: SECRET };
const TICKET = `cct_${'ab'.repeat(32)}`;
const sha256Hex = (d: string | Buffer) => createHash('sha256').update(d).digest('hex');

/** Parse a test-suite request file: request line, header lines (obs-fold continuations kept with their line break), body. */
function parseSuiteRequest(text: string): { req: SignableRequest; body: Buffer } {
  const blank = text.indexOf('\n\n');
  const head = blank === -1 ? text.replace(/\n$/, '') : text.slice(0, blank);
  const body = blank === -1 ? '' : text.slice(blank + 2);
  const [requestLine, ...lines] = head.split('\n');
  const [method, target] = requestLine.split(' ');
  const headers: Array<[string, string]> = [];
  for (const line of lines) {
    if (/^[ \t]/.test(line)) headers[headers.length - 1][1] += `\n${line}`;
    else {
      const colon = line.indexOf(':');
      headers.push([line.slice(0, colon), line.slice(colon + 1)]);
    }
  }
  return { req: { method, target, headers }, body: Buffer.from(body) };
}

const read = (c: string, f: string) => fs.readFileSync(new URL(`${c}/${f}`, SUITE), 'utf8');

const CASES = [
  'get-vanilla', 'get-vanilla-query-order-key-case', 'get-header-value-trim', 'get-header-value-multiline', 'get-utf8',
  'post-vanilla-query', 'post-x-www-form-urlencoded', 'post-sts-header-after', 'get-vanilla-with-session-token',
];

describe('sigv4: published vectors', () => {
  it('derives the signing key from the AWS documentation example', () => {
    expect(deriveSigningKey(SECRET, '20150830', 'us-east-1', 'iam').toString('hex'))
      .toBe('c4afb1cc5771d871763a393e44b703571b55cc28424d1a5e86da6ed3c154a4b9');
  });

  for (const c of CASES) {
    it(`${c}: canonical request, string-to-sign and signature match the suite`, () => {
      const { req, body } = parseSuiteRequest(read(c, 'header-signed-request.txt'));
      const auth = parseSigV4Authorization(firstHeader(req, 'authorization')!) as SigV4Authorization;
      expect(auth.accessKeyId).toBe('AKIDEXAMPLE');
      const mode = payloadMode(req);
      const hash = mode.kind === 'header' ? mode.value : sha256Hex(body);
      const canonical = canonicalRequest(req, auth.signedHeaders, hash, auth.service);
      expect(canonical).toBe(read(c, 'header-canonical-request.txt').replace(/\n$/, ''));
      const sts = stringToSign(amzDateOf(req)!, `${auth.date}/${auth.region}/${auth.service}/aws4_request`, canonical);
      expect(sts).toBe(read(c, 'header-string-to-sign.txt').replace(/\n$/, ''));
      const signature = signatureFor(req, auth, auth.signedHeaders, hash, SECRET);
      expect(signature).toBe(read(c, 'header-signature.txt').trim());
      expect(signature).toBe(auth.signature);
    });

    it(`${c}: re-signing an agent's ticket-signed request yields the suite's Authorization`, () => {
      const { req: signed, body } = parseSuiteRequest(read(c, 'header-signed-request.txt'));
      const expectedAuth = firstHeader(signed, 'authorization')!;
      const published = parseSigV4Authorization(expectedAuth) as SigV4Authorization;
      const context = JSON.parse(read(c, 'context.json')) as { credentials: { token?: string }; omit_session_token?: boolean };
      // The agent: the same request signed with the ticket as both key id and secret.
      const mode = payloadMode(signed);
      const hash = mode.kind === 'header' ? mode.value : sha256Hex(body);
      const agentSig = signatureFor(signed, published, published.signedHeaders, hash, TICKET);
      const agent: SignableRequest = {
        ...signed,
        headers: signed.headers.map(([n, v]): [string, string] => n.toLowerCase() === 'authorization'
          ? [n, expectedAuth.replace('AKIDEXAMPLE', TICKET).replace(published.signature, agentSig)]
          : [n, v]),
      };
      const auth = parseSigV4Authorization(firstHeader(agent, 'authorization')!) as SigV4Authorization;
      // post-sts-header-after adds the token after signing, unsigned: re-sign without one.
      const token = context.credentials.token && !context.omit_session_token ? context.credentials.token : undefined;
      const credential = { ...EXAMPLE, ...(token ? { sessionToken: token } : {}) };
      const view = { request: agent, body };
      const out = finalizeSigV4(auth, TICKET, credential, view, view);
      expect(out.ok).toBe(true);
      const headers = (out as { headers: Array<[string, string]> }).headers;
      expect(firstHeader({ ...agent, headers }, 'authorization')).toBe(expectedAuth.trim());
      expect(firstHeader({ ...agent, headers }, 'x-amz-security-token')).toBe(token);
    });
  }
});

describe('sigv4: canonical forms', () => {
  it('s3 keeps the path as sent; other services encode it again and normalise', () => {
    const path = '/reports/my%20report.md/a b';
    expect(canonicalUri(path, 's3')).toBe(path);
    expect(canonicalUri('/reports/my%20report.md', 'sts')).toBe('/reports/my%2520report.md');
    expect(canonicalUri('/a/./b/../c//d/', 'service')).toBe('/a/c/d/');
    expect(canonicalUri('', 's3')).toBe('/');
  });

  it('sorts query parameters by name then value and re-encodes them (RFC 3986)', () => {
    expect(canonicalQuery('b=2&a=2&a=1&c')).toBe('a=1&a=2&b=2&c=');
    expect(canonicalQuery('k=a%20b&x=%2a!')).toBe('k=a%20b&x=%2A%21');
    expect(canonicalQuery('bad=%zz')).toBe('bad=%25zz');
    expect(uriEncode("a!'()*~")).toBe('a%21%27%28%29%2A~');
  });

  it('takes the request time from Date when X-Amz-Date is absent', () => {
    expect(amzDateOf({ method: 'GET', target: '/', headers: [['Date', 'Sun, 30 Aug 2015 12:36:00 GMT']] })).toBe('20150830T123600Z');
    expect(amzDateOf({ method: 'GET', target: '/', headers: [] })).toBeUndefined();
  });
});

describe('sigv4: Authorization parser and payload modes', () => {
  const good = `AWS4-HMAC-SHA256 Credential=${TICKET}/20150830/us-east-1/s3/aws4_request, SignedHeaders=host;x-amz-date, Signature=${'0'.repeat(64)}`;

  it('parses a SigV4 Authorization value', () => {
    expect(parseSigV4Authorization(good)).toEqual({
      accessKeyId: TICKET, date: '20150830', region: 'us-east-1', service: 's3',
      signedHeaders: ['host', 'x-amz-date'], signature: '0'.repeat(64),
    });
  });

  it('leaves other schemes alone and flags SigV4a', () => {
    expect(parseSigV4Authorization(`Bearer ${TICKET}`)).toBeNull();
    expect(parseSigV4Authorization('AWS4-ECDSA-P256-SHA256 Credential=x')).toBe('sigv4a');
  });

  it.each([
    ['no components', 'AWS4-HMAC-SHA256'],
    ['missing Signature', `AWS4-HMAC-SHA256 Credential=${TICKET}/20150830/us-east-1/s3/aws4_request, SignedHeaders=host`],
    ['short signature', good.replace('0'.repeat(64), 'abc')],
    ['bad scope', good.replace('/aws4_request', '/aws5_request')],
    ['bad date', good.replace('20150830', '2015083')],
    ['upper-case signed header', good.replace('host;', 'Host;')],
    ['duplicate component', `${good}, Signature=${'1'.repeat(64)}`],
    ['extra component', `${good}, Extra=1`],
    ['signs authorization', good.replace('host;', 'authorization;host;')],
    ['component without =', `${good}, junk`],
  ])('rejects a malformed value: %s', (_label, value) => {
    expect(parseSigV4Authorization(value)).toBe('malformed-authorization');
  });

  const withHash = (v?: string): SignableRequest => ({ method: 'PUT', target: '/', headers: v === undefined ? [] : [['x-amz-content-sha256', v]] });
  it('uses x-amz-content-sha256 as the payload hash; without it the body is needed', () => {
    expect(payloadMode(withHash())).toEqual({ kind: 'body' });
    expect(payloadMode(withHash('UNSIGNED-PAYLOAD'))).toEqual({ kind: 'header', value: 'UNSIGNED-PAYLOAD' });
    expect(payloadMode(withHash('STREAMING-UNSIGNED-PAYLOAD-TRAILER'))).toEqual({ kind: 'header', value: 'STREAMING-UNSIGNED-PAYLOAD-TRAILER' });
    expect(payloadMode(withHash('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855')).kind).toBe('header');
    for (const marker of ['STREAMING-AWS4-HMAC-SHA256-PAYLOAD', 'STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER', 'STREAMING-AWS4-ECDSA-P256-SHA256-PAYLOAD']) {
      expect(payloadMode(withHash(marker))).toEqual({ kind: 'unsignable', reason: 'streaming-signed-payload' });
    }
    expect(payloadMode({ method: 'PUT', target: '/', headers: [['x-amz-content-sha256', 'a'], ['X-Amz-Content-Sha256', 'b']] }))
      .toEqual({ kind: 'unsignable', reason: 'repeated-payload-hash' });
  });
});

/** Deterministic PRNG (mulberry32), so a failing case can be replayed from its seed. */
function rng(seed: number) {
  let a = seed >>> 0;
  const next = () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
  const int = (n: number) => Math.floor(next() * n);
  const pick = <T>(xs: readonly T[]): T => xs[int(xs.length)];
  const str = (alphabet: string, min: number, max: number) =>
    Array.from({ length: min + int(max - min + 1) }, () => alphabet[int(alphabet.length)]).join('');
  return { next, int, pick, str };
}

const SEGMENT_CHARS = 'abcXYZ019-_.~ !*()é/+=&%';
const VALUE_CHARS = 'abc XYZ 019\t-_.~!*"\'()/+=,;:';

describe('sigv4: property check against @smithy/signature-v4', () => {
  const hostPattern = parseHostPattern('example.amazonaws.com') as HostPattern;

  it('verifies the SDK-signed request and re-signs it exactly as the SDK would with the real key (300 cases)', async () => {
    for (let seed = 1; seed <= 300; seed++) {
      const r = rng(seed);
      const service = r.pick(['service', 'sts', 's3', 'execute-api']);
      const s3 = service === 's3';
      const method = r.pick(['GET', 'POST', 'PUT', 'DELETE']);
      // The wire path as an SDK serialises it: segments percent-encoded once.
      const segments = Array.from({ length: r.int(4) }, () => (r.next() < 0.1 ? r.pick(['.', '..', '']) : uriEncode(r.str(SEGMENT_CHARS, 1, 8))));
      const path = `/${segments.join('/')}${r.next() < 0.2 ? '/' : ''}`;
      const query: Record<string, string | string[]> = {};
      for (let i = r.int(4); i > 0; i--) {
        const key = r.str('abcAB01-_.~ =&', 1, 5);
        const value = r.str('abc 01-_.~/=&+é', 0, 6);
        query[key] = r.next() < 0.2 ? [value, r.str('xyz', 1, 3)] : value;
      }
      const headers: Record<string, string> = { host: 'example.amazonaws.com' };
      for (let i = r.int(5); i > 0; i--) {
        const name = r.pick(['X-Test-', 'x-custom-', 'Content-Type']) + (r.next() < 0.7 ? r.str('abc', 1, 3) : '');
        headers[name] = ` ${r.str(VALUE_CHARS, 0, 12)} `.replace(/^ | $/g, () => (r.next() < 0.5 ? ' ' : ''));
      }
      const body = r.next() < 0.5 ? Buffer.from(r.str('{}"abc 123\n', 0, 64)) : undefined;
      if (s3) headers['x-amz-content-sha256'] = r.next() < 0.5 ? 'UNSIGNED-PAYLOAD' : sha256Hex(body ?? Buffer.alloc(0));
      const agentToken = r.next() < 0.3 ? `cct_${'cd'.repeat(32)}` : undefined;
      const realToken = r.next() < 0.4 ? `FQoG${r.str('abcdef0123456789/+=', 20, 40)}` : undefined;
      const signingDate = new Date(Date.UTC(2026, r.int(12), 1 + r.int(28), r.int(24), r.int(60), r.int(60)));

      const unsigned = () => new HttpRequest({ method, protocol: 'https:', hostname: 'example.amazonaws.com', path, query, headers: { ...headers }, body });
      const signer = (accessKeyId: string, secretAccessKey: string, sessionToken?: string) => new SignatureV4({
        credentials: { accessKeyId, secretAccessKey, ...(sessionToken ? { sessionToken } : {}) },
        region: 'eu-west-2', service, sha256: Sha256, uriEscapePath: !s3, applyChecksum: false,
      });
      const store = new TokenStore();
      const { id } = store.issue('aws', '', {
        allowedHosts: [hostPattern],
        signing: { scheme: 'aws-sigv4', accessKeyId: 'AKIAREALKEY', secretAccessKey: 'real/secret+key', ...(realToken ? { sessionToken: realToken } : {}) },
      });
      const agentSigned = await signer(id, id, agentToken).sign(unsigned(), { signingDate });
      const expected = await signer('AKIAREALKEY', 'real/secret+key', realToken).sign(unsigned(), { signingDate });

      // The agent's request on the wire: query in an arbitrary order.
      const wireQuery = Object.entries(query).flatMap(([k, v]) => (Array.isArray(v) ? v : [v]).map(x => `${uriEncode(k)}=${uriEncode(x)}`));
      if (r.next() < 0.5) wireQuery.reverse();
      const req: SignableRequest = {
        method,
        target: wireQuery.length > 0 ? `${path}?${wireQuery.join('&')}` : path,
        headers: Object.entries(agentSigned.headers).map(([n, v]): [string, string] => [n, ` ${v}`]),
      };

      const plan = planFor(store, req);
      store.destroy();
      expect(plan.needsBody, `seed ${seed}`).toBe(!s3);
      const view = { request: req, body: body ?? Buffer.alloc(0) };
      const out = plan.finalize(view, view);
      expect(out.ok, `seed ${seed}`).toBe(true);
      const outHeaders = (out as { headers: Array<[string, string]> }).headers;
      const got = { ...req, headers: outHeaders };
      expect(expected.headers.authorization).toMatch(/^AWS4-HMAC-SHA256 Credential=AKIAREALKEY\//);
      expect(firstHeader(got, 'authorization'), `seed ${seed}`).toBe(expected.headers.authorization);
      expect(firstHeader(got, 'x-amz-security-token'), `seed ${seed}`).toBe(realToken);
    }
  });

  it('refuses an SDK-signed request whose signed header changed afterwards', async () => {
    const store = new TokenStore();
    const { id } = store.issue('aws', '', { allowedHosts: [hostPattern], signing: EXAMPLE });
    const signed = await new SignatureV4({
      credentials: { accessKeyId: id, secretAccessKey: id }, region: 'us-east-1', service: 'sts', sha256: Sha256,
    }).sign(new HttpRequest({ method: 'POST', hostname: 'example.amazonaws.com', path: '/', headers: { host: 'example.amazonaws.com', 'x-test': 'a' }, body: 'x=1' }));
    const req: SignableRequest = { method: 'POST', target: '/', headers: Object.entries(signed.headers).map(([n, v]) => [n, n === 'x-test' ? 'b' : v]) };
    const plan = planFor(store, req);
    store.destroy();
    const view = { request: req, body: Buffer.from('x=1') };
    expect(plan.finalize(view, view)).toEqual({ ok: false, reason: 'signature-mismatch' });
  });
});

function planFor(store: TokenStore, req: SignableRequest): SigningPlan {
  const plan = planSigning(store, req, { host: 'example.amazonaws.com', scheme: 'https' });
  if (plan?.kind !== 'plan') throw new Error(`expected a plan, got ${JSON.stringify(plan)}`);
  return plan;
}
