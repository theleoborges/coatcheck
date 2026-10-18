import { describe, it, expect } from 'vitest';
import { createHmac } from 'node:crypto';
import { decodeHmacKey, finalizeHmac, hmacMessage, hmacRecipeJson, hmacSignature, parseHmacRecipe, type HmacCredential, type HmacRecipe } from './hmac.js';
import { firstHeader, type SignableRequest } from './request.js';

const LEDGER = {
  type: 'hmac', hash: 'sha256', key_header: 'X-Ledger-Key', signature_header: 'X-Ledger-Signature', encoding: 'base64',
  message: ['header:X-Ledger-Timestamp', 'method', 'path_query', 'body'],
};
const TICKET = `cct_${'ab'.repeat(32)}`;
const recipe = (over: Record<string, unknown> = {}) => parseHmacRecipe({ ...LEDGER, ...over }) as HmacRecipe;

describe('parseHmacRecipe', () => {
  it('parses the ledger recipe with defaults filled in', () => {
    const r = parseHmacRecipe({ type: 'hmac', key_header: 'X-Key', signature_header: 'X-Sig', message: ['method'] });
    expect(r).toEqual(expect.objectContaining({ hash: 'sha256', encoding: 'hex', keyEncoding: 'utf8', verify: true, keyHeader: 'x-key', signatureHeader: 'x-sig' }));
    expect(recipe().message).toEqual([{ kind: 'header', name: 'x-ledger-timestamp' }, { kind: 'method' }, { kind: 'path_query' }, { kind: 'body' }]);
  });

  it.each([
    ['not an object', 'hmac'],
    ['an array', []],
    ['wrong type', { ...LEDGER, type: 'hmac-sha256' }],
    ['no type', { ...LEDGER, type: undefined }],
    ['unknown key', { ...LEDGER, msg: ['body'] }],
    ['bad hash', { ...LEDGER, hash: 'md5' }],
    ['missing key_header', { ...LEDGER, key_header: undefined }],
    ['key_header not a token', { ...LEDGER, key_header: 'X Key' }],
    ['key_header host', { ...LEDGER, key_header: 'Host' }],
    ['missing signature_header', { ...LEDGER, signature_header: undefined }],
    ['signature_header host', { ...LEDGER, signature_header: 'host' }],
    ['signature_header Content-Length (would reframe the request)', { ...LEDGER, signature_header: 'Content-Length' }],
    ['signature_header transfer-encoding', { ...LEDGER, signature_header: 'transfer-encoding' }],
    ['key_header connection', { ...LEDGER, key_header: 'Connection' }],
    ['key_header proxy-authorization', { ...LEDGER, key_header: 'Proxy-Authorization' }],
    ['same header twice', { ...LEDGER, signature_header: 'x-ledger-key' }],
    ['bad encoding', { ...LEDGER, encoding: 'base32' }],
    ['bad key_encoding', { ...LEDGER, key_encoding: 'latin1', verify: false }],
    ['key_encoding base64 with verify', { ...LEDGER, key_encoding: 'base64' }],
    ['key_encoding hex with verify: true', { ...LEDGER, key_encoding: 'hex', verify: true }],
    ['verify not boolean', { ...LEDGER, verify: 'no' }],
    ['empty message', { ...LEDGER, message: [] }],
    ['message not a list', { ...LEDGER, message: 'body' }],
    ['unknown part', { ...LEDGER, message: ['url'] }],
    ['non-string part', { ...LEDGER, message: [1] }],
    ['bad header part', { ...LEDGER, message: ['header:'] }],
    ['header part with a space', { ...LEDGER, message: ['header:X Y'] }],
  ])('rejects %s', (_label, v) => {
    expect(typeof parseHmacRecipe(JSON.parse(JSON.stringify(v ?? null)))).toBe('string');
  });

  it('accepts a non-utf8 key encoding with verify: false', () => {
    expect(recipe({ key_encoding: 'base64', verify: false }).keyEncoding).toBe('base64');
  });

  it('publishes the recipe as written, never key material', () => {
    expect(hmacRecipeJson(recipe())).toEqual({ ...LEDGER });
  });
});

describe('hmacMessage', () => {
  const req: SignableRequest = {
    method: 'POST',
    target: '/v1/transfers?dry_run=1',
    headers: [['Host', ' ledger'], ['X-Ledger-Timestamp', ' 1760000000 '], ['X-Multi', ' a'], ['x-multi', 'b ']],
  };
  const body = Buffer.from([0x7b, 0x00, 0xff, 0x7d]);
  const msg = (message: string[], b: Buffer | undefined = body) => hmacMessage(recipe({ message }), { request: req, body: b });

  it('builds each part as sent', () => {
    expect(msg(['method']).toString()).toBe('POST');
    expect(msg(['path']).toString()).toBe('/v1/transfers');
    expect(msg(['query']).toString()).toBe('dry_run=1');
    expect(msg(['path_query']).toString()).toBe('/v1/transfers?dry_run=1');
    expect(msg(['header:x-ledger-timestamp']).toString()).toBe('1760000000');
    expect(msg(['literal:v1|']).toString()).toBe('v1|');
    expect(msg(['header:X-Missing', 'literal:|']).toString()).toBe('|');
  });

  it('joins repeated headers with a comma', () => {
    expect(msg(['header:X-Multi']).toString()).toBe('a,b');
  });

  it('keeps body bytes exactly and concatenates parts in order', () => {
    expect(msg(['body'])).toEqual(body);
    expect(msg(['header:X-Ledger-Timestamp', 'method', 'path_query', 'body']))
      .toEqual(Buffer.concat([Buffer.from('1760000000POST/v1/transfers?dry_run=1'), body]));
    expect(hmacMessage(recipe({ message: ['body'] }), { request: req })).toEqual(Buffer.alloc(0));
  });
});

describe('hmacSignature: each hash and encoding against node:crypto', () => {
  const message = Buffer.from('1760000000GET/v1/accounts');
  for (const hash of ['sha256', 'sha384', 'sha512', 'sha1'] as const) {
    for (const encoding of ['hex', 'base64'] as const) {
      it(`${hash} / ${encoding}`, () => {
        expect(hmacSignature(recipe({ hash, encoding }), 'k3y', message))
          .toBe(createHmac(hash, 'k3y').update(message).digest(encoding));
      });
    }
  }
});

describe('decodeHmacKey', () => {
  it('decodes per key_encoding and refuses what does not decode', () => {
    expect(decodeHmacKey('s3cret', 'utf8')).toEqual(Buffer.from('s3cret'));
    expect(decodeHmacKey('00ff10', 'hex')).toEqual(Buffer.from([0, 255, 16]));
    expect(decodeHmacKey('0f1', 'hex')).toBeNull();
    expect(decodeHmacKey('AP8Q', 'base64')).toEqual(Buffer.from([0, 255, 16]));
    expect(decodeHmacKey('AP8Q==', 'base64')).toEqual(Buffer.from([0, 255, 16]));
    expect(decodeHmacKey('not base64!', 'base64')).toBeNull();
    // A dangling character (Node would drop it silently) is refused, not a shortened key.
    expect(decodeHmacKey('AP8QA', 'base64')).toBeNull();
    expect(decodeHmacKey('AP8QA=', 'base64')).toBeNull();
  });
});

describe('finalizeHmac', () => {
  const key = Buffer.from('real-ledger-secret');
  const base = (r: HmacRecipe, keyHeader = r.written.keyHeader): SignableRequest => ({
    method: 'GET',
    target: '/v1/accounts',
    headers: [['Host', ' ledger'], [keyHeader, ` ${TICKET}`], ['X-Ledger-Timestamp', ' 1760000000']],
  });
  const agentSigned = (r: HmacRecipe, req: SignableRequest, body?: Buffer): SignableRequest => ({
    ...req,
    headers: [...req.headers, [r.written.signatureHeader, ` ${hmacSignature(r, TICKET, hmacMessage(r, { request: req, body }))}`]],
  });

  it('verifies the agent signature, replaces the key header with key_id, and signs with the real key', () => {
    const r = recipe();
    const req = agentSigned(r, base(r));
    const cred: HmacCredential = { scheme: 'hmac', recipe: r, key, keyId: 'auditor-1' };
    const out = finalizeHmac(TICKET, cred, { request: req }, { request: req });
    expect(out.ok).toBe(true);
    const headers = (out as { headers: Array<[string, string]> }).headers;
    const signed = { ...req, headers };
    expect(firstHeader(signed, 'x-ledger-key')).toBe('auditor-1');
    expect(firstHeader(signed, 'x-ledger-signature'))
      .toBe(createHmac('sha256', key).update('1760000000GET/v1/accounts').digest('base64'));
    expect(headers.filter(([n]) => n.toLowerCase() === 'x-ledger-signature')).toHaveLength(1);
    expect(JSON.stringify(headers)).not.toContain(TICKET);
  });

  it('refuses a signature over a different message, a missing one and a repeated one', () => {
    const r = recipe();
    const req = agentSigned(r, base(r));
    const cred: HmacCredential = { scheme: 'hmac', recipe: r, key, keyId: 'k' };
    const tampered = { ...req, target: '/v1/accounts/acc_ops' };
    expect(finalizeHmac(TICKET, cred, { request: tampered }, { request: tampered })).toEqual({ ok: false, reason: 'signature-mismatch' });
    const unsigned = base(r);
    expect(finalizeHmac(TICKET, cred, { request: unsigned }, { request: unsigned })).toEqual({ ok: false, reason: 'signature-mismatch' });
    const twice: SignableRequest = { ...req, headers: [...req.headers, req.headers[req.headers.length - 1]] };
    expect(finalizeHmac(TICKET, cred, { request: twice }, { request: twice })).toEqual({ ok: false, reason: 'signature-mismatch' });
  });

  it('accepts an upper-case hex signature (hex is case-insensitive)', () => {
    const r = recipe({ encoding: 'hex' });
    const req = base(r);
    const sig = hmacSignature(r, TICKET, hmacMessage(r, { request: req })).toUpperCase();
    const signedReq: SignableRequest = { ...req, headers: [...req.headers, [r.written.signatureHeader, ` ${sig}`]] };
    const cred: HmacCredential = { scheme: 'hmac', recipe: r, key, keyId: 'k' };
    expect(finalizeHmac(TICKET, cred, { request: signedReq }, { request: signedReq }).ok).toBe(true);
  });

  it('with verify: false signs without checking (non-utf8 key)', () => {
    const r = recipe({ key_encoding: 'base64', verify: false });
    const req = base(r);
    const raw = Buffer.from([1, 2, 3, 4]);
    const out = finalizeHmac(TICKET, { scheme: 'hmac', recipe: r, key: raw, keyId: 'k' }, { request: req }, { request: req });
    expect(out.ok).toBe(true);
    expect(firstHeader({ ...req, headers: (out as { headers: Array<[string, string]> }).headers }, 'x-ledger-signature'))
      .toBe(createHmac('sha256', raw).update('1760000000GET/v1/accounts').digest('base64'));
  });

  it('strips the key header when the secret has no key_id (X-Coatcheck-Key)', () => {
    const r = recipe({ key_header: 'X-Coatcheck-Key' });
    const req = agentSigned(r, base(r));
    const out = finalizeHmac(TICKET, { scheme: 'hmac', recipe: r, key }, { request: req }, { request: req });
    const headers = (out as { headers: Array<[string, string]> }).headers;
    expect(headers.some(([n]) => n.toLowerCase() === 'x-coatcheck-key')).toBe(false);
  });

  it('a recipe signing the key header verifies with the ticket and signs with key_id', () => {
    const r = recipe({ message: ['header:X-Ledger-Key', 'literal:|', 'method', 'path_query'] });
    const req = agentSigned(r, base(r));
    const out = finalizeHmac(TICKET, { scheme: 'hmac', recipe: r, key, keyId: 'auditor-1' }, { request: req }, { request: req });
    expect(out.ok).toBe(true);
    expect(firstHeader({ ...req, headers: (out as { headers: Array<[string, string]> }).headers }, 'x-ledger-signature'))
      .toBe(createHmac('sha256', key).update('auditor-1|GET/v1/accounts').digest('base64'));
  });

  it('signs the outgoing body, which can differ from the received one', () => {
    const r = recipe();
    const req: SignableRequest = { ...base(r), method: 'POST', target: '/v1/transfers' };
    const received = Buffer.from('{"note":"cct_x"}');
    const sent = Buffer.from('{"note":"real"}');
    const signed = agentSigned(r, req, received);
    const out = finalizeHmac(TICKET, { scheme: 'hmac', recipe: r, key, keyId: 'k' }, { request: signed, body: received }, { request: signed, body: sent });
    expect(firstHeader({ ...req, headers: (out as { headers: Array<[string, string]> }).headers }, 'x-ledger-signature'))
      .toBe(createHmac('sha256', key).update(Buffer.concat([Buffer.from('1760000000POST/v1/transfers'), sent])).digest('base64'));
  });
});
