import { createHash, createHmac, timingSafeEqual } from 'node:crypto';
import { firstHeader, headerValues, rawHeaderValues, type SignableRequest, type SigningView } from './request.js';

/**
 * AWS Signature Version 4, header form (design: docs/design/signing-processors.md
 * §4.3). Pure: `node:crypto` only, no clock. Nothing here logs; callers must
 * never log a canonical request, string-to-sign, signature or key.
 */

export const SIGV4_ALGORITHM = 'AWS4-HMAC-SHA256';
const SIGV4A_ALGORITHM = 'AWS4-ECDSA-P256-SHA256';

/** A real AWS credential as the token store holds it for a signing ticket. */
export interface SigV4Credential {
  scheme: 'aws-sigv4';
  accessKeyId: string;
  secretAccessKey: string;
  sessionToken?: string;
}

/** A parsed `Authorization: AWS4-HMAC-SHA256 …` value. */
export interface SigV4Authorization {
  accessKeyId: string;
  /** `YYYYMMDD` from the credential scope. */
  date: string;
  region: string;
  service: string;
  /** As listed (lowercase). */
  signedHeaders: string[];
  /** Lowercase hex. */
  signature: string;
}

/** Why a SigV4 request is not re-signed (`[swap] result=unsignable reason=…`). */
export type SigV4Unsignable = 'sigv4a' | 'malformed-authorization' | 'streaming-signed-payload' | 'repeated-payload-hash';

const CREDENTIAL = /^([^/\s]+)\/(\d{8})\/([^/\s]+)\/([^/\s]+)\/aws4_request$/;
const SIGNED_HEADERS = /^[a-z0-9!#$%&'*+.^_`|~-]+(?:;[a-z0-9!#$%&'*+.^_`|~-]+)*$/;
const SIGNATURE = /^[0-9a-f]{64}$/;

/**
 * Parse an `Authorization` value. Returns null for any other scheme (left
 * alone: a client holding real credentials passes through), `sigv4a` for
 * SigV4a, `malformed-authorization` for a SigV4 value that doesn't parse.
 */
export function parseSigV4Authorization(value: string): SigV4Authorization | 'sigv4a' | 'malformed-authorization' | null {
  const v = value.trim();
  const space = v.search(/\s/);
  const algorithm = space === -1 ? v : v.slice(0, space);
  if (algorithm === SIGV4A_ALGORITHM) return 'sigv4a';
  if (algorithm !== SIGV4_ALGORITHM) return null;
  if (space === -1) return 'malformed-authorization';

  const parts = new Map<string, string>();
  for (const component of v.slice(space).split(',')) {
    const eq = component.indexOf('=');
    if (eq === -1) return 'malformed-authorization';
    const key = component.slice(0, eq).trim();
    if (parts.has(key)) return 'malformed-authorization';
    parts.set(key, component.slice(eq + 1).trim());
  }
  const credential = CREDENTIAL.exec(parts.get('Credential') ?? '');
  const signedHeaders = parts.get('SignedHeaders') ?? '';
  const signature = parts.get('Signature') ?? '';
  if (parts.size !== 3 || !credential || !SIGNED_HEADERS.test(signedHeaders) || !SIGNATURE.test(signature)) {
    return 'malformed-authorization';
  }
  const names = signedHeaders.split(';');
  // A signature can't cover the header that carries it.
  if (names.includes('authorization')) return 'malformed-authorization';
  return {
    accessKeyId: credential[1],
    date: credential[2],
    region: credential[3],
    service: credential[4],
    signedHeaders: names,
    signature,
  };
}

/** RFC 3986 encoding as the AWS SDKs do it: `encodeURIComponent` plus `!'()*`. */
export function uriEncode(text: string): string {
  return encodeURIComponent(text).replace(/[!'()*]/g, c => `%${c.charCodeAt(0).toString(16).toUpperCase()}`);
}

/** Decode `%XX` sequences, leaving a malformed one as it is. `+` stays a `+`. */
function percentDecode(text: string): string {
  try {
    return decodeURIComponent(text);
  } catch {
    return text.replace(/(?:%[0-9A-Fa-f]{2})+/g, run => {
      try { return decodeURIComponent(run); } catch { return run; }
    });
  }
}

/**
 * Canonical URI. `s3` uses the path as sent (no normalisation, no second
 * encoding); every other service removes dot segments and empty segments and
 * encodes the path as sent once more (so `%20` on the wire becomes `%2520`),
 * as the SDKs do.
 */
export function canonicalUri(path: string, service: string): string {
  if (path === '') return '/';
  if (service === 's3') return path;
  const segments: string[] = [];
  for (const segment of path.split('/')) {
    if (segment === '' || segment === '.') continue;
    if (segment === '..') segments.pop();
    else segments.push(segment);
  }
  const normalised = `${path.startsWith('/') ? '/' : ''}${segments.join('/')}${segments.length > 0 && path.endsWith('/') ? '/' : ''}`;
  return uriEncode(normalised).replace(/%2F/g, '/');
}

/** Canonical query: parameters decoded, re-encoded (RFC 3986), sorted by name then value. */
export function canonicalQuery(query: string): string {
  if (query === '') return '';
  const pairs: Array<[string, string]> = [];
  for (const piece of query.split('&')) {
    if (piece === '') continue;
    const eq = piece.indexOf('=');
    const key = eq === -1 ? piece : piece.slice(0, eq);
    const value = eq === -1 ? '' : piece.slice(eq + 1);
    pairs.push([uriEncode(percentDecode(key)), uriEncode(percentDecode(value))]);
  }
  pairs.sort(([ak, av], [bk, bv]) => (ak < bk ? -1 : ak > bk ? 1 : av < bv ? -1 : av > bv ? 1 : 0));
  return pairs.map(([k, v]) => `${k}=${v}`).join('&');
}

/**
 * A header value as SigV4 canonicalises it (as the SDKs do): line breaks
 * (obs-fold) become spaces, runs of spaces and tabs collapse to one, and
 * the ends are trimmed.
 */
function canonicalHeaderValue(value: string): string {
  return value.replace(/[\r\n]/g, ' ').replace(/[ \t]+/g, ' ').replace(/^ | $/g, '');
}

/** Canonical headers block for `signedHeaders` (each `name:value\n`; repeated headers joined with `,`). */
export function canonicalHeaders(req: SignableRequest, signedHeaders: readonly string[]): string {
  return signedHeaders
    .map(name => `${name}:${rawHeaderValues(req, name).map(canonicalHeaderValue).join(',')}\n`)
    .join('');
}

const sha256Hex = (data: string | Buffer) => createHash('sha256').update(data).digest('hex');
const hmac = (key: string | Buffer, data: string) => createHmac('sha256', key).update(data, 'utf8').digest();

/** The SigV4 canonical request (never log it). */
export function canonicalRequest(req: SignableRequest, signedHeaders: readonly string[], payloadHash: string, service: string): string {
  const q = req.target.indexOf('?');
  const path = q === -1 ? req.target : req.target.slice(0, q);
  const query = q === -1 ? '' : req.target.slice(q + 1);
  return [
    req.method,
    canonicalUri(path, service),
    canonicalQuery(query),
    canonicalHeaders(req, signedHeaders),
    signedHeaders.join(';'),
    payloadHash,
  ].join('\n');
}

/** The SigV4 string-to-sign (never log it). */
export function stringToSign(amzDate: string, scope: string, canonical: string): string {
  return [SIGV4_ALGORITHM, amzDate, scope, sha256Hex(canonical)].join('\n');
}

/** `kSigning` from a secret key and the credential scope. */
export function deriveSigningKey(secretAccessKey: string, date: string, region: string, service: string): Buffer {
  const kDate = hmac(`AWS4${secretAccessKey}`, date);
  const kRegion = hmac(kDate, region);
  const kService = hmac(kRegion, service);
  return hmac(kService, 'aws4_request');
}

/**
 * The request's timestamp in ISO 8601 basic format: `X-Amz-Date`, else
 * `Date` converted. Undefined when neither is usable.
 */
export function amzDateOf(req: SignableRequest): string | undefined {
  const amz = firstHeader(req, 'x-amz-date');
  if (amz !== undefined) return amz;
  const date = firstHeader(req, 'date');
  if (date === undefined) return undefined;
  const t = Date.parse(date);
  if (Number.isNaN(t)) return undefined;
  return new Date(t).toISOString().replace(/[-:]|\.\d{3}/g, '');
}

/** Signature (hex) of `req` under `auth`'s scope with `secretAccessKey`. */
export function signatureFor(
  req: SignableRequest,
  auth: Pick<SigV4Authorization, 'date' | 'region' | 'service'>,
  signedHeaders: readonly string[],
  payloadHash: string,
  secretAccessKey: string,
): string {
  const amzDate = amzDateOf(req) ?? '';
  const scope = `${auth.date}/${auth.region}/${auth.service}/aws4_request`;
  const sts = stringToSign(amzDate, scope, canonicalRequest(req, signedHeaders, payloadHash, auth.service));
  return createHmac('sha256', deriveSigningKey(secretAccessKey, auth.date, auth.region, auth.service)).update(sts, 'utf8').digest('hex');
}

const HEX_HASH = /^[0-9a-f]{64}$/i;

/**
 * How the payload is hashed. A `x-amz-content-sha256` header is the hash
 * (hex, `UNSIGNED-PAYLOAD`, `STREAMING-UNSIGNED-PAYLOAD-TRAILER`): the body is
 * not needed, and streams. Without it (every non-S3 service) the body is
 * buffered and hashed. Per-chunk signed streaming payloads can't be re-signed.
 */
export function payloadMode(req: SignableRequest): { kind: 'header'; value: string } | { kind: 'body' } | { kind: 'unsignable'; reason: SigV4Unsignable } {
  const values = headerValues(req, 'x-amz-content-sha256');
  if (values.length > 1) return { kind: 'unsignable', reason: 'repeated-payload-hash' };
  if (values.length === 0) return { kind: 'body' };
  if (/^STREAMING-AWS4-/i.test(values[0])) return { kind: 'unsignable', reason: 'streaming-signed-payload' };
  return { kind: 'header', value: values[0] };
}

/** Result of re-signing: the outgoing headers, or a refusal. */
export type FinalizeResult =
  | { ok: true; headers: Array<[string, string]> }
  | { ok: false; reason: 'signature-mismatch' };

const SECURITY_TOKEN = 'x-amz-security-token';

/**
 * Verify that the agent signed `received` with the ticket as its secret key,
 * then sign `outgoing` with the real credential. The real access key id goes
 * into the scope; the session token (if any) is set and signed, and one the
 * agent sent is replaced or removed to match the credential.
 */
export function finalizeSigV4(
  auth: SigV4Authorization,
  ticketId: string,
  credential: SigV4Credential,
  received: SigningView,
  outgoing: SigningView,
): FinalizeResult {
  const mode = payloadMode(received.request);
  const bodyHash = (body: Buffer | undefined) => sha256Hex(body ?? Buffer.alloc(0));
  const receivedHash = mode.kind === 'header' ? mode.value : bodyHash(received.body);
  const expected = signatureFor(received.request, auth, auth.signedHeaders, receivedHash, ticketId);
  if (!timingSafeEqual(Buffer.from(expected, 'hex'), Buffer.from(auth.signature, 'hex'))) {
    return { ok: false, reason: 'signature-mismatch' };
  }

  // A swap_body ticket changed a body whose hash is in the head: the header follows the body.
  let headers = outgoing.request.headers.filter(([n]) => n.toLowerCase() !== SECURITY_TOKEN);
  let outgoingHash = mode.kind === 'header' ? mode.value : bodyHash(outgoing.body);
  if (mode.kind === 'header' && HEX_HASH.test(mode.value) && received.body && outgoing.body && !received.body.equals(outgoing.body)) {
    outgoingHash = bodyHash(outgoing.body);
    headers = headers.map(([n, v]) => (n.toLowerCase() === 'x-amz-content-sha256' ? [n, ` ${outgoingHash}`] : [n, v]));
  }

  const signed = new Set(auth.signedHeaders.filter(h => h !== SECURITY_TOKEN));
  if (credential.sessionToken !== undefined) {
    signed.add(SECURITY_TOKEN);
    headers.push(['X-Amz-Security-Token', ` ${credential.sessionToken}`]);
  }
  const signedHeaders = [...signed].sort();
  const request = { ...outgoing.request, headers };
  const signature = signatureFor(request, auth, signedHeaders, outgoingHash, credential.secretAccessKey);
  const authorization = `${SIGV4_ALGORITHM} Credential=${credential.accessKeyId}/${auth.date}/${auth.region}/${auth.service}/aws4_request, ` +
    `SignedHeaders=${signedHeaders.join(';')}, Signature=${signature}`;

  const at = headers.findIndex(([n]) => n.toLowerCase() === 'authorization');
  if (at === -1) headers.push(['Authorization', ` ${authorization}`]);
  else headers[at] = [headers[at][0], ` ${authorization}`];
  return { ok: true, headers };
}
