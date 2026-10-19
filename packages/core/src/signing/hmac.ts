import { createHmac, timingSafeEqual } from 'node:crypto';
import { headerValues, type SignableRequest, type SigningView } from './request.js';
import type { FinalizeResult } from './sigv4.js';

/**
 * HMAC recipes (design: docs/design/signing-processors.md §5): the operator
 * declares what is signed, with which hash, into which header. Pure:
 * `node:crypto` only. Nothing here logs; callers must never log a message,
 * signature or key.
 */

export type HmacHash = 'sha256' | 'sha384' | 'sha512' | 'sha1';
export type HmacPart =
  | { kind: 'method' } | { kind: 'path' } | { kind: 'query' } | { kind: 'path_query' } | { kind: 'body' }
  | { kind: 'header'; name: string } | { kind: 'literal'; text: string };

export interface HmacRecipe {
  type: 'hmac';
  hash: HmacHash;
  /** Lowercase. Where the ticket arrives; replaced by `key_id`, or removed. */
  keyHeader: string;
  /** Lowercase. Overwritten with the real signature. */
  signatureHeader: string;
  encoding: 'hex' | 'base64';
  keyEncoding: 'utf8' | 'base64' | 'hex';
  message: HmacPart[];
  verify: boolean;
  /** Header names as the operator wrote them (for the mint response). */
  written: { keyHeader: string; signatureHeader: string; message: string[] };
}

/** A real HMAC credential as the token store holds it for a signing ticket. */
export interface HmacCredential {
  scheme: 'hmac';
  recipe: HmacRecipe;
  key: Buffer;
  keyId?: string;
}

const KEYS = ['type', 'hash', 'key_header', 'signature_header', 'encoding', 'key_encoding', 'message', 'verify'];
const HASHES: readonly HmacHash[] = ['sha256', 'sha384', 'sha512', 'sha1'];
// RFC 9110 §5.6.2 token.
const HEADER_NAME = /^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/;
const SIMPLE_PARTS = ['method', 'path', 'query', 'path_query', 'body'] as const;
// Headers that frame the message or the connection: a recipe writing or
// removing one would change how the upstream reads the request.
const RESERVED_HEADERS = new Set([
  'host', 'content-length', 'transfer-encoding', 'connection', 'keep-alive', 'te', 'trailer', 'upgrade',
  'proxy-authenticate', 'proxy-authorization', 'proxy-connection',
]);

/** Parse and validate a recipe (strict schema). Returns an error message when invalid. */
export function parseHmacRecipe(v: unknown): HmacRecipe | string {
  if (typeof v !== 'object' || v === null || Array.isArray(v)) return 'must be an object';
  const r = v as Record<string, unknown>;
  for (const key of Object.keys(r)) {
    if (!KEYS.includes(key)) return `unknown key '${key}' (allowed: ${KEYS.join(', ')})`;
  }
  if (r.type !== 'hmac') return 'type must be "hmac"';
  const hash = r.hash ?? 'sha256';
  if (typeof hash !== 'string' || !HASHES.includes(hash as HmacHash)) return `hash must be one of ${HASHES.join(', ')}`;
  const header = (key: string): string | { error: string } => {
    const h = r[key];
    if (typeof h !== 'string' || !HEADER_NAME.test(h)) return { error: `${key} must be a header name` };
    if (RESERVED_HEADERS.has(h.toLowerCase())) return { error: `${key} can't be "${h.toLowerCase()}" (a framing or hop-by-hop header)` };
    return h;
  };
  const keyHeader = header('key_header');
  if (typeof keyHeader !== 'string') return keyHeader.error;
  const signatureHeader = header('signature_header');
  if (typeof signatureHeader !== 'string') return signatureHeader.error;
  if (keyHeader.toLowerCase() === signatureHeader.toLowerCase()) return 'key_header and signature_header must differ';
  const encoding = r.encoding ?? 'hex';
  if (encoding !== 'hex' && encoding !== 'base64') return 'encoding must be "hex" or "base64"';
  const keyEncoding = r.key_encoding ?? 'utf8';
  if (keyEncoding !== 'utf8' && keyEncoding !== 'base64' && keyEncoding !== 'hex') return 'key_encoding must be "utf8", "base64" or "hex"';
  const verify = r.verify ?? true;
  if (typeof verify !== 'boolean') return 'verify must be true or false';
  if (keyEncoding !== 'utf8' && verify) return `key_encoding "${keyEncoding}" needs "verify": false (the agent signs with the ticket as a UTF-8 key)`;
  if (!Array.isArray(r.message) || r.message.length === 0) return 'message must be a non-empty list of parts';
  const message: HmacPart[] = [];
  for (const [i, part] of r.message.entries()) {
    if (typeof part !== 'string') return `message[${i}] must be a string`;
    if ((SIMPLE_PARTS as readonly string[]).includes(part)) message.push({ kind: part as (typeof SIMPLE_PARTS)[number] });
    else if (part.startsWith('header:')) {
      const name = part.slice('header:'.length);
      if (!HEADER_NAME.test(name)) return `message[${i}] ${JSON.stringify(part)}: not a header name`;
      message.push({ kind: 'header', name: name.toLowerCase() });
    } else if (part.startsWith('literal:')) message.push({ kind: 'literal', text: part.slice('literal:'.length) });
    else return `message[${i}] ${JSON.stringify(part)}: one of ${SIMPLE_PARTS.join(', ')}, header:<name>, literal:<text>`;
  }
  return {
    type: 'hmac',
    hash: hash as HmacHash,
    keyHeader: keyHeader.toLowerCase(),
    signatureHeader: signatureHeader.toLowerCase(),
    encoding,
    keyEncoding,
    message,
    verify,
    written: { keyHeader, signatureHeader, message: r.message as string[] },
  };
}

/** The public recipe for a mint response: never the key or `key_id`. */
export function hmacRecipeJson(recipe: HmacRecipe): Record<string, unknown> {
  return {
    type: 'hmac',
    hash: recipe.hash,
    key_header: recipe.written.keyHeader,
    signature_header: recipe.written.signatureHeader,
    encoding: recipe.encoding,
    message: recipe.written.message,
  };
}

/** The stored secret as key bytes, per `key_encoding`; null when it doesn't decode. */
export function decodeHmacKey(secret: string, encoding: HmacRecipe['keyEncoding']): Buffer | null {
  if (encoding === 'utf8') return Buffer.from(secret, 'utf8');
  if (encoding === 'hex') return /^(?:[0-9a-fA-F]{2})+$/.test(secret) ? Buffer.from(secret, 'hex') : null;
  // Standard or URL-safe alphabet, padding optional; anything else isn't a key.
  // Node drops a dangling sextet silently, so a truncated key is refused instead.
  if (!/^[A-Za-z0-9+/_-]+={0,2}$/.test(secret)) return null;
  if (secret.replace(/=+$/, '').length % 4 === 1) return null;
  const b = Buffer.from(secret, 'base64');
  return b.length > 0 ? b : null;
}

/**
 * The message a recipe signs, from a request: parts concatenated as bytes.
 * `method` and `path_query` as sent; repeated headers joined with `,`; a
 * missing header or body is empty. The body is the bytes as sent
 * (content-encoded bodies are hashed as they are).
 */
export function hmacMessage(recipe: HmacRecipe, view: SigningView): Buffer {
  const { request: req } = view;
  const q = req.target.indexOf('?');
  const parts = recipe.message.map((part): Buffer => {
    switch (part.kind) {
      case 'method': return Buffer.from(req.method, 'utf8');
      case 'path': return Buffer.from(q === -1 ? req.target : req.target.slice(0, q), 'utf8');
      case 'query': return Buffer.from(q === -1 ? '' : req.target.slice(q + 1), 'utf8');
      case 'path_query': return Buffer.from(req.target, 'utf8');
      case 'body': return view.body ?? Buffer.alloc(0);
      case 'header': return Buffer.from(headerValues(req, part.name).join(','), 'latin1');
      case 'literal': return Buffer.from(part.text, 'utf8');
    }
  });
  return Buffer.concat(parts);
}

/** The encoded HMAC of `message` under `key`. */
export function hmacSignature(recipe: HmacRecipe, key: Buffer | string, message: Buffer): string {
  return createHmac(recipe.hash, key).update(message).digest(recipe.encoding);
}

/**
 * Verify the agent's HMAC (ticket as key) over `received` unless the recipe
 * says `verify: false`, then sign `outgoing` with the real key: the key
 * header carries `key_id` (or is removed), the signature header the real
 * signature. A recipe that signs the key header sees the ticket on the
 * receive side and `key_id` on the outgoing side.
 */
export function finalizeHmac(ticketId: string, credential: HmacCredential, received: SigningView, outgoing: SigningView): FinalizeResult {
  const { recipe } = credential;
  if (recipe.verify) {
    const sent = headerValues(received.request, recipe.signatureHeader);
    const expected = hmacSignature(recipe, ticketId, hmacMessage(recipe, received));
    // Hex is case-insensitive (some clients send upper case); base64 is not.
    const ours = recipe.encoding === 'hex' ? sent.map(v => v.toLowerCase()) : sent;
    if (ours.length !== 1 || !equal(ours[0], expected)) return { ok: false, reason: 'signature-mismatch' };
  }

  const headers: Array<[string, string]> = [];
  let keySeen = false;
  for (const [name, value] of outgoing.request.headers) {
    const lower = name.toLowerCase();
    if (lower === recipe.signatureHeader) continue;
    if (lower === recipe.keyHeader) {
      if (keySeen || credential.keyId === undefined) continue;
      keySeen = true;
      headers.push([name, ` ${credential.keyId}`]);
      continue;
    }
    headers.push([name, value]);
  }
  const request: SignableRequest = { ...outgoing.request, headers };
  const signature = hmacSignature(recipe, credential.key, hmacMessage(recipe, { request, body: outgoing.body }));
  headers.push([recipe.written.signatureHeader, ` ${signature}`]);
  return { ok: true, headers };
}

/** Constant-time comparison of two encoded signatures. */
function equal(a: string, b: string): boolean {
  const x = Buffer.from(a, 'utf8');
  const y = Buffer.from(b, 'utf8');
  return x.length === y.length && timingSafeEqual(x, y);
}
