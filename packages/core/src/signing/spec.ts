import { headerFieldValue } from '../value-encoding.js';
import type { SecretValue } from '../secret-binding.js';
import { decodeHmacKey, hmacRecipeJson, parseHmacRecipe, type HmacRecipe } from './hmac.js';
import type { SigningCredential } from './types.js';

/**
 * A secret's signing scheme, from the policy file's `signing` or the
 * secret's in-band `_signing` (design: docs/design/signing-processors.md §3):
 * `"aws-sigv4"`, or an HMAC recipe object (§5).
 */
export type SigningSpec = { type: 'aws-sigv4' } | HmacRecipe;

/** Parse a `signing` / `_signing` value. Returns an error message when invalid. */
export function parseSigningSpec(v: unknown): SigningSpec | string {
  if (v === 'aws-sigv4') return { type: 'aws-sigv4' };
  if (typeof v === 'object' && v !== null && !Array.isArray(v)) {
    const recipe = parseHmacRecipe(v);
    return typeof recipe === 'string' ? `(hmac recipe): ${recipe}` : recipe;
  }
  return 'must be "aws-sigv4" or an HMAC recipe object ({"type": "hmac", …})';
}

/** The `signing` field of a mint response: the public part of the spec, never key material. */
export function signingSpecJson(spec: SigningSpec): unknown {
  return spec.type === 'hmac' ? hmacRecipeJson(spec) : spec.type;
}

/** Field names that hold the signing key: `?field=` refuses them (a literal ticket would be a copy of the key). */
export function keyFields(spec: SigningSpec): readonly string[] {
  switch (spec.type) {
    case 'aws-sigv4': return ['secret_access_key', 'SecretAccessKey'];
    case 'hmac': return ['secret'];
  }
}

// An access key id sits in the credential scope (`<id>/<date>/…`) of a header value.
const ACCESS_KEY_ID = /^[^\s/,;=]+$/;

/** A string that can be a whole header field value: no control characters, no surrounding whitespace. */
const headerSafe = (v: string) => headerFieldValue(v) !== null && v.trim() === v && v !== '';

/**
 * The signing credential from a secret. AWS accepts both
 * `aws configure export-credentials` casing and snake_case. HMAC takes a
 * simple secret (the key) or `{"key_id": …, "secret": …}`. An error message
 * when a required field is missing or can't be sent (fails minting with 500;
 * no ticket is issued).
 */
export function signingCredentialFrom(spec: SigningSpec, secret: SecretValue): SigningCredential | string {
  const fields = secret.kind === 'multi' ? secret.fields : null;
  switch (spec.type) {
    case 'aws-sigv4': {
      const pick = (snake: string, pascal: string) => fields?.[snake] ?? fields?.[pascal];
      const accessKeyId = pick('access_key_id', 'AccessKeyId');
      const secretAccessKey = pick('secret_access_key', 'SecretAccessKey');
      const sessionToken = pick('session_token', 'SessionToken');
      if (typeof accessKeyId !== 'string' || !ACCESS_KEY_ID.test(accessKeyId)) {
        return 'aws-sigv4 secret needs an access_key_id (or AccessKeyId) without whitespace, "/", ",", ";" or "="';
      }
      if (typeof secretAccessKey !== 'string' || secretAccessKey === '') {
        return 'aws-sigv4 secret needs a secret_access_key (or SecretAccessKey)';
      }
      if (sessionToken !== undefined && sessionToken !== null && sessionToken !== '') {
        if (typeof sessionToken !== 'string' || !headerSafe(sessionToken)) {
          return 'aws-sigv4 session_token (or SessionToken) must be a string that can be sent in a header';
        }
        return { scheme: 'aws-sigv4', accessKeyId, secretAccessKey, sessionToken };
      }
      return { scheme: 'aws-sigv4', accessKeyId, secretAccessKey };
    }
    case 'hmac': {
      const raw = secret.kind === 'simple' ? secret.value : fields?.secret;
      if (typeof raw !== 'string' || raw === '') return 'hmac secret needs a value, or a "secret" field';
      const key = decodeHmacKey(raw, spec.keyEncoding);
      if (!key) return `hmac secret is not valid ${spec.keyEncoding} (key_encoding)`;
      const keyId = fields?.key_id;
      if (keyId === undefined) return { scheme: 'hmac', recipe: spec, key };
      if (typeof keyId !== 'string' || !headerSafe(keyId)) return 'hmac key_id must be a string that can be sent in a header';
      return { scheme: 'hmac', recipe: spec, key, keyId };
    }
  }
}
