import type { MatchTarget } from './host-matcher.js';
import { TICKET_PREFIX, type SwapResult, type TokenStore } from './token-store.js';
import { headerFieldValue } from './value-encoding.js';

const BASIC_CREDENTIALS = /^(basic[ \t]+)([A-Za-z0-9+/]+={0,2})([ \t]*)$/i;
const AUTHORIZATION_FIELD = /^(authorization:[ \t]*)(.*)$/i;

/** A Basic swap's outcome; `userPass` is the decoded credential after the swap, for spotting un-swapped literals in logs. */
export type BasicSwapResult = SwapResult & { userPass: string };

/**
 * Swap tickets inside an `Authorization: Basic` credential (RFC 7617). The
 * user-pass is base64-encoded, so a ticket in it (`curl -u user:cct_…`, git
 * credential helpers) never appears as a literal: it is decoded, swapped
 * against `target` like any header value, and re-encoded. Host binding and
 * the whole-request deny apply as in `TokenStore.replaceAll`.
 *
 * A real value that can't be represented is reported in `invalid`: a control
 * character, or a `:` in the user-id, which would move the user/password split.
 *
 * Returns null when `value` is not a canonical Basic credential holding a
 * ticket prefix; the caller leaves it as is.
 */
export function swapBasicCredentials(store: TokenStore, value: string, target: MatchTarget): BasicSwapResult | null {
  const m = BASIC_CREDENTIALS.exec(value);
  if (!m) return null;
  const [, scheme, encoded, trailing] = m;
  const decoded = Buffer.from(encoded, 'base64').toString('utf8');
  // Node's decoder is lenient (bad padding, invalid UTF-8): only a canonical
  // encoding is opened, so the credential swapped is the one the upstream reads.
  if (Buffer.from(decoded, 'utf8').toString('base64') !== encoded || !decoded.includes(TICKET_PREFIX)) return null;

  const colon = decoded.indexOf(':');
  const user = store.replaceAll(colon === -1 ? decoded : decoded.slice(0, colon), target,
    v => (v.includes(':') ? null : headerFieldValue(v)));
  const pass = colon === -1 ? null : store.replaceAll(decoded.slice(colon + 1), target, headerFieldValue);

  const parts = pass ? [user, pass] : [user];
  const denied = parts.flatMap(p => p.denied);
  const invalid = parts.flatMap(p => p.invalid ?? []);
  if (denied.length > 0 || invalid.length > 0) {
    return { output: value, userPass: decoded, swaps: [], denied, ...(invalid.length > 0 ? { invalid } : {}) };
  }
  const swapped = pass ? `${user.output}:${pass.output}` : user.output;
  const output = `${scheme}${Buffer.from(swapped, 'utf8').toString('base64')}${trailing}`;
  return { output, userPass: swapped, swaps: parts.flatMap(p => p.swaps), denied };
}

/** `swapBasicCredentials` on a raw `Authorization:` field line (MITM path); null for any other line. */
export function swapBasicFieldLine(store: TokenStore, line: string, target: MatchTarget): BasicSwapResult | null {
  const m = AUTHORIZATION_FIELD.exec(line);
  if (!m) return null;
  const r = swapBasicCredentials(store, m[2], target);
  return r && { ...r, output: m[1] + r.output };
}
