import { formatHostPattern, intersectHostPatterns, parseHostPattern, type HostPattern } from './host-matcher.js';

/**
 * A secret value as coatcheck reads it (design: docs/design/v1-decisions.md §3).
 * - `simple`: one value. Also a JSON object whose only non-underscore key is
 *   `value`, so a single-value secret can carry metadata such as `_allowed_hosts`.
 * - `multi`: a JSON object of fields; keys starting with `_` are metadata.
 */
export type SecretValue =
  | { kind: 'simple'; value: string; inBand: InBandMetadata }
  | { kind: 'multi'; fields: Record<string, unknown>; inBand: InBandMetadata };

/** Where a secret may be swapped, beyond `Authorization` (design §3, "Swap placement"). */
export interface SwapSettings {
  swapBody?: boolean;
  swapUrl?: boolean;
  /** Extra header names (lowercase) whose values a ticket is swapped in. */
  swapHeaders?: string[];
}

/**
 * In-band `_allowed_hosts`, `_swap_body`, `_swap_url` and `_swap_headers`:
 * each absent or parsed, or an error when any is invalid (fails minting with 500).
 */
export type InBandMetadata = ({ hosts?: HostPattern[] } & SwapSettings) | { error: string };

/** Headers a ticket is always swapped in; any other placement is opt-in per secret. */
export const DEFAULT_SWAP_HEADERS: readonly string[] = ['authorization', 'proxy-authorization'];

// RFC 9110 §5.6.2 token.
const HEADER_NAME = /^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/;

/**
 * Parse a `swap_headers` list: non-empty header names, lowercased and
 * deduplicated. `host` is refused (a real value must never steer routing).
 * Returns an error message for an invalid list.
 */
export function parseSwapHeaders(v: unknown): string[] | string {
  if (!Array.isArray(v) || v.length === 0) return 'must be a non-empty array of header names';
  const out = new Set<string>();
  for (const [i, item] of v.entries()) {
    if (typeof item !== 'string' || !HEADER_NAME.test(item)) return `[${i}] ${JSON.stringify(item)}: not a header name`;
    const name = item.toLowerCase();
    if (name === 'host') return `[${i}] "host": a value can't be swapped into Host`;
    out.add(name);
  }
  return [...out];
}

export function parseSecretValue(raw: string): SecretValue {
  let obj: unknown;
  try {
    obj = JSON.parse(raw);
  } catch {
    return { kind: 'simple', value: raw, inBand: {} };
  }
  if (!obj || typeof obj !== 'object' || Array.isArray(obj)) return { kind: 'simple', value: raw, inBand: {} };

  const fields = obj as Record<string, unknown>;
  const inBand = parseInBand(fields);
  const keys = userFields(fields);
  if (keys.length === 1 && keys[0] === 'value' && typeof fields.value === 'string') {
    return { kind: 'simple', value: fields.value, inBand };
  }
  return { kind: 'multi', fields, inBand };
}

/** Field names an agent may see and request: everything but `_`-prefixed metadata. */
export function userFields(fields: Record<string, unknown>): string[] {
  return Object.keys(fields).filter(k => !k.startsWith('_'));
}

function parseInBand(fields: Record<string, unknown>): InBandMetadata {
  const out: { hosts?: HostPattern[] } & SwapSettings = {};
  const v = fields._allowed_hosts;
  if (v !== undefined) {
    if (!Array.isArray(v) || v.length === 0) return { error: '_allowed_hosts must be a non-empty array of host patterns' };
    const hosts: HostPattern[] = [];
    for (const [i, item] of v.entries()) {
      const p = parseHostPattern(item);
      if (typeof p === 'string') return { error: `_allowed_hosts[${i}] ${JSON.stringify(item)}: ${p}` };
      hosts.push(p);
    }
    out.hosts = hosts;
  }
  if (fields._swap_body !== undefined) {
    if (typeof fields._swap_body !== 'boolean') return { error: '_swap_body must be true or false' };
    out.swapBody = fields._swap_body;
  }
  if (fields._swap_url !== undefined) {
    if (typeof fields._swap_url !== 'boolean') return { error: '_swap_url must be true or false' };
    out.swapUrl = fields._swap_url;
  }
  if (fields._swap_headers !== undefined) {
    const headers = parseSwapHeaders(fields._swap_headers);
    if (typeof headers === 'string') return { error: `_swap_headers ${headers}` };
    out.swapHeaders = headers;
  }
  return out;
}

/** Where a ticket is swapped, snapshotted at mint (see `SwapSettings`). */
export interface Placement {
  swapBody: boolean;
  swapUrl: boolean;
  /** Extra header names beyond `DEFAULT_SWAP_HEADERS`, lowercase, sorted. */
  swapHeaders: string[];
}

/** The outcome of resolving a secret's effective hosts at mint time. */
export type Binding =
  | ({ ok: true; allowedHosts: HostPattern[] | undefined } & Placement)
  | { ok: false; status: 403 | 500; error: string };

/**
 * Effective allowed hosts: the intersection of the policy file's hosts and the
 * in-band `_allowed_hosts`, whichever are present. Unbound secrets are refused
 * unless `allowUnbound`; so are secrets whose two sources share no host.
 * Body and URL swapping are each on when either source enables it and neither
 * disables it. Extra swap headers, like hosts, are the intersection of both
 * lists when both are present, so a secret can narrow the operator's list but
 * never widen it.
 */
export function resolveBinding(
  secretName: string,
  policyHosts: HostPattern[] | undefined,
  inBand: InBandMetadata,
  allowUnbound: boolean,
  policySwap: SwapSettings = {},
): Binding {
  if ('error' in inBand) {
    return { ok: false, status: 500, error: `Secret '${secretName}' has an invalid ${inBand.error}` };
  }
  const own = inBand.hosts;
  const enabled = (a: boolean | undefined, b: boolean | undefined) => [a, b].includes(true) && ![a, b].includes(false);
  const policyHeaders = policySwap.swapHeaders;
  const ownHeaders = inBand.swapHeaders;
  const headers = policyHeaders && ownHeaders ? policyHeaders.filter(h => ownHeaders.includes(h)) : policyHeaders ?? ownHeaders ?? [];
  const placement: Placement = {
    swapBody: enabled(policySwap.swapBody, inBand.swapBody),
    swapUrl: enabled(policySwap.swapUrl, inBand.swapUrl),
    swapHeaders: headers.filter(h => !DEFAULT_SWAP_HEADERS.includes(h)).sort(),
  };
  const hosts = policyHosts && own ? intersectHostPatterns(policyHosts, own) : policyHosts ?? own;
  if (hosts === undefined) {
    if (allowUnbound) return { ok: true, allowedHosts: undefined, ...placement };
    return {
      ok: false,
      status: 403,
      error: `Secret '${secretName}' is not bound to any host: list it in the policy file or give it an _allowed_hosts field`,
    };
  }
  if (hosts.length === 0) {
    return {
      ok: false,
      status: 403,
      error: `Secret '${secretName}' has no host allowed by both the policy file and its _allowed_hosts`,
    };
  }
  return { ok: true, allowedHosts: hosts, ...placement };
}

/** `allowed_hosts` for a mint response: entries as written, or null when unbound. */
export function allowedHostsJson(hosts: readonly HostPattern[] | undefined): string[] | null {
  return hosts ? hosts.map(formatHostPattern) : null;
}
