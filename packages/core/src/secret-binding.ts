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

/**
 * In-band `_allowed_hosts` and `_swap_body`: each absent or parsed, or an
 * error when either is invalid (fails minting with 500).
 */
export type InBandMetadata = { hosts?: HostPattern[]; swapBody?: boolean } | { error: string };

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
  const out: { hosts?: HostPattern[]; swapBody?: boolean } = {};
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
  return out;
}

/** The outcome of resolving a secret's effective hosts at mint time. */
export type Binding =
  | { ok: true; allowedHosts: HostPattern[] | undefined; swapBody: boolean }
  | { ok: false; status: 403 | 500; error: string };

/**
 * Effective allowed hosts: the intersection of the policy file's hosts and the
 * in-band `_allowed_hosts`, whichever are present. Unbound secrets are refused
 * unless `allowUnbound`; so are secrets whose two sources share no host.
 * Body swapping is on when either source enables it and neither disables it.
 */
export function resolveBinding(
  secretName: string,
  policyHosts: HostPattern[] | undefined,
  inBand: InBandMetadata,
  allowUnbound: boolean,
  policySwapBody?: boolean,
): Binding {
  if ('error' in inBand) {
    return { ok: false, status: 500, error: `Secret '${secretName}' has an invalid ${inBand.error}` };
  }
  const own = inBand.hosts;
  const settings = [policySwapBody, inBand.swapBody];
  const swapBody = settings.includes(true) && !settings.includes(false);
  const hosts = policyHosts && own ? intersectHostPatterns(policyHosts, own) : policyHosts ?? own;
  if (hosts === undefined) {
    if (allowUnbound) return { ok: true, allowedHosts: undefined, swapBody };
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
  return { ok: true, allowedHosts: hosts, swapBody };
}

/** `allowed_hosts` for a mint response: entries as written, or null when unbound. */
export function allowedHostsJson(hosts: readonly HostPattern[] | undefined): string[] | null {
  return hosts ? hosts.map(formatHostPattern) : null;
}
