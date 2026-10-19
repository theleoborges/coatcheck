import { parseHostPattern, type HostPattern } from './host-matcher.js';
import { isValidSecretName } from './secret-provider.js';
import { parseSwapHeaders, type SwapSettings } from './secret-binding.js';
import { parseSigningSpec } from './signing/spec.js';

/**
 * The operator's policy file (`COATCHECK_POLICY_FILE`): allowed hosts per secret
 * and the shared-secret allowlist. Design: docs/design/v1-decisions.md §3.
 */
export interface Policy {
  /** Per-agent secrets: exact names, or a prefix ending in `*`. */
  secrets: PolicyRule[];
  /** Shared secrets (exact names). Listed here = allowlisted for `/_secret/*`. */
  shared: ReadonlyMap<string, SharedRule>;
}

/**
 * Explicit `swap_body`, `swap_url` and `swap_headers` (where a ticket is
 * swapped, design §3) and `signing` (docs/design/signing-processors.md §3)
 * are each undefined when absent.
 */
export interface SharedRule extends SwapSettings {
  allowedHosts: HostPattern[];
}

export interface PolicyRule extends SwapSettings {
  /** Exact name, or prefix when `wildcard`. */
  name: string;
  wildcard: boolean;
  allowedHosts: HostPattern[];
}

export const EMPTY_POLICY: Policy = { secrets: [], shared: new Map() };

type Json = unknown;

/** Parse and validate policy JSON. Collects every problem into `problems`. */
export function parsePolicy(text: string, problems: string[], source = 'policy file'): Policy {
  let raw: Json;
  try {
    raw = JSON.parse(text);
  } catch (err) {
    problems.push(`${source}: invalid JSON (${(err as Error).message})`);
    return EMPTY_POLICY;
  }
  if (!isObject(raw)) {
    problems.push(`${source}: must be a JSON object`);
    return EMPTY_POLICY;
  }
  for (const key of Object.keys(raw)) {
    if (key !== 'secrets' && key !== 'shared') problems.push(`${source}: unknown key '${key}' (allowed: secrets, shared)`);
  }

  const secrets: PolicyRule[] = [];
  for (const [name, entry] of section(raw.secrets, 'secrets', source, problems)) {
    const wildcard = name.endsWith('*');
    const base = wildcard ? name.slice(0, -1) : name;
    if (wildcard && base === '') {
      problems.push(`${source}: secrets["*"]: a bare '*' would bind every secret; list names or prefixes`);
      continue;
    }
    // A non-empty prefix of a valid name is itself a valid name, so one check covers both forms.
    if (!isValidSecretName(base)) {
      problems.push(`${source}: secrets["${name}"]: invalid secret name or pattern (a trailing '*' is the only wildcard)`);
      continue;
    }
    const hosts = allowedHosts(entry, `secrets["${name}"]`, source, problems);
    const swap = swapSettingsOf(entry, `secrets["${name}"]`, source, problems);
    if (hosts) secrets.push({ name: base, wildcard, allowedHosts: hosts, ...swap });
  }

  const shared = new Map<string, SharedRule>();
  for (const [name, entry] of section(raw.shared, 'shared', source, problems)) {
    if (!isValidSecretName(name)) {
      problems.push(`${source}: shared["${name}"]: shared secrets must be exact, valid names`);
      continue;
    }
    const hosts = allowedHosts(entry, `shared["${name}"]`, source, problems);
    const swap = swapSettingsOf(entry, `shared["${name}"]`, source, problems);
    if (hosts) shared.set(name, { allowedHosts: hosts, ...swap });
  }

  return { secrets, shared };
}

/**
 * The rule for a per-agent secret, or undefined when none matches. An exact
 * name beats any wildcard; among wildcards the longest prefix wins.
 */
export function policyRuleFor(policy: Policy, secretName: string): PolicyRule | undefined {
  let best: PolicyRule | undefined;
  for (const rule of policy.secrets) {
    if (!rule.wildcard) {
      if (rule.name === secretName) return rule;
      continue;
    }
    if (secretName.startsWith(rule.name) && (!best || rule.name.length > best.name.length)) best = rule;
  }
  return best;
}

/** Allowed-host patterns for a per-agent secret, or undefined when no rule matches. */
export function policyHostsFor(policy: Policy, secretName: string): HostPattern[] | undefined {
  return policyRuleFor(policy, secretName)?.allowedHosts;
}

/** Every host pattern the policy names (per-agent rules and shared secrets). */
export function allPolicyHosts(policy: Policy): HostPattern[] {
  return [...policy.secrets.flatMap(r => r.allowedHosts), ...[...policy.shared.values()].flatMap(r => r.allowedHosts)];
}

function isObject(v: Json): v is Record<string, Json> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

function section(v: Json, key: string, source: string, problems: string[]): Array<[string, Json]> {
  if (v === undefined) return [];
  if (!isObject(v)) {
    problems.push(`${source}: '${key}' must be an object keyed by secret name`);
    return [];
  }
  return Object.entries(v);
}

function allowedHosts(entry: Json, where: string, source: string, problems: string[]): HostPattern[] | null {
  if (!isObject(entry)) {
    problems.push(`${source}: ${where}: must be an object with 'allowed_hosts'`);
    return null;
  }
  for (const key of Object.keys(entry)) {
    if (!ENTRY_KEYS.includes(key)) {
      problems.push(`${source}: ${where}: unknown key '${key}' (allowed: ${ENTRY_KEYS.join(', ')})`);
    }
  }
  const list = entry.allowed_hosts;
  if (!Array.isArray(list) || list.length === 0) {
    problems.push(`${source}: ${where}.allowed_hosts must be a non-empty array of host patterns`);
    return null;
  }
  const out: HostPattern[] = [];
  list.forEach((item, i) => {
    const parsed = parseHostPattern(item);
    if (typeof parsed === 'string') problems.push(`${source}: ${where}.allowed_hosts[${i}] ${JSON.stringify(item)}: ${parsed}`);
    else out.push(parsed);
  });
  return out.length === list.length ? out : null;
}

const ENTRY_KEYS = ['allowed_hosts', 'swap_body', 'swap_url', 'swap_headers', 'signing'];

/** The entry's explicit swap settings; keys that are absent or invalid are left out. */
function swapSettingsOf(entry: Json, where: string, source: string, problems: string[]): SwapSettings {
  const out: SwapSettings = {};
  if (!isObject(entry)) return out;
  for (const [key, field] of [['swap_body', 'swapBody'], ['swap_url', 'swapUrl']] as const) {
    if (entry[key] === undefined) continue;
    if (typeof entry[key] !== 'boolean') problems.push(`${source}: ${where}.${key} must be true or false`);
    else out[field] = entry[key];
  }
  if (entry.swap_headers !== undefined) {
    const headers = parseSwapHeaders(entry.swap_headers);
    if (typeof headers === 'string') problems.push(`${source}: ${where}.swap_headers ${headers}`);
    else out.swapHeaders = headers;
  }
  if (entry.signing !== undefined) {
    const signing = parseSigningSpec(entry.signing);
    if (typeof signing === 'string') problems.push(`${source}: ${where}.signing ${signing}`);
    else out.signing = signing;
  }
  return out;
}
