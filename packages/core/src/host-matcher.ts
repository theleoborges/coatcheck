import net from 'node:net';
import { domainToASCII } from 'node:url';
import { isValidHostname } from './connect-target.js';

/**
 * Allowed-host patterns (design: docs/design/v1-decisions.md §3 "Matching").
 *
 * - `api.example.com`: exact host, HTTPS only.
 * - `*.example.com`: any subdomain at any depth, never the apex; at least two
 *   labels after `*.`.
 * - `http://host` (exact or wildcard): also allows plaintext HTTP.
 * - IP literals match exactly; no wildcards.
 * Entries are normalised (lowercase, no trailing dot, punycode). Ports and
 * paths are not allowed in entries; target ports are ignored.
 */
export interface HostPattern {
  kind: 'exact' | 'wildcard';
  /** Exact host, or the suffix after `*.` for wildcards. */
  host: string;
  /** True for `http://` entries: plaintext HTTP is allowed too. */
  plaintext: boolean;
}

export interface MatchTarget {
  host: string;
  scheme: 'http' | 'https';
}

/**
 * Parse one allowed-host entry. Returns the pattern, or an error message.
 * Takes `unknown` so callers can pass raw JSON (policy file, in-band
 * `_allowed_hosts`) without their own type check.
 */
export function parseHostPattern(entry: unknown): HostPattern | string {
  if (typeof entry !== 'string') return 'must be a string';
  if (entry.trim() !== entry || entry === '') {
    return 'must be a non-empty string without surrounding whitespace';
  }
  let rest = entry;
  let plaintext = false;
  if (rest.toLowerCase().startsWith('http://')) {
    plaintext = true;
    rest = rest.slice('http://'.length);
  }
  if (rest.includes('://')) return 'only the http:// scheme prefix is allowed (HTTPS is implied)';
  if (rest.includes('/')) return 'must not contain a path';

  if (rest.startsWith('[') && rest.endsWith(']')) {
    const ip = normaliseHost(rest.slice(1, -1));
    return ip !== null && net.isIPv6(ip) ? { kind: 'exact', host: ip, plaintext } : 'brackets are only allowed around an IPv6 address';
  }
  if (net.isIP(rest)) {
    const ip = normaliseHost(rest);
    return ip === null ? 'is not a valid IP address (IPv6 zone IDs are not allowed)' : { kind: 'exact', host: ip, plaintext };
  }
  if (rest.includes(':')) return 'must not contain a port (ports are ignored when matching)';

  let kind: HostPattern['kind'] = 'exact';
  if (rest.startsWith('*.')) {
    kind = 'wildcard';
    rest = rest.slice(2);
  }
  if (rest.includes('*')) return "'*' is only allowed as a leading '*.' label";

  const host = normaliseHost(rest);
  if (host === null) return 'is not a valid hostname';
  if (kind === 'wildcard') {
    if (net.isIP(host)) return 'wildcards cannot apply to IP addresses';
    if (host.split('.').length < 2) return 'wildcard is too broad: needs at least two labels after "*."';
  }
  return { kind, host, plaintext };
}

/**
 * Lowercase, strip one trailing dot, convert to punycode, validate. IPv6 is
 * canonicalised the way the WHATWG URL parser does it (`2001:0DB8::0001` ->
 * `2001:db8::1`), so patterns and targets compare equal; zone IDs are refused.
 * Null if invalid.
 */
export function normaliseHost(host: string): string | null {
  const trimmed = host.toLowerCase().replace(/\.$/, '');
  if (net.isIPv6(trimmed)) {
    const canonical = domainToASCII(`[${trimmed}]`);
    return canonical === '' ? null : canonical.slice(1, -1);
  }
  if (net.isIPv4(trimmed)) return trimmed;
  // domainToASCII parses its input as a URL host and silently drops anything
  // after a delimiter ('api.example.com/evil' -> 'api.example.com'), so refuse
  // URL syntax before converting.
  if (/[/\\?#@:%\s[\]]/.test(trimmed)) return null;
  const ascii = domainToASCII(trimmed);
  return ascii !== '' && isValidHostname(ascii) ? ascii : null;
}

/** True when `target` is allowed by any pattern. */
export function matchesHost(patterns: readonly HostPattern[], target: MatchTarget): boolean {
  let host = target.host;
  if (host.startsWith('[') && host.endsWith(']')) host = host.slice(1, -1);
  const normalised = normaliseHost(host);
  if (normalised === null) return false;

  return patterns.some(p => {
    if (target.scheme === 'http' && !p.plaintext) return false;
    if (p.kind === 'exact') return normalised === p.host;
    return normalised.endsWith(`.${p.host}`);
  });
}

/** The entry as an operator would write it (`*.example.com`, `http://host`, `[::1]`). */
export function formatHostPattern(p: HostPattern): string {
  const host = net.isIPv6(p.host) ? `[${p.host}]` : p.host;
  return `${p.plaintext ? 'http://' : ''}${p.kind === 'wildcard' ? '*.' : ''}${host}`;
}

/**
 * Patterns allowing exactly the targets that both `a` and `b` allow (design §3,
 * "Host binding details"). Plaintext survives only when both sides allow it.
 */
export function intersectHostPatterns(a: readonly HostPattern[], b: readonly HostPattern[]): HostPattern[] {
  // Keyed by kind + host; `http://x` implies `x`, so duplicates merge by OR-ing plaintext.
  const out = new Map<string, HostPattern>();
  for (const x of a) {
    for (const y of b) {
      const p = intersectOne(x, y);
      if (!p) continue;
      const key = `${p.kind}:${p.host}`;
      const prev = out.get(key);
      out.set(key, prev ? { ...p, plaintext: prev.plaintext || p.plaintext } : p);
    }
  }
  return [...out.values()];
}

function intersectOne(a: HostPattern, b: HostPattern): HostPattern | null {
  const plaintext = a.plaintext && b.plaintext;
  if (a.kind === 'exact' && b.kind === 'exact') return a.host === b.host ? { kind: 'exact', host: a.host, plaintext } : null;
  if (a.kind === 'exact') return covers(b.host, a.host) ? { kind: 'exact', host: a.host, plaintext } : null;
  if (b.kind === 'exact') return covers(a.host, b.host) ? { kind: 'exact', host: b.host, plaintext } : null;
  // Both wildcards: the narrower one, when one suffix sits inside the other.
  if (a.host === b.host || covers(b.host, a.host)) return { kind: 'wildcard', host: a.host, plaintext };
  if (covers(a.host, b.host)) return { kind: 'wildcard', host: b.host, plaintext };
  return null;
}

/** True when `*.suffix` matches `host` (a strict subdomain). */
function covers(suffix: string, host: string): boolean {
  return host.endsWith(`.${suffix}`);
}
