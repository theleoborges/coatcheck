import net from 'node:net';

export interface ConnectTarget {
  /** Lowercased DNS name or IP literal (IPv6 without brackets). */
  hostname: string;
  port: number;
}

const MAX_HOSTNAME_LENGTH = 253;
const DNS_LABEL = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
const PORT = /^[0-9]{1,5}$/;

/**
 * Parse a CONNECT request target (`host:port`, or `[v6]:port`) strictly.
 *
 * The hostname is later used to mint a leaf certificate and to dial upstream,
 * so anything that is not an RFC 1123 DNS name or an IP literal is rejected:
 * shell metacharacters, path separators, `..`, empty or over-long labels.
 * Returns null when the target is invalid; callers answer 400.
 */
export function parseConnectTarget(target: string | undefined): ConnectTarget | null {
  if (!target) return null;

  let host: string;
  let portStr: string;
  if (target.startsWith('[')) {
    const close = target.indexOf(']');
    if (close === -1 || target[close + 1] !== ':') return null;
    host = target.slice(1, close);
    portStr = target.slice(close + 2);
    if (!net.isIPv6(host)) return null;
  } else {
    const colon = target.lastIndexOf(':');
    if (colon === -1 || target.indexOf(':') !== colon) return null;
    host = target.slice(0, colon);
    portStr = target.slice(colon + 1);
  }

  if (!PORT.test(portStr)) return null;
  const port = parseInt(portStr, 10);
  if (port < 1 || port > 65535) return null;

  if (net.isIPv6(host)) return { hostname: host.toLowerCase(), port };
  if (net.isIPv4(host)) return { hostname: host, port };

  const hostname = host.toLowerCase().replace(/\.$/, '');
  if (hostname.length === 0 || hostname.length > MAX_HOSTNAME_LENGTH) return null;
  if (!hostname.split('.').every(label => DNS_LABEL.test(label))) return null;
  // A dotted string of digits that is not a valid IPv4 literal (e.g. 999.1.1.1)
  // would otherwise pass as a DNS name.
  if (/^[0-9.]+$/.test(hostname)) return null;
  return { hostname, port };
}
