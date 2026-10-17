import { createHash, timingSafeEqual } from 'node:crypto';
import type http from 'node:http';

/**
 * `COATCHECK_API_TOKEN` checks (design: docs/design/v1-decisions.md §4, "API
 * token details"). The vault API takes `Authorization: Bearer <token>`; the
 * proxy takes `Proxy-Authorization` as `Bearer <token>` or `Basic` with the
 * token as the password (what clients send for `http://user:token@proxy`).
 */
export interface ApiAuth {
  /** True when the request may use the vault API. */
  vault(req: http.IncomingMessage): boolean;
  /** True when the request may use the proxy (forward or CONNECT). */
  proxy(req: http.IncomingMessage): boolean;
}

/** Vault paths that stay open: health probes and the (public) CA certificate. */
const OPEN_PATHS = new Set(['/_health', '/_ca']);

export function isOpenVaultPath(url: string): boolean {
  return OPEN_PATHS.has(url);
}

/** With no token configured every request passes (loopback-only, enforced by loadConfig). */
export function createApiAuth(token: string | undefined): ApiAuth {
  if (token === undefined) return { vault: () => true, proxy: () => true };
  const expected = digest(token);
  const matches = (candidate: string | undefined) =>
    candidate !== undefined && timingSafeEqual(digest(candidate), expected);

  return {
    vault: req => matches(credential(req.headers.authorization, 'bearer')),
    proxy: req => {
      const header = req.headers['proxy-authorization'];
      return matches(credential(header, 'bearer')) || matches(basicPassword(header));
    },
  };
}

function digest(s: string): Buffer {
  return createHash('sha256').update(s).digest();
}

/** The credential after `<scheme> `, if the header uses that scheme (case-insensitive). */
function credential(header: string | undefined, scheme: string): string | undefined {
  if (!header) return undefined;
  const space = header.indexOf(' ');
  if (space === -1 || header.slice(0, space).toLowerCase() !== scheme) return undefined;
  return header.slice(space + 1).trim();
}

/** The password of a Basic credential (the user name is ignored). */
function basicPassword(header: string | undefined): string | undefined {
  const encoded = credential(header, 'basic');
  if (encoded === undefined) return undefined;
  const decoded = Buffer.from(encoded, 'base64').toString('utf8');
  const colon = decoded.indexOf(':');
  return colon === -1 ? undefined : decoded.slice(colon + 1);
}

export function sendUnauthorized(res: http.ServerResponse): void {
  res.writeHead(401, { 'Content-Type': 'application/json', 'WWW-Authenticate': 'Bearer realm="coatcheck"' });
  res.end(JSON.stringify({ error: 'Missing or invalid API token (Authorization: Bearer <COATCHECK_API_TOKEN>)' }));
}

export const PROXY_AUTH_REQUIRED =
  'HTTP/1.1 407 Proxy Authentication Required\r\n' +
  'Proxy-Authenticate: Basic realm="coatcheck"\r\n' +
  'Content-Length: 0\r\n' +
  'Connection: close\r\n\r\n';
