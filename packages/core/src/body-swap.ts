import { TICKET_PREFIX, type SwapResult, type TokenStore } from './token-store.js';
import type { MatchTarget } from './host-matcher.js';

/**
 * Swap tickets in a request body, for secrets that opt in (`swap_body`,
 * design §3 "Request body substitution"). Returns null when the body isn't
 * scanned: empty, content-encoded, or holding no ticket prefix. Otherwise
 * `body` is the rewritten body (the input when nothing was swapped).
 */
export function swapRequestBody(
  tokenStore: TokenStore,
  body: Buffer,
  headers: { contentType?: string; contentEncoding?: string },
  target: MatchTarget,
): { body: Buffer; result: SwapResult } | null {
  if (body.length === 0 || !body.includes(TICKET_PREFIX)) return null;
  const encoding = headers.contentEncoding?.trim().toLowerCase();
  if (encoding && encoding !== 'identity') return null;

  // latin1 maps bytes 1:1, so bytes outside tickets (binary included) round-trip exactly.
  const escape = escaperFor(headers.contentType);
  const result = tokenStore.replaceAllInBody(
    body.toString('latin1'),
    target,
    value => Buffer.from(escape(value), 'utf8').toString('latin1'),
  );
  if (result.swaps.length === 0) return { body, result };
  return { body: Buffer.from(result.output, 'latin1'), result };
}

/** How a real value is escaped for the body's media type. */
function escaperFor(contentType: string | undefined): (value: string) => string {
  const type = contentType?.split(';')[0].trim().toLowerCase() ?? '';
  // A ticket in JSON sits inside a string literal.
  if (type === 'application/json' || type.endsWith('+json')) return v => JSON.stringify(v).slice(1, -1);
  if (type === 'application/x-www-form-urlencoded') return encodeURIComponent;
  return v => v;
}
