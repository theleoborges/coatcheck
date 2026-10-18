import { TICKET_PATTERN, TICKET_PREFIX, type SwapInfo } from './token-store.js';

export interface SwapOutcome {
  swaps: SwapInfo[];
  denied: SwapInfo[];
  /**
   * Tickets whose secret doesn't opt in to being swapped where they sit: the
   * body (no `where`), or the request line or a non-default header (`where`).
   */
  skipped?: SwapInfo[];
  /** Tickets whose value can't be represented where they sit (request refused). */
  invalid?: SwapInfo[];
}

/**
 * Emit structured lines per outbound request describing the swap outcome:
 * `result=denied` (host mismatch, request not forwarded), `result=hit` (bound
 * tickets swapped), `result=unbound` (tickets without a host binding swapped),
 * `result=body-skipped` (a body ticket whose secret doesn't enable `swap_body`),
 * `result=placement-skipped` (a ticket in the request line or a header its
 * secret isn't swapped in; `where=` names the places, never the values),
 * `result=invalid-value` (a value that can't go in a header; not forwarded).
 * `postSwapText` is the text *after* swaps were applied — any ticket literal (`cct_<hex>`)
 * remaining in it is un-swapped (TTL-expired token, stale tunnel, or a literal
 * the agent typed by mistake). Never logs token values, IDs, or request bodies.
 */
export function logSwapOutcome(
  scheme: 'http' | 'https',
  hostname: string,
  outcome: SwapOutcome,
  postSwapText: string,
): void {
  const { swaps, denied, invalid = [] } = outcome;
  if (denied.length > 0) {
    console.warn(`[swap] scheme=${scheme} host=${hostname} result=denied secrets=${names(denied)}`);
  }
  if (invalid.length > 0) {
    console.warn(`[swap] scheme=${scheme} host=${hostname} result=invalid-value secrets=${names(invalid)} (value has a control character, or a ':' in a Basic auth user-id)`);
  }
  if (denied.length > 0 || invalid.length > 0) return; // nothing is forwarded, so un-swapped literals don't matter

  const bound = swaps.filter(s => !s.unbound);
  const unbound = swaps.filter(s => s.unbound);
  if (bound.length > 0) {
    console.log(`[swap] scheme=${scheme} host=${hostname} result=hit secrets=${names(bound)} max_age_ms=${maxAge(bound)}`);
  }
  if (unbound.length > 0) {
    console.warn(`[swap] scheme=${scheme} host=${hostname} result=unbound secrets=${names(unbound)} max_age_ms=${maxAge(unbound)}`);
  }

  const bodySkipped = (outcome.skipped ?? []).filter(s => s.where === undefined);
  const headSkipped = (outcome.skipped ?? []).filter(s => s.where !== undefined);
  if (bodySkipped.length > 0) {
    console.warn(
      `[swap] scheme=${scheme} host=${hostname} result=body-skipped secrets=${names(bodySkipped)} ` +
      '(ticket in the request body; its secret does not enable swap_body, so it was sent as a literal)'
    );
  }
  if (headSkipped.length > 0) {
    console.warn(
      `[swap] scheme=${scheme} host=${hostname} result=placement-skipped secrets=${names(headSkipped)} ` +
      `where=${[...new Set(headSkipped.map(s => s.where))].join(',')} ` +
      '(ticket outside Authorization; its secret does not enable swap_url/swap_headers there, so it was sent as a literal)'
    );
  }

  // Reset regex state — TICKET_PATTERN is a /g RegExp shared across calls.
  TICKET_PATTERN.lastIndex = 0;
  const unswapped = (postSwapText.match(TICKET_PATTERN) ?? []).length;
  if (unswapped > 0) {
    console.warn(
      `[swap] scheme=${scheme} host=${hostname} result=miss unswapped_ticket_literals=${unswapped} ` +
      `(TTL expiry, passthrough tunnel, never-issued token, or body/placement-skipped — request reaching upstream with ${TICKET_PREFIX}… intact)`
    );
  }
}

/** A buffered body passed `COATCHECK_MAX_SWAP_BODY_BYTES` and is forwarded unscanned. */
export function logBodyUnscanned(scheme: 'http' | 'https', hostname: string, maxBytes: number): void {
  console.warn(
    `[swap] scheme=${scheme} host=${hostname} result=body-unscanned reason=too-large max_bytes=${maxBytes} ` +
    '(tickets in this body are sent as literals; raise COATCHECK_MAX_SWAP_BODY_BYTES if needed)'
  );
}

/** Header that marks a response coatcheck produced instead of forwarding the request. */
export const DENIED_HEADER = 'X-Coatcheck-Denied';

/** JSON body of the `403` sent when a ticket is used for a host it isn't bound to. */
export function hostMismatchBody(denied: SwapInfo[], hostname: string): string {
  const secrets = [...new Set(denied.map(d => d.secretName))];
  return JSON.stringify({
    error: `Secret ${secrets.map(s => `'${s}'`).join(', ')} is not allowed for host '${hostname}'`,
    reason: 'host-mismatch',
    secrets,
    host: hostname,
  });
}

/** JSON body of the `403` sent when a real value can't be represented where its ticket sits. */
export function invalidValueBody(invalid: SwapInfo[]): string {
  const secrets = [...new Set(invalid.map(d => d.secretName))];
  return JSON.stringify({
    error: `Secret ${secrets.map(s => `'${s}'`).join(', ')} has a value that can't be sent in a header (control character, or ':' in a Basic auth user-id)`,
    reason: 'invalid-value',
    secrets,
  });
}

/**
 * JSON body of the `403` sent when a request body to a browser-service host
 * can't be inspected for browser-code parameters (content-encoded, over the
 * size cap, or not JSON), so it is refused rather than forwarded.
 */
export function uninspectableBodyBody(hostname: string, why: string): string {
  return JSON.stringify({
    error: `Request body to browser-service host '${hostname}' can't be inspected (${why}); send plain JSON under COATCHECK_MAX_SWAP_BODY_BYTES`,
    reason: 'uninspectable-body',
    host: hostname,
  });
}

function names(infos: SwapInfo[]): string {
  return infos.map(s => s.secretName).join(',');
}

function maxAge(infos: SwapInfo[]): number {
  return Math.max(...infos.map(s => s.ageMs));
}
