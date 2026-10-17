import { TICKET_PATTERN, TICKET_PREFIX, type SwapInfo } from './token-store.js';

export interface SwapOutcome {
  swaps: SwapInfo[];
  denied: SwapInfo[];
  /** Tickets found in a request body whose secret doesn't opt in to body swapping. */
  skipped?: SwapInfo[];
}

/**
 * Emit structured lines per outbound request describing the swap outcome:
 * `result=denied` (host mismatch, request not forwarded), `result=hit` (bound
 * tickets swapped), `result=unbound` (tickets without a host binding swapped),
 * `result=body-skipped` (a body ticket whose secret doesn't enable `swap_body`).
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
  const { swaps, denied } = outcome;
  if (denied.length > 0) {
    console.warn(`[swap] scheme=${scheme} host=${hostname} result=denied secrets=${names(denied)}`);
    return; // nothing is forwarded, so un-swapped literals don't matter
  }

  const bound = swaps.filter(s => !s.unbound);
  const unbound = swaps.filter(s => s.unbound);
  if (bound.length > 0) {
    console.log(`[swap] scheme=${scheme} host=${hostname} result=hit secrets=${names(bound)} max_age_ms=${maxAge(bound)}`);
  }
  if (unbound.length > 0) {
    console.warn(`[swap] scheme=${scheme} host=${hostname} result=unbound secrets=${names(unbound)} max_age_ms=${maxAge(unbound)}`);
  }

  if (outcome.skipped && outcome.skipped.length > 0) {
    console.warn(
      `[swap] scheme=${scheme} host=${hostname} result=body-skipped secrets=${names(outcome.skipped)} ` +
      '(ticket in the request body; its secret does not enable swap_body, so it was sent as a literal)'
    );
  }

  // Reset regex state — TICKET_PATTERN is a /g RegExp shared across calls.
  TICKET_PATTERN.lastIndex = 0;
  const unswapped = (postSwapText.match(TICKET_PATTERN) ?? []).length;
  if (unswapped > 0) {
    console.warn(
      `[swap] scheme=${scheme} host=${hostname} result=miss unswapped_ticket_literals=${unswapped} ` +
      `(TTL expiry, passthrough tunnel, never-issued token, or body-skipped — request reaching upstream with ${TICKET_PREFIX}… intact)`
    );
  }
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

function names(infos: SwapInfo[]): string {
  return infos.map(s => s.secretName).join(',');
}

function maxAge(infos: SwapInfo[]): number {
  return Math.max(...infos.map(s => s.ageMs));
}
