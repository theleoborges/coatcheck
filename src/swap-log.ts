import { TICKET_PATTERN, TICKET_PREFIX, type SwapInfo } from './token-store.js';

/**
 * Emit a single structured line per outbound request describing the swap outcome.
 * `postSwapText` is the text *after* swaps were applied — any ticket literal (`cct_<hex>`)
 * remaining in it is un-swapped (TTL-expired token, stale tunnel, or a literal
 * the agent typed by mistake). Never logs token values, IDs, or request bodies.
 */
export function logSwapOutcome(
  scheme: 'http' | 'https',
  hostname: string,
  swaps: SwapInfo[],
  postSwapText: string,
): void {
  if (swaps.length > 0) {
    const secrets = swaps.map(s => s.secretName).join(',');
    const maxAge = Math.max(...swaps.map(s => s.ageMs));
    console.log(`[swap] scheme=${scheme} host=${hostname} result=hit secrets=${secrets} max_age_ms=${maxAge}`);
  }

  // Reset regex state — TICKET_PATTERN is a /g RegExp shared across calls.
  TICKET_PATTERN.lastIndex = 0;
  const unswapped = (postSwapText.match(TICKET_PATTERN) ?? []).length;
  if (unswapped > 0) {
    console.warn(
      `[swap] scheme=${scheme} host=${hostname} result=miss unswapped_ticket_literals=${unswapped} ` +
      `(TTL expiry, passthrough tunnel, or never-issued token — request reaching upstream with ${TICKET_PREFIX}… intact)`
    );
  }
}
