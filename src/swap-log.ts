import { TOKEN_LITERAL_PATTERN, type SwapInfo } from './token-store.js';

/**
 * Emit a single structured line per outbound request describing the swap outcome.
 * `postSwapText` is the text *after* swaps were applied — any `tok_<hex>` literal
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

  // Reset regex state — TOKEN_LITERAL_PATTERN is a /g RegExp shared across calls.
  TOKEN_LITERAL_PATTERN.lastIndex = 0;
  const unswapped = (postSwapText.match(TOKEN_LITERAL_PATTERN) ?? []).length;
  if (unswapped > 0) {
    console.warn(
      `[swap] scheme=${scheme} host=${hostname} result=miss unswapped_tok_literals=${unswapped} ` +
      `(TTL expiry, passthrough tunnel, or never-issued token — request reaching upstream with tok_… intact)`
    );
  }
}
