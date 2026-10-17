/**
 * Fail-closed detection for `page.type()` on a vault token.
 *
 * `page.fill()` sends a token in one `Input.insertText` frame, which the
 * outbound substitutor swaps cleanly. `page.type()` sends one
 * `Input.dispatchKeyEvent` per character, so the token never appears intact in
 * a single frame and would be typed literally into the site. We don't buffer-
 * and-replay (v1 scope); instead we detect the per-keystroke run that spells a
 * known session token and fail closed: the proxy drops the offending frame and
 * errors the agent, rather than leaking `cct_*` to the site as a password.
 *
 * One detector per CDP session. The buffer never crosses sessions.
 */

// Token ids are `cct_` + 64 hex = 68 chars. Keep a little margin.
const WINDOW = 80;

export class KeystrokeDetector {
  private buffer = '';

  /**
   * Feed the `text` of an `Input.dispatchKeyEvent` frame. Returns the matched
   * token id when the accumulated keystrokes end with a currently-active
   * session token, else null. On a match the buffer is reset so we don't
   * re-fire on the next character.
   */
  inspect(text: string, activeTokenIds: string[]): string | null {
    if (typeof text !== 'string' || text.length === 0) return null;
    this.buffer = (this.buffer + text).slice(-WINDOW);
    for (const id of activeTokenIds) {
      if (this.buffer.endsWith(id)) {
        this.buffer = '';
        return id;
      }
    }
    return null;
  }

  reset(): void {
    this.buffer = '';
  }
}
