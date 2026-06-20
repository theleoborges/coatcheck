import type { TokenStore } from '../token-store.js';

/**
 * CDP frame substitution, ported from the de-risk probe at
 * docs/future-work/cdp-credential-injection-probe/test.js.
 *
 * Outbound (agent → Browserbase): replace session-scoped `tok_*` tokens with
 *   their real values in the small set of CDP methods a login flow can reach.
 * Inbound (Browserbase → agent): defend echo-back. Redact any real value to a
 *   `[REDACTED:tok_*]` marker; if a frame still carries a real value after
 *   redaction (unparseable / binary-ish), drop it entirely (the byte-level floor).
 *
 * CDP is JSON-over-WebSocket. The pre-filter (`indexOf`) keeps the hot path
 * cheap: the vast majority of frames carry no substitution candidate and skip
 * JSON parsing entirely.
 */

export interface OutboundResult {
  payload: string;
  substitutions: number;
  /** A supported-but-unlisted method that still carried a `tok_*` literal. */
  unsupportedTokenMethod?: string;
}

export interface InboundResult {
  /** Rewritten frame to forward, or null when the frame must be dropped. */
  payload: string | null;
  redactions: number;
  dropped: boolean;
}

/** Substitute outbound `tok_*` tokens for the given session. */
export function substituteOutbound(
  raw: string,
  tokenStore: TokenStore,
  sessionId: string,
): OutboundResult {
  // Pre-filter: no token literal, nothing to do.
  if (raw.indexOf('tok_') === -1) return { payload: raw, substitutions: 0 };

  let parsed: { method?: string; params?: Record<string, unknown> };
  try {
    parsed = JSON.parse(raw);
  } catch {
    return { payload: raw, substitutions: 0 };
  }

  // Collect (container, key) targets to scan, by CDP method. Only the methods a
  // form-fill login realistically reaches are handled; anything else is left
  // untouched (and flagged below so we learn about gaps without leaking).
  const targets: Array<{ container: Record<string, unknown>; key: string }> = [];
  const method = parsed.method;
  const params = parsed.params;
  if (method === 'Input.insertText' && params) {
    targets.push({ container: params, key: 'text' });
  } else if (method === 'Runtime.evaluate' && params) {
    targets.push({ container: params, key: 'expression' });
  } else if (method === 'Runtime.callFunctionOn' && params) {
    targets.push({ container: params, key: 'functionDeclaration' });
    // Playwright pads `arguments` with internal context entries before the
    // user's args — iterate the whole array, never index-assume.
    const args = params.arguments;
    if (Array.isArray(args)) {
      for (const arg of args) {
        if (arg && typeof arg === 'object') {
          targets.push({ container: arg as Record<string, unknown>, key: 'value' });
        }
      }
    }
  }

  let substitutions = 0;
  let mutated = false;
  for (const { container, key } of targets) {
    const current = container[key];
    if (typeof current !== 'string') continue;
    const r = tokenStore.replaceAllForSession(current, sessionId);
    if (r.swaps.length > 0) {
      container[key] = r.output;
      substitutions += r.swaps.length;
      mutated = true;
    }
  }

  // A `tok_*` literal survived in a method we don't substitute. Don't leak it,
  // but surface it so production tells us about an uncovered code path.
  const unsupportedTokenMethod =
    !mutated && targets.length === 0 ? method : undefined;

  return {
    payload: mutated ? JSON.stringify(parsed) : raw,
    substitutions,
    unsupportedTokenMethod,
  };
}

/** Redact inbound echo-back of real values; drop the frame if it can't be cleaned. */
export function substituteInbound(
  raw: string,
  tokenStore: TokenStore,
  sessionId: string,
): InboundResult {
  const values = tokenStore.sessionValues(sessionId);
  if (values.length === 0) return { payload: raw, redactions: 0, dropped: false };

  // Byte-level floor: is any active real value present at all?
  let present = false;
  for (const { value } of values) {
    if (value.length > 0 && raw.indexOf(value) !== -1) {
      present = true;
      break;
    }
  }
  if (!present) return { payload: raw, redactions: 0, dropped: false };

  // A real value is in the frame. Try to redact it via the JSON tree.
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    // Can't parse → can't safely redact → drop.
    return { payload: null, redactions: 0, dropped: true };
  }

  const redactions = walkAndRedact(parsed, values);
  const output = JSON.stringify(parsed);

  // Floor: if any real value survived redaction (e.g. embedded in a way the
  // string walk missed), drop rather than forward a partially-cleaned frame.
  for (const { value } of values) {
    if (value.length > 0 && output.indexOf(value) !== -1) {
      return { payload: null, redactions, dropped: true };
    }
  }

  return { payload: output, redactions, dropped: false };
}

function walkAndRedact(obj: unknown, values: Array<{ value: string; secretName: string }>): number {
  if (obj === null || typeof obj !== 'object') return 0;
  let redactions = 0;
  const record = obj as Record<string, unknown>;
  for (const k of Object.keys(record)) {
    const v = record[k];
    if (typeof v === 'string') {
      const r = redactString(v, values);
      if (r.output !== v) {
        record[k] = r.output;
        redactions += r.count;
      }
    } else if (v !== null && typeof v === 'object') {
      redactions += walkAndRedact(v, values);
    }
  }
  return redactions;
}

function redactString(
  s: string,
  values: Array<{ value: string; secretName: string }>,
): { output: string; count: number } {
  let out = s;
  let count = 0;
  for (const { value, secretName } of values) {
    if (value.length > 0 && out.indexOf(value) !== -1) {
      out = out.split(value).join(`[REDACTED:${secretName}]`);
      count++;
    }
  }
  return { output: out, count };
}
