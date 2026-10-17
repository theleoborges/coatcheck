import { TICKET_PREFIX, type TokenStore } from '../token-store.js';
import type { MatchTarget } from '../host-matcher.js';

/**
 * CDP frame substitution (design: docs/design/cdp-injection.md).
 *
 * Outbound (agent → browser): replace session-scoped `cct_*` tokens with their
 *   real values in `Input.insertText` only (what `page.fill()` sends), and only
 *   when the CDP session's committed main-frame origin is one of the ticket's
 *   allowed hosts. Otherwise the frame is dropped and answered with a CDP error.
 *   `Runtime.evaluate` / `Runtime.callFunctionOn` are never substitution sites:
 *   an expression could send the value anywhere.
 * Inbound (browser → agent): defend echo-back. Redact any real value to a
 *   `[REDACTED:<secretName>]` marker; if a frame still carries a real value after
 *   redaction (unparseable / binary-ish), drop it entirely (the byte-level floor).
 *
 * CDP is JSON-over-WebSocket. The pre-filter (`indexOf`) keeps the hot path
 * cheap: the vast majority of frames carry no substitution candidate and skip
 * JSON parsing entirely.
 */

/** A CDP session's origin for the binding check (see `OriginTracker.originFor`). */
export type OriginLookup = (cdpSessionId: string | undefined) => { target: MatchTarget } | { unknown: string };

export interface OutboundDenial {
  /** The request's `id` and `sessionId`, so the CDP error reaches the waiting call. */
  id: unknown;
  sessionId?: string;
  secretNames: string[];
  /** CDP error message: names and host only, never a value. */
  message: string;
}

export interface OutboundResult {
  payload: string;
  substitutions: number;
  /** A method other than `Input.insertText` that still carried a `cct_*` literal (forwarded unchanged). */
  unsupportedTokenMethod?: string;
  /** Set when the frame must be dropped and answered with a CDP error. */
  denial?: OutboundDenial;
}

export interface InboundResult {
  /** Rewritten frame to forward, or null when the frame must be dropped. */
  payload: string | null;
  redactions: number;
  dropped: boolean;
}

/** Substitute outbound `cct_*` tokens for the given session, gated on the page origin. */
export function substituteOutbound(
  raw: string,
  tokenStore: TokenStore,
  sessionId: string,
  originFor: OriginLookup,
): OutboundResult {
  // Pre-filter: no token literal, nothing to do.
  if (raw.indexOf(TICKET_PREFIX) === -1) return { payload: raw, substitutions: 0 };

  let parsed: { id?: unknown; sessionId?: unknown; method?: string; params?: Record<string, unknown> };
  try {
    parsed = JSON.parse(raw);
  } catch {
    return { payload: raw, substitutions: 0 };
  }

  const params = parsed.params;
  if (parsed.method !== 'Input.insertText' || !params || typeof params.text !== 'string') {
    // Not a substitution site. Surface it (names only, via the caller's log)
    // so production tells us about uncovered code paths.
    return { payload: raw, substitutions: 0, unsupportedTokenMethod: parsed.method ?? '(response)' };
  }

  const cdpSessionId = typeof parsed.sessionId === 'string' ? parsed.sessionId : undefined;
  const origin = originFor(cdpSessionId);
  const r = tokenStore.replaceAllForSession(params.text, sessionId, 'target' in origin ? origin.target : null);
  if (r.denied.length > 0) {
    const secretNames = r.denied.map(d => d.secretName);
    const message = 'target' in origin
      ? `credential-origin violation: ${secretNames.join(', ')} not allowed on ${origin.target.scheme}://${origin.target.host}`
      : `credential-origin violation: page origin unknown (${origin.unknown}); ${secretNames.join(', ')} not filled`;
    return { payload: raw, substitutions: 0, denial: { id: parsed.id, sessionId: cdpSessionId, secretNames, message } };
  }
  if (r.swaps.length === 0) return { payload: raw, substitutions: 0 };
  params.text = r.output;
  return { payload: JSON.stringify(parsed), substitutions: r.swaps.length };
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
