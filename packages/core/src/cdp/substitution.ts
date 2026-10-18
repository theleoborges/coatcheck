import { type TokenStore } from '../token-store.js';

/**
 * CDP inbound frame redaction (design: docs/design/cdp-broker-login.md).
 *
 * Since broker-performed login (roadmap item 20) coatcheck never substitutes a
 * credential ticket into an outbound CDP frame — it fills the form itself while
 * the agent is quiesced. The only CDP-side defence left is inbound: redact any
 * real value the *browser* reports back (raw field reads, request bodies, site
 * console output) before the frame reaches the agent, and drop a frame that
 * still carries a real value after redaction (the byte-level floor).
 *
 * Redaction matches the real value and the small, fixed set of encodings the
 * **browser** applies to values it reports: percent-encoding (form bodies),
 * HTML-entity escaping and JSON string escaping. These are finite and knowable.
 * It deliberately does NOT chase arbitrary transforms an **agent's** own script
 * could apply (base64, reversal, char codes): item 20 removes the agent's
 * opportunity to run script while a real value is in the page, which is what
 * makes those unreachable — see the design's "Problem" section.
 *
 * CDP is JSON-over-WebSocket. A byte-level pre-scan keeps the hot path cheap:
 * the vast majority of frames carry no real value in any form and skip parsing.
 */

export interface InboundResult {
  /** Rewritten frame to forward, or null when the frame must be dropped. */
  payload: string | null;
  redactions: number;
  dropped: boolean;
}

interface Variant {
  /** An encoded form of a real value to match. */
  needle: string;
  secretName: string;
}

/** HTML-entity-escape the five characters a browser serialises in markup. */
function htmlEscape(s: string): string {
  return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

/** The inner of a JSON string literal (JSON escaping, without the quotes). */
function jsonEscape(s: string): string {
  const j = JSON.stringify(s);
  return j.slice(1, j.length - 1);
}

/**
 * Every browser-applied encoding of each real value, deduplicated, longest
 * first so a longer form is redacted before a shorter one it contains.
 */
function variantsFor(values: Array<{ value: string; secretName: string }>): Variant[] {
  const seen = new Set<string>();
  const out: Variant[] = [];
  for (const { value, secretName } of values) {
    if (value.length === 0) continue;
    for (const needle of [value, encodeURIComponent(value), htmlEscape(value), jsonEscape(value)]) {
      if (needle.length === 0 || seen.has(needle)) continue;
      seen.add(needle);
      out.push({ needle, secretName });
    }
  }
  out.sort((a, b) => b.needle.length - a.needle.length);
  return out;
}

/** Redact inbound echo-back of real values (and browser encodings); drop if it can't be cleaned. */
export function substituteInbound(raw: string, tokenStore: TokenStore, sessionId: string): InboundResult {
  const values = tokenStore.sessionValues(sessionId);
  if (values.length === 0) return { payload: raw, redactions: 0, dropped: false };

  const variants = variantsFor(values);

  // Byte-level floor: is any variant present at all?
  let present = false;
  for (const { needle } of variants) {
    if (raw.indexOf(needle) !== -1) { present = true; break; }
  }
  if (!present) return { payload: raw, redactions: 0, dropped: false };

  // A real value is in the frame. Try to redact it via the JSON tree.
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return { payload: null, redactions: 0, dropped: true }; // can't parse → can't safely redact → drop
  }

  const redactions = walkAndRedact(parsed, variants);
  const output = JSON.stringify(parsed);

  // Floor: if any variant survived (e.g. embedded in a way the walk missed),
  // drop rather than forward a partially-cleaned frame.
  for (const { needle } of variants) {
    if (output.indexOf(needle) !== -1) return { payload: null, redactions, dropped: true };
  }
  return { payload: output, redactions, dropped: false };
}

function walkAndRedact(obj: unknown, variants: Variant[]): number {
  if (obj === null || typeof obj !== 'object') return 0;
  let redactions = 0;
  const record = obj as Record<string, unknown>;
  for (const k of Object.keys(record)) {
    const v = record[k];
    if (typeof v === 'string') {
      const r = redactString(v, variants);
      if (r.output !== v) { record[k] = r.output; redactions += r.count; }
    } else if (v !== null && typeof v === 'object') {
      redactions += walkAndRedact(v, variants);
    }
  }
  return redactions;
}

function redactString(s: string, variants: Variant[]): { output: string; count: number } {
  let out = s;
  let count = 0;
  for (const { needle, secretName } of variants) {
    if (out.indexOf(needle) !== -1) {
      out = out.split(needle).join(`[REDACTED:${secretName}]`);
      count++;
    }
  }
  return { output: out, count };
}
