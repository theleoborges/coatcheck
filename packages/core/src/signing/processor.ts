import { matchesHost, type MatchTarget } from '../host-matcher.js';
import { TICKET_PATTERN, type SigningTicket, type SwapInfo, type TokenStore } from '../token-store.js';
import { headerValues, type SignableRequest, type SigningView } from './request.js';
import { finalizeHmac } from './hmac.js';
import { finalizeSigV4, parseSigV4Authorization, payloadMode, type FinalizeResult } from './sigv4.js';
import type { SigningScheme } from './types.js';

/**
 * Signing processors (design: docs/design/signing-processors.md §4.2). Per
 * request: find a signing ticket used as a key, check its host binding,
 * decide whether the body is needed, and later verify what the agent signed
 * and re-sign what goes out. Signing tickets are never swapped as literals.
 */

/** A request coatcheck will verify and re-sign. */
export interface SigningPlan {
  kind: 'plan';
  scheme: SigningScheme;
  info: SwapInfo;
  /** The request head as received, which the agent's signature is verified over. */
  received: SignableRequest;
  /** The body must be buffered (and hashed); past the cap the request is refused. */
  needsBody: boolean;
  /** Header names (lowercase) the scheme writes; the literal head swap skips them. */
  ownedHeaders: ReadonlySet<string>;
  /** Verify over `received` (as the agent sent it), sign over `outgoing` (after swaps). */
  finalize(received: SigningView, outgoing: SigningView): FinalizeResult;
}

export type PlanResult =
  | null
  | { kind: 'denied'; denied: SwapInfo[] }
  | { kind: 'unsignable'; reason: string; info: SwapInfo }
  | SigningPlan;

const SIGV4_OWNED: ReadonlySet<string> = new Set(['authorization', 'x-amz-security-token']);

function infoOf(ticket: SigningTicket): SwapInfo {
  return { secretName: ticket.secretName, ageMs: ticket.ageMs, ...(ticket.allowedHosts ? {} : { unbound: true as const }) };
}

/** The first live signing ticket whose id appears in `text`. */
function signingTicketIn(store: TokenStore, text: string): [string, SigningTicket] | null {
  for (const id of text.match(TICKET_PATTERN) ?? []) {
    const ticket = store.signingTicket(id);
    if (ticket) return [id, ticket];
  }
  return null;
}

/**
 * Plan signing for a request head as received: a SigV4 ticket as the access
 * key id in `Authorization`, an HMAC ticket as the whole value of its
 * recipe's `key_header`. `null`: no signing ticket is used as a key (the request takes the ordinary swap path). `denied`: the
 * ticket is bound to other hosts (`403 host-mismatch`). `unsignable`: a shape
 * coatcheck doesn't re-sign (`403 unsignable`).
 */
export function planSigning(store: TokenStore, req: SignableRequest, target: MatchTarget): PlanResult {
  for (const [name, value] of req.headers) {
    const found = signingTicketIn(store, value);
    if (!found) continue;
    const [ticketId, ticket] = found;
    const { credential } = ticket;
    // Each scheme carries the ticket in one header; anywhere else it is a
    // literal, left to the swap path (`signing-skipped`, or a host denial).
    const carrier = credential.scheme === 'aws-sigv4' ? 'authorization' : credential.recipe.keyHeader;
    if (name.toLowerCase() !== carrier) continue;
    const info = infoOf(ticket);
    if (ticket.allowedHosts && !matchesHost(ticket.allowedHosts, target)) return { kind: 'denied', denied: [info] };
    const carried = headerValues(req, carrier);
    const repeated = carried.length > 1;

    if (credential.scheme === 'hmac') {
      const { recipe } = credential;
      if (repeated || carried[0] !== ticketId) return { kind: 'unsignable', reason: 'malformed-key-header', info };
      return {
        kind: 'plan',
        scheme: 'hmac',
        info,
        received: req,
        needsBody: recipe.message.some(p => p.kind === 'body'),
        ownedHeaders: new Set([recipe.keyHeader, recipe.signatureHeader]),
        finalize: (received, outgoing) => finalizeHmac(ticketId, credential, received, outgoing),
      };
    }

    const auth = parseSigV4Authorization(value);
    // Another scheme (`Bearer cct_…`): a literal.
    if (auth === null) continue;
    if (typeof auth === 'string') return { kind: 'unsignable', reason: auth, info };
    // Repeated, or the ticket somewhere other than the access key id.
    if (repeated || auth.accessKeyId !== ticketId) return { kind: 'unsignable', reason: 'malformed-authorization', info };
    const mode = payloadMode(req);
    if (mode.kind === 'unsignable') return { kind: 'unsignable', reason: mode.reason, info };
    return {
      kind: 'plan',
      scheme: 'aws-sigv4',
      info,
      received: req,
      needsBody: mode.kind === 'body',
      ownedHeaders: SIGV4_OWNED,
      finalize: (received, outgoing) => finalizeSigV4(auth, ticketId, credential, received, outgoing),
    };
  }
  return null;
}
