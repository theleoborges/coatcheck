import type { HmacCredential } from './hmac.js';
import type { SigV4Credential } from './sigv4.js';

/**
 * The real credential behind a signing ticket (design:
 * docs/design/signing-processors.md §3, "Token store"). A signing ticket is
 * never literal-substituted; its credential is only used to re-sign.
 */
export type SigningCredential = SigV4Credential | HmacCredential;

/** The scheme names that appear in mint responses and `[swap]` lines. */
export type SigningScheme = SigningCredential['scheme'];
