import { createJsonResponseRewriter, type JsonResponseRewriter } from './json-response-rewriter.js';

/** @deprecated Kept for existing callers; use a `BrowserAdapter` (browser-adapters.ts). */
export type ConnectUrlRewriter = JsonResponseRewriter;

/**
 * Rewrite every `connectUrl` string in JSON responses through `rewriteUrl`.
 * Retained wrapper over `createJsonResponseRewriter`; the MITM path uses the
 * Browserbase adapter, which also covers debugger URLs and `signingKey`.
 */
export function createConnectUrlRewriter(rewriteUrl: (realConnectUrl: string) => string): ConnectUrlRewriter {
  return createJsonResponseRewriter(body => replaceConnectUrls(body, rewriteUrl));
}

/** Recursively replace every `connectUrl` string value. Returns true if any changed. */
function replaceConnectUrls(obj: unknown, rewriteUrl: (url: string) => string): boolean {
  if (obj === null || typeof obj !== 'object') return false;
  let changed = false;
  const record = obj as Record<string, unknown>;
  for (const k of Object.keys(record)) {
    const v = record[k];
    if (k === 'connectUrl' && typeof v === 'string') {
      record[k] = rewriteUrl(v);
      changed = true;
    } else if (v !== null && typeof v === 'object') {
      if (replaceConnectUrls(v, rewriteUrl)) changed = true;
    }
  }
  return changed;
}
