/**
 * Browser adapters (design: v1-decisions.md §6): which REST responses carry
 * remote-browser CDP URLs, and how to point them at the local CDP proxy.
 * The HTTP framing is shared (`createJsonResponseRewriter`); an adapter only
 * transforms parsed JSON.
 */

export interface BrowserAdapter {
  name: string;
  /** REST hosts whose responses are rewritten (`allowed_hosts` syntax: exact or `*.suffix`). */
  hosts: string[];
  /** Mutate parsed JSON in place; `register(realWsUrl)` returns the local ws URL. Return true if changed. */
  rewriteJson(body: unknown, register: (realUrl: string) => string): boolean;
}

export const BROWSERBASE_API_HOST = 'api.browserbase.com';

function parseUrl(value: string): URL | null {
  try {
    return new URL(value);
  } catch {
    return null;
  }
}

function isBrowserbaseHost(hostname: string): boolean {
  const h = hostname.toLowerCase();
  return h === 'browserbase.com' || h.endsWith('.browserbase.com');
}

function isWsUrl(u: URL | null): u is URL {
  return u !== null && (u.protocol === 'ws:' || u.protocol === 'wss:');
}

/** A Browserbase CDP endpoint: `ws(s)://…browserbase.com…`, checked on the parsed hostname. */
function isBrowserbaseWs(value: string): boolean {
  const u = parseUrl(value);
  return isWsUrl(u) && isBrowserbaseHost(u.hostname);
}

/**
 * An http(s) URL whose query carries a Browserbase WebSocket target, with or
 * without a scheme (the hosted DevTools viewer: `inspector.html?wss=connect.browserbase.com/…`).
 */
function embedsBrowserbaseWs(value: string): boolean {
  const u = parseUrl(value);
  if (!u || (u.protocol !== 'http:' && u.protocol !== 'https:')) return false;
  for (const [key, v] of u.searchParams) {
    if (isBrowserbaseWs(v)) return true;
    if ((key === 'ws' || key === 'wss') && isBrowserbaseWs(`${key}://${v}`)) return true;
  }
  return false;
}

const VIEWER_KEYS = new Set(['debuggerUrl', 'debuggerFullscreenUrl']);

/**
 * Rewrite Browserbase CDP URLs by value (`connectUrl`, `wsUrl`, debugger
 * URLs, `pages[]`), delete `signingKey`, and delete viewer URLs that would
 * hand the agent a direct route to the browser.
 */
function rewriteBrowserbase(node: unknown, register: (realUrl: string) => string): boolean {
  if (node === null || typeof node !== 'object') return false;
  let changed = false;
  const record = node as Record<string, unknown>;
  for (const key of Object.keys(record)) {
    const v = record[key];
    if (key === 'signingKey') {
      delete record[key];
      changed = true;
    } else if (typeof v === 'string') {
      if (isBrowserbaseWs(v) || (key === 'connectUrl' && isWsUrl(parseUrl(v)))) {
        record[key] = register(v);
        changed = true;
      } else if (embedsBrowserbaseWs(v) || VIEWER_KEYS.has(key)) {
        delete record[key];
        changed = true;
      }
    } else if (v !== null && typeof v === 'object') {
      if (rewriteBrowserbase(v, register)) changed = true;
    }
  }
  return changed;
}

/** Browserbase, with an overridable API host (tests point it at a local upstream). */
export function createBrowserbaseAdapter(apiHost = BROWSERBASE_API_HOST): BrowserAdapter {
  return { name: 'browserbase', hosts: [apiHost], rewriteJson: rewriteBrowserbase };
}

export const browserbaseAdapter: BrowserAdapter = createBrowserbaseAdapter();

/** Built-ins selectable through `COATCHECK_BROWSER_ADAPTERS`. */
export const BUILTIN_BROWSER_ADAPTERS: Readonly<Record<string, BrowserAdapter>> = {
  browserbase: browserbaseAdapter,
};

export function builtinBrowserAdapters(names: readonly string[]): BrowserAdapter[] {
  return names.map(n => {
    const a = BUILTIN_BROWSER_ADAPTERS[n];
    if (!a) throw new Error(`unknown browser adapter '${n}'`);
    return a;
  });
}
