import type { CdpConnection } from './proxy.js';
import type { LoginRequest, LoginResult } from '../cdp-session-store.js';
import { matchesHost, type MatchTarget } from '../host-matcher.js';

/**
 * Broker-performed login driver (design: docs/design/cdp-broker-login.md,
 * "The login window" + "Implementation decisions"). coatcheck quiesces the
 * agent, removes the agent's new-document scripts, reloads to a fresh document,
 * fills the real values, submits, waits for the success condition, and empties
 * the fields on timeout — all over the agent's CDP connection, so no
 * agent-controlled script runs while a real value is in the page.
 */

interface CdpMsg { id?: unknown; method?: unknown; sessionId?: unknown; params?: Record<string, unknown>; result?: Record<string, unknown>; error?: unknown }

/** Resolve a URL to a match target, or null when it isn't http(s). */
function targetOf(url: string): MatchTarget | null {
  let u: URL;
  try { u = new URL(url); } catch { return null; }
  if (u.protocol !== 'https:' && u.protocol !== 'http:') return null;
  return { host: u.hostname.replace(/^\[|\]$/g, ''), scheme: u.protocol === 'https:' ? 'https' : 'http' };
}

export async function runLogin(conn: CdpConnection, req: LoginRequest): Promise<LoginResult> {
  // --- Precondition: resolve the page target ---
  const candidates: Array<{ session: string; url: string }> = [];
  for (const session of conn.pageTargets.keys()) {
    const snap = conn.origins.snapshot(session);
    if (snap.url === undefined) continue;
    if (req.pageUrlPrefix !== undefined && !snap.url.startsWith(req.pageUrlPrefix)) continue;
    candidates.push({ session, url: snap.url });
  }
  if (candidates.length !== 1) return { status: 409, reason: 'page-ambiguous' };
  const page = candidates[0].session;

  // --- Precondition: request interception must be off on that page ---
  if (conn.interception.has(page)) return { status: 409, reason: 'interception-active' };

  const started = Date.now();
  const deadline = started + req.timeoutMs;
  const remaining = () => Math.max(0, deadline - Date.now());
  const filled: string[] = []; // selectors coatcheck filled, for the clear step
  console.log(`[cdp] sid=${conn.sid} login secret=${req.secretName} window open`);

  conn.beginWindow();
  let outcome = 'error';
  try {
    // --- Precondition re-check: origin before touching the page ---
    const originCheck = checkOrigin(conn, page, req);
    if (originCheck) { outcome = 'denied'; return originCheck; }

    // --- Fresh document: remove the agent's new-document scripts, then reload ---
    for (const identifier of conn.agentScriptIds.get(page) ?? []) {
      await conn.sendCommand('Page.removeScriptToEvaluateOnNewDocument', { identifier }, page);
    }
    const reloaded = await reload(conn, page, remaining());
    if (!reloaded) { outcome = 'no-success'; return { status: 409, reason: 'no-success', cleared: true }; }

    // Re-check the origin after the reload (it could have redirected).
    const afterReload = checkOrigin(conn, page, req);
    if (afterReload) { outcome = 'denied'; return afterReload; }

    // --- Fill ---
    const rootNodeId = await documentNodeId(conn, page);
    for (const [field, selector] of Object.entries(req.fields)) {
      const value = req.values[field];
      if (typeof value !== 'string') return { status: 501 };
      const nodeId = await querySelector(conn, page, rootNodeId, selector);
      if (nodeId === 0) { outcome = 'selector-not-found'; return { status: 404, reason: 'selector-not-found', field }; }
      await conn.sendCommand('DOM.focus', { nodeId }, page);
      await clearNode(conn, page, nodeId);
      await conn.sendCommand('Input.insertText', { text: value }, page);
      filled.push(selector);
    }

    // --- Submit ---
    await submit(conn, page, req);

    // --- Wait for the success condition ---
    const ok = await waitUntil(conn, page, req, remaining());
    if (!ok) {
      await clearFields(conn, page, filled);
      outcome = 'no-success';
      return { status: 409, reason: 'no-success', cleared: true };
    }

    // Success: clear any field still mounted (SPA), then report the URL.
    await clearFields(conn, page, filled);
    outcome = 'ok';
    return { status: 200, url: conn.origins.snapshot(page).url ?? '' };
  } catch {
    if (conn.isClosed) { outcome = 'upstream-closed'; return { status: 502, reason: 'upstream-closed' }; }
    // A coatcheck command failed for a reason not in the table. Empty the
    // fields and report a driver error; never echo the CDP error text.
    await clearFields(conn, page, filled).catch(() => { /* best effort */ });
    outcome = 'driver-error';
    return { status: 502, reason: 'driver-error', cleared: true };
  } finally {
    conn.endWindow();
    console.log(`[cdp] sid=${conn.sid} login secret=${req.secretName} window closed outcome=${outcome} ms=${Date.now() - started} queued=${conn.queuedCount}`);
  }
}

/** 403 when the page's committed origin isn't allowed; null when it is. */
function checkOrigin(conn: CdpConnection, page: string, req: LoginRequest): LoginResult | null {
  const snap = conn.origins.snapshot(page);
  if (snap.navigating || snap.url === undefined) {
    return { status: 403, error: 'credential-origin violation: page origin unknown or navigating' };
  }
  const target = targetOf(snap.url);
  if (!target) return { status: 403, error: `credential-origin violation: page scheme is not http(s)` };
  if (req.allowedHosts !== undefined && !matchesHost(req.allowedHosts, target)) {
    return { status: 403, error: `credential-origin violation: ${req.secretName} not allowed on ${target.scheme}://${target.host}` };
  }
  return null;
}

/** Reload the page and wait for the main frame to commit and finish loading. */
async function reload(conn: CdpConnection, page: string, timeoutMs: number): Promise<boolean> {
  if (timeoutMs <= 0) return false;
  const navigated = conn.waitForEvent(
    m => m.method === 'Page.frameNavigated' && isMainFrame(m) && m.sessionId === page,
    timeoutMs,
  );
  const loaded = conn.waitForEvent(
    m => m.method === 'Page.loadEventFired' && m.sessionId === page,
    timeoutMs,
  );
  try {
    await conn.sendCommand('Page.reload', {}, page);
    await navigated;
    await loaded;
    return true;
  } catch {
    return false;
  }
}

function isMainFrame(m: CdpMsg): boolean {
  const frame = m.params?.frame as { parentId?: unknown } | undefined;
  return !!frame && frame.parentId === undefined;
}

async function documentNodeId(conn: CdpConnection, page: string): Promise<number> {
  const res = await conn.sendCommand('DOM.getDocument', { depth: 0 }, page);
  const root = res.result?.root as { nodeId?: unknown } | undefined;
  return typeof root?.nodeId === 'number' ? root.nodeId : 0;
}

async function querySelector(conn: CdpConnection, page: string, rootNodeId: number, selector: string): Promise<number> {
  const res = await conn.sendCommand('DOM.querySelector', { nodeId: rootNodeId, selector }, page);
  const nodeId = res.result?.nodeId;
  return typeof nodeId === 'number' ? nodeId : 0;
}

/** Empty a field's value via coatcheck's own Runtime call (clears autofill). */
async function clearNode(conn: CdpConnection, page: string, nodeId: number): Promise<void> {
  const resolved = await conn.sendCommand('DOM.resolveNode', { nodeId }, page);
  const objectId = (resolved.result?.object as { objectId?: unknown } | undefined)?.objectId;
  if (typeof objectId !== 'string') return;
  await conn.sendCommand('Runtime.callFunctionOn', {
    objectId,
    functionDeclaration: 'function(){this.value="";}',
  }, page);
}

async function submit(conn: CdpConnection, page: string, req: LoginRequest): Promise<void> {
  if ('press' in req.submit) {
    // Enter on the currently focused (last filled) field.
    await conn.sendCommand('Input.dispatchKeyEvent', { type: 'keyDown', key: 'Enter', code: 'Enter', windowsVirtualKeyCode: 13 }, page);
    await conn.sendCommand('Input.dispatchKeyEvent', { type: 'keyUp', key: 'Enter', code: 'Enter', windowsVirtualKeyCode: 13 }, page);
    return;
  }
  const rootNodeId = await documentNodeId(conn, page);
  const nodeId = await querySelector(conn, page, rootNodeId, req.submit.selector);
  if (nodeId === 0) throw new Error('submit selector not found');
  const box = await conn.sendCommand('DOM.getBoxModel', { nodeId }, page);
  const content = (box.result?.model as { content?: number[] } | undefined)?.content;
  if (!content || content.length < 8) throw new Error('no box model for submit');
  const x = (content[0] + content[2] + content[4] + content[6]) / 4;
  const y = (content[1] + content[3] + content[5] + content[7]) / 4;
  await conn.sendCommand('Input.dispatchMouseEvent', { type: 'mousePressed', x, y, button: 'left', clickCount: 1 }, page);
  await conn.sendCommand('Input.dispatchMouseEvent', { type: 'mouseReleased', x, y, button: 'left', clickCount: 1 }, page);
}

/** Wait for the `until` success condition within the remaining budget. */
async function waitUntil(conn: CdpConnection, page: string, req: LoginRequest, timeoutMs: number): Promise<boolean> {
  if (timeoutMs <= 0) return false;
  if (req.until.kind === 'navigation') {
    const before = conn.origins.snapshot(page).loaderId;
    try {
      await conn.waitForEvent(
        m => m.method === 'Page.frameNavigated' && isMainFrame(m) && m.sessionId === page
          && typeof (m.params?.frame as { loaderId?: unknown }).loaderId === 'string'
          && (m.params?.frame as { loaderId?: string }).loaderId !== before,
        timeoutMs,
      );
      return true;
    } catch { return false; }
  }
  if (req.until.kind === 'urlPrefix') {
    const prefix = req.until.urlPrefix;
    if ((conn.origins.snapshot(page).url ?? '').startsWith(prefix)) return true;
    try {
      await conn.waitForEvent(
        m => m.method === 'Page.frameNavigated' && isMainFrame(m) && m.sessionId === page
          && typeof (m.params?.frame as { url?: unknown }).url === 'string'
          && (m.params?.frame as { url: string }).url.startsWith(prefix),
        timeoutMs,
      );
      return true;
    } catch { return false; }
  }
  // selector: poll until it appears or the budget runs out.
  const selector = req.until.selector;
  const end = Date.now() + timeoutMs;
  while (Date.now() < end && !conn.isClosed) {
    const rootNodeId = await documentNodeId(conn, page);
    if (await querySelector(conn, page, rootNodeId, selector) !== 0) return true;
    await new Promise(r => setTimeout(r, 250));
  }
  return false;
}

/** Empty each still-present field (best effort). */
async function clearFields(conn: CdpConnection, page: string, selectors: string[]): Promise<void> {
  if (selectors.length === 0 || conn.isClosed) return;
  const rootNodeId = await documentNodeId(conn, page);
  for (const selector of selectors) {
    const nodeId = await querySelector(conn, page, rootNodeId, selector);
    if (nodeId !== 0) await clearNode(conn, page, nodeId);
  }
}
