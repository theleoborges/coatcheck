import { describe, it, expect, afterEach } from 'vitest';
import { WebSocketServer, WebSocket } from 'ws';
import type { AddressInfo } from 'node:net';
import { TokenStore } from '../token-store.js';
import { CdpSessionStore, type LoginRequest } from '../cdp-session-store.js';
import { startCdpProxy, type CdpProxyHandle } from './proxy.js';
import { parseHostPattern, type HostPattern } from '../host-matcher.js';

const hosts = (...e: string[]) => e.map(x => parseHostPattern(x) as HostPattern);

function once<T = unknown>(emitter: { once(event: string, cb: (...a: unknown[]) => void): unknown }, event: string): Promise<T> {
  return new Promise(resolve => emitter.once(event, (...a: unknown[]) => resolve(a[0] as T)));
}

interface Frame { id?: number; method?: string; sessionId?: string; params?: Record<string, unknown>; result?: Record<string, unknown> }

/**
 * A fake remote browser that answers coatcheck's own CDP commands and emits the
 * events a login window waits on, so the driver can be unit-tested without a
 * real Chromium. `removedScripts` records which new-document scripts coatcheck
 * removed; `filledText` records what it typed via Input.insertText.
 */
function fakeBrowser() {
  const removedScripts: string[] = [];
  const filledText: string[] = [];
  const clearedNodes: number[] = [];
  let conn: WebSocket | null = null;
  const received: Frame[] = [];
  let loaderSeq = 100;
  const opts = {
    page: 'P1',
    url: 'https://login.example.com/login',
    /** When set, the submit click triggers a navigation (full-page login). */
    navigateOnSubmit: true,
    /** Selector query results: selector → nodeId (0 = not found). */
    selectors: new Map<string, number>([['#user', 11], ['#pass', 12], ['#go', 20], ['#done', 0]]),
    /** A selector to "appear" after submit (for until.selector). */
    appearAfterSubmit: null as string | null,
  };

  function send(f: Frame) { conn?.send(JSON.stringify(f)); }
  function emitNavigated(url: string) {
    send({ method: 'Page.frameNavigated', sessionId: opts.page, params: { frame: { id: 'F1', url, loaderId: `L${loaderSeq++}` } } });
  }

  function handle(f: Frame) {
    received.push(f);
    if (typeof f.id !== 'number' || f.id < 0x40000000) return; // only answer coatcheck's own
    const m = f.method;
    const reply = (result: Record<string, unknown>) => send({ id: f.id, sessionId: f.sessionId, result });
    switch (m) {
      case 'Page.removeScriptToEvaluateOnNewDocument':
        removedScripts.push(String((f.params as { identifier?: string }).identifier));
        return reply({});
      case 'Page.reload':
        reply({});
        setTimeout(() => { emitNavigated(opts.url); send({ method: 'Page.loadEventFired', sessionId: opts.page, params: {} }); }, 5);
        return;
      case 'DOM.getDocument': return reply({ root: { nodeId: 1 } });
      case 'DOM.querySelector': {
        const sel = (f.params as { selector: string }).selector;
        let nodeId = opts.selectors.get(sel) ?? 0;
        if (opts.appearAfterSubmit === sel && received.some(r => r.method === 'Input.dispatchMouseEvent')) nodeId = 99;
        return reply({ nodeId });
      }
      case 'DOM.focus': return reply({});
      case 'DOM.resolveNode': return reply({ object: { objectId: `obj-${(f.params as { nodeId: number }).nodeId}` } });
      case 'Runtime.callFunctionOn': {
        const objectId = String((f.params as { objectId: string }).objectId);
        clearedNodes.push(Number(objectId.replace('obj-', '')));
        return reply({ result: { type: 'undefined' } });
      }
      case 'Input.insertText':
        filledText.push(String((f.params as { text: string }).text));
        return reply({});
      case 'DOM.getBoxModel': return reply({ model: { content: [0, 0, 10, 0, 10, 10, 0, 10] } });
      case 'Input.dispatchMouseEvent':
        reply({});
        if (m === 'Input.dispatchMouseEvent' && (f.params as { type: string }).type === 'mouseReleased') {
          if (opts.navigateOnSubmit) setTimeout(() => emitNavigated('https://login.example.com/home'), 5);
        }
        return;
      case 'Input.dispatchKeyEvent':
        reply({});
        return;
      default: return reply({});
    }
  }

  const server = new WebSocketServer({ host: '127.0.0.1', port: 0 });
  server.on('connection', ws => {
    conn = ws;
    ws.on('message', (d: Buffer) => handle(JSON.parse(d.toString())));
  });
  return new Promise<{
    url: string; server: WebSocketServer; opts: typeof opts; received: Frame[];
    removedScripts: string[]; filledText: string[]; clearedNodes: number[];
    methods(): string[];
  }>(resolve => {
    server.on('listening', () => {
      const { port } = server.address() as AddressInfo;
      resolve({
        url: `ws://127.0.0.1:${port}`, server, opts, received, removedScripts, filledText, clearedNodes,
        methods: () => received.filter(f => typeof f.id === 'number' && f.id >= 0x40000000).map(f => String(f.method)),
      });
    });
  });
}

describe('login driver', () => {
  let tokenStore: TokenStore;
  let cdpSessionStore: CdpSessionStore;
  let proxy: CdpProxyHandle;
  let browser: Awaited<ReturnType<typeof fakeBrowser>>;
  let client: WebSocket;

  afterEach(async () => {
    client?.close();
    await proxy?.close();
    browser?.server.close();
    tokenStore?.destroy();
    cdpSessionStore?.destroy();
  });

  /** Connect, attach a page target with a committed origin, register scripts, return [sid, conn]. */
  async function connect(agentScripts: string[] = []) {
    tokenStore = new TokenStore();
    cdpSessionStore = new CdpSessionStore();
    browser = await fakeBrowser();
    const sid = cdpSessionStore.register(browser.url);
    proxy = await startCdpProxy({ tokenStore, cdpSessionStore, port: 0 });
    client = new WebSocket(`ws://127.0.0.1:${proxy.port}/cdp/${sid}`);
    await once(client, 'open');
    await new Promise(r => setTimeout(r, 30));
    const conn = cdpSessionStore.controller(sid) as unknown as import('./proxy.js').CdpConnection;

    // The browser attaches the page target and the agent navigates to the login page.
    browser.server.clients.forEach(w => w.send(JSON.stringify({ method: 'Target.attachedToTarget', params: { sessionId: 'P1', targetInfo: { type: 'page', targetId: 'TP1' } } })));
    browser.server.clients.forEach(w => w.send(JSON.stringify({ method: 'Page.frameNavigated', sessionId: 'P1', params: { frame: { id: 'F1', url: 'https://login.example.com/login', loaderId: 'L0' } } })));
    await new Promise(r => setTimeout(r, 30));

    // The agent registers new-document scripts (tracked via their responses).
    let idc = 1;
    for (const source of agentScripts) {
      const id = idc++;
      client.send(JSON.stringify({ id, sessionId: 'P1', method: 'Page.addScriptToEvaluateOnNewDocument', params: { source } }));
      await new Promise(r => setTimeout(r, 5));
      browser.server.clients.forEach(w => w.send(JSON.stringify({ id, sessionId: 'P1', result: { identifier: `script-${id}` } })));
    }
    await new Promise(r => setTimeout(r, 20));
    return { sid, conn };
  }

  const baseReq = (over: Partial<LoginRequest> = {}): LoginRequest => ({
    fields: { username: '#user', password: '#pass' },
    values: { username: 'alice@example.com', password: 'hunter2-real-pw' },
    cleartextFields: [],
    secretName: 'example-login',
    allowedHosts: hosts('login.example.com'),
    submit: { selector: '#go' },
    until: { kind: 'navigation' },
    timeoutMs: 3000,
    ...over,
  });

  it('removes the agent scripts, reloads, fills real values, submits, waits and returns 200', async () => {
    const { conn } = await connect(['window.__spy=1', 'window.__spy2=1']);
    const result = await conn.login(baseReq());
    expect(result).toEqual({ status: 200, url: 'https://login.example.com/home' });
    expect(browser.removedScripts.sort()).toEqual(['script-1', 'script-2']);
    expect(browser.filledText).toEqual(['alice@example.com', 'hunter2-real-pw']);
    // The reload happened before any fill.
    const methods = browser.methods();
    expect(methods.indexOf('Page.reload')).toBeLessThan(methods.indexOf('Input.insertText'));
  });

  it('supports an SPA login via until.selector and clears the field afterwards', async () => {
    const { conn } = await connect();
    browser.opts.navigateOnSubmit = false;
    browser.opts.appearAfterSubmit = '#done';
    const result = await conn.login(baseReq({ until: { kind: 'selector', selector: '#done' } }));
    expect(result.status).toBe(200);
    // The fields were cleared after success (Runtime.callFunctionOn ran on them).
    expect(browser.clearedNodes.length).toBeGreaterThanOrEqual(2);
  });

  it('empties the filled fields and returns 409 no-success on timeout', async () => {
    const { conn } = await connect();
    browser.opts.navigateOnSubmit = false; // nothing satisfies `until: navigation`
    const result = await conn.login(baseReq({ timeoutMs: 400 }));
    expect(result).toEqual({ status: 409, reason: 'no-success', cleared: true });
    // Fill (2) then clear (2): the real value was typed then wiped.
    expect(browser.clearedNodes.length).toBeGreaterThanOrEqual(2);
  });

  it('refuses a page on a disallowed origin with 403, filling nothing', async () => {
    const { conn } = await connect();
    browser.opts.url = 'https://attacker.example/login';
    // The committed origin is still login.example.com until a navigation; move it.
    browser.server.clients.forEach(w => w.send(JSON.stringify({ method: 'Page.frameNavigated', sessionId: 'P1', params: { frame: { id: 'F1', url: 'https://attacker.example/login', loaderId: 'L9' } } })));
    await new Promise(r => setTimeout(r, 20));
    const result = await conn.login(baseReq());
    expect(result.status).toBe(403);
    expect(browser.filledText).toEqual([]);
  });

  it('returns 404 selector-not-found for a field whose selector matches nothing', async () => {
    const { conn } = await connect();
    browser.opts.selectors.set('#pass', 0);
    const result = await conn.login(baseReq());
    expect(result).toEqual({ status: 404, reason: 'selector-not-found', field: 'password' });
  });

  it('fills nothing when a later field selector matches nothing (password must not stay in the page)', async () => {
    // Attack: list the password first and point a later field at nothing, so a
    // fill-as-you-go driver would leave the real password in the DOM for agent
    // script to read once its frames are released.
    const { conn } = await connect();
    browser.opts.selectors.set('#missing', 0);
    const result = await conn.login(baseReq({ fields: { password: '#pass', username: '#missing' } }));
    expect(result).toEqual({ status: 404, reason: 'selector-not-found', field: 'username' });
    expect(browser.filledText).toEqual([]);
    expect(browser.received.some(f => f.method === 'Input.insertText')).toBe(false);
  });

  it('returns 409 interception-active when request interception is on', async () => {
    const { conn } = await connect();
    client.send(JSON.stringify({ id: 500, sessionId: 'P1', method: 'Fetch.enable', params: { patterns: [{ urlPattern: '*' }] } }));
    await new Promise(r => setTimeout(r, 20));
    const result = await conn.login(baseReq());
    expect(result).toEqual({ status: 409, reason: 'interception-active' });
  });

  it('returns 409 busy when a login is already running', async () => {
    const { conn } = await connect();
    browser.opts.navigateOnSubmit = false;
    const first = conn.login(baseReq({ timeoutMs: 800 }));
    await new Promise(r => setTimeout(r, 50));
    const second = await conn.login(baseReq());
    expect(second).toEqual({ status: 409, reason: 'busy' });
    await first;
  });

  it('queues agent frames during the window and releases them afterwards', async () => {
    const { conn } = await connect();
    const p = conn.login(baseReq());
    // An agent frame sent mid-window must not reach the browser until after.
    client.send(JSON.stringify({ id: 7, sessionId: 'P1', method: 'Runtime.evaluate', params: { expression: '1' } }));
    await p;
    await new Promise(r => setTimeout(r, 30));
    const evals = browser.received.filter(f => f.method === 'Runtime.evaluate');
    expect(evals.length).toBe(1); // it arrived, but only after the window
  });
});
