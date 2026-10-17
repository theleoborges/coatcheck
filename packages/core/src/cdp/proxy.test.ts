import { describe, it, expect, afterEach } from 'vitest';
import { WebSocketServer, WebSocket } from 'ws';
import type { AddressInfo } from 'node:net';
import { TokenStore } from '../token-store.js';
import { CdpSessionStore } from '../cdp-session-store.js';
import { startCdpProxy, type CdpProxyHandle } from './proxy.js';
import { parseHostPattern, type HostPattern } from '../host-matcher.js';

const hosts = (...entries: string[]) => entries.map(e => parseHostPattern(e) as HostPattern);

function once<T = unknown>(emitter: { once(event: string, cb: (...a: unknown[]) => void): unknown }, event: string): Promise<T> {
  return new Promise(resolve => emitter.once(event, (...args: unknown[]) => resolve(args[0] as T)));
}

/** A fake Browserbase CDP upstream that records the frames it receives. */
function fakeUpstream(): Promise<{ url: string; received: string[]; server: WebSocketServer; pushToClient: (s: string) => void }> {
  return new Promise(resolve => {
    const received: string[] = [];
    let conn: WebSocket | null = null;
    const server = new WebSocketServer({ host: '127.0.0.1', port: 0 });
    server.on('connection', ws => {
      conn = ws;
      ws.on('message', (data: Buffer) => received.push(data.toString()));
    });
    server.on('listening', () => {
      const { port } = server.address() as AddressInfo;
      resolve({
        url: `ws://127.0.0.1:${port}`,
        received,
        server,
        pushToClient: (s: string) => conn?.send(s),
      });
    });
  });
}

describe('CDP proxy', () => {
  let tokenStore: TokenStore;
  let cdpSessionStore: CdpSessionStore;
  let proxy: CdpProxyHandle;
  let upstream: Awaited<ReturnType<typeof fakeUpstream>>;
  let client: WebSocket;

  afterEach(async () => {
    client?.close();
    await proxy?.close();
    upstream?.server.close();
    tokenStore?.destroy();
    cdpSessionStore?.destroy();
  });

  async function setup() {
    tokenStore = new TokenStore();
    cdpSessionStore = new CdpSessionStore();
    upstream = await fakeUpstream();
    const sid = cdpSessionStore.register(upstream.url);
    proxy = await startCdpProxy({ tokenStore, cdpSessionStore, port: 0 });
    client = new WebSocket(`ws://127.0.0.1:${proxy.port}/cdp/${sid}`);
    await once(client, 'open');
    // give the proxy a tick to open the upstream leg
    await new Promise(r => setTimeout(r, 50));
    return sid;
  }

  it('rejects a connection for an unknown session', async () => {
    tokenStore = new TokenStore();
    cdpSessionStore = new CdpSessionStore();
    proxy = await startCdpProxy({ tokenStore, cdpSessionStore, port: 0 });
    client = new WebSocket(`ws://127.0.0.1:${proxy.port}/cdp/deadbeef`);
    const code = await once<number>(client, 'close');
    expect(code).toBe(1008);
  });

  /** The browser reports a committed main-frame navigation on flattened session T1. */
  async function navigated(url: string, sessionId = 'T1') {
    upstream.pushToClient(JSON.stringify({ method: 'Page.frameNavigated', sessionId, params: { frame: { id: 'F1', url } } }));
    await once(client, 'message');
  }

  it('substitutes an outbound token (page.fill) on an allowed origin before it reaches upstream', async () => {
    const sid = await setup();
    const tok = tokenStore.issue('site:password', 'real-secret-42', { sessionId: sid, allowedHosts: hosts('login.example.com') }).id;
    await navigated('https://login.example.com/signin');

    client.send(JSON.stringify({ id: 1, sessionId: 'T1', method: 'Input.insertText', params: { text: tok } }));
    await new Promise(r => setTimeout(r, 50));

    expect(upstream.received).toHaveLength(1);
    expect(JSON.parse(upstream.received[0]).params.text).toBe('real-secret-42');
  });

  // Attack (roadmap item 15): fill a login ticket into a page on another origin.
  it('refuses a fill on another origin: nothing reaches upstream, the caller gets a CDP error', async () => {
    const sid = await setup();
    const tok = tokenStore.issue('site:password', 'real-secret-42', { sessionId: sid, allowedHosts: hosts('login.example.com') }).id;
    await navigated('https://attacker.example/fake-login');

    const errP = once<Buffer>(client, 'message');
    client.send(JSON.stringify({ id: 9, sessionId: 'T1', method: 'Input.insertText', params: { text: tok } }));
    const err = JSON.parse((await errP).toString());
    expect(err).toEqual({
      id: 9,
      sessionId: 'T1',
      error: { code: -32000, message: 'credential-origin violation: site:password not allowed on https://attacker.example' },
    });
    await new Promise(r => setTimeout(r, 50));
    expect(upstream.received).toHaveLength(0);
  });

  it('refuses a fill when no navigation was seen, and during a navigation', async () => {
    const sid = await setup();
    const tok = tokenStore.issue('site:password', 'real-secret-42', { sessionId: sid, allowedHosts: hosts('login.example.com') }).id;

    let errP = once<Buffer>(client, 'message');
    client.send(JSON.stringify({ id: 1, sessionId: 'T1', method: 'Input.insertText', params: { text: tok } }));
    expect(JSON.parse((await errP).toString()).error.message).toContain('page origin unknown');

    // On the login page, the agent starts navigating away and fills immediately.
    await navigated('https://login.example.com/signin');
    client.send(JSON.stringify({ id: 2, sessionId: 'T1', method: 'Page.navigate', params: { url: 'https://attacker.example/' } }));
    errP = once<Buffer>(client, 'message');
    client.send(JSON.stringify({ id: 3, sessionId: 'T1', method: 'Input.insertText', params: { text: tok } }));
    expect(JSON.parse((await errP).toString()).error.message).toContain('a navigation is in progress');

    await new Promise(r => setTimeout(r, 50));
    expect(upstream.received.map(f => JSON.parse(f).method)).toEqual(['Page.navigate']);
    expect(upstream.received.join('')).not.toContain('real-secret-42');
  });

  it('redacts an inbound echo-back of the real value', async () => {
    const sid = await setup();
    tokenStore.issue('site:password', 'real-secret-42', { sessionId: sid });

    const msgP = once<Buffer>(client, 'message');
    upstream.pushToClient(JSON.stringify({ id: 2, result: { value: 'real-secret-42' } }));
    const msg = await msgP;
    expect(JSON.parse(msg.toString()).result.value).toBe('[REDACTED:site:password]');
  });

  it('drops an inbound frame that carries the real value unparseably', async () => {
    const sid = await setup();
    tokenStore.issue('site:password', 'real-secret-42', { sessionId: sid });

    const msgP = once<Buffer>(client, 'message');
    upstream.pushToClient('GARBAGE real-secret-42 GARBAGE'); // should be dropped
    upstream.pushToClient(JSON.stringify({ id: 3, sentinel: true })); // should arrive
    const msg = await msgP;
    expect(JSON.parse(msg.toString()).sentinel).toBe(true);
  });

  it('fails closed when page.type() spells a token, and never forwards the completing keystroke', async () => {
    const sid = await setup();
    const tok = tokenStore.issue('site:password', 'real-secret-42', { sessionId: sid }).id;

    const errP = once<Buffer>(client, 'message');
    for (const ch of tok) {
      client.send(JSON.stringify({ id: 99, method: 'Input.dispatchKeyEvent', params: { text: ch } }));
    }
    const err = await errP;
    const parsed = JSON.parse(err.toString());
    expect(parsed.error.code).toBe(-32000);
    expect(parsed.error.message).toContain('page.fill()');

    await new Promise(r => setTimeout(r, 50));
    // The completing keystroke was dropped: upstream saw fewer frames than chars typed.
    expect(upstream.received.length).toBeLessThan(tok.length);
    // and the real value never reached upstream
    expect(upstream.received.join('')).not.toContain('real-secret-42');
  });

  it('revokes session tokens when the client disconnects', async () => {
    const sid = await setup();
    tokenStore.issue('site:password', 'real-secret-42', { sessionId: sid });
    expect(tokenStore.sessionValues(sid)).toHaveLength(1);

    client.close();
    await new Promise(r => setTimeout(r, 50));
    expect(tokenStore.sessionValues(sid)).toHaveLength(0);
    expect(cdpSessionStore.get(sid)).toBeNull();
  });

  it('keeps a connected sid live until the connection closes, then refuses it', async () => {
    const sid = await setup();
    expect(cdpSessionStore.has(sid)).toBe(true);
    // Connected: no longer subject to the registration TTL.
    const realNow = Date.now;
    Date.now = () => realNow() + 3_600_000;
    try {
      expect(cdpSessionStore.has(sid)).toBe(true);
    } finally {
      Date.now = realNow;
    }
    client.close();
    await new Promise(r => setTimeout(r, 50));
    expect(cdpSessionStore.has(sid)).toBe(false);
  });
});
