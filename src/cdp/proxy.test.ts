import { describe, it, expect, afterEach } from 'vitest';
import { WebSocketServer, WebSocket } from 'ws';
import type { AddressInfo } from 'node:net';
import { TokenStore } from '../token-store.js';
import { CdpSessionStore } from '../cdp-session-store.js';
import { startCdpProxy, type CdpProxyHandle } from './proxy.js';

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

  it('substitutes an outbound token (page.fill) before it reaches upstream', async () => {
    const sid = await setup();
    const tok = tokenStore.issueForSession('site:password', 'real-secret-42', sid).id;

    client.send(JSON.stringify({ id: 1, method: 'Input.insertText', params: { text: tok } }));
    await new Promise(r => setTimeout(r, 50));

    expect(upstream.received).toHaveLength(1);
    expect(JSON.parse(upstream.received[0]).params.text).toBe('real-secret-42');
  });

  it('redacts an inbound echo-back of the real value', async () => {
    const sid = await setup();
    tokenStore.issueForSession('site:password', 'real-secret-42', sid);

    const msgP = once<Buffer>(client, 'message');
    upstream.pushToClient(JSON.stringify({ id: 2, result: { value: 'real-secret-42' } }));
    const msg = await msgP;
    expect(JSON.parse(msg.toString()).result.value).toBe('[REDACTED:site:password]');
  });

  it('drops an inbound frame that carries the real value unparseably', async () => {
    const sid = await setup();
    tokenStore.issueForSession('site:password', 'real-secret-42', sid);

    const msgP = once<Buffer>(client, 'message');
    upstream.pushToClient('GARBAGE real-secret-42 GARBAGE'); // should be dropped
    upstream.pushToClient(JSON.stringify({ id: 3, sentinel: true })); // should arrive
    const msg = await msgP;
    expect(JSON.parse(msg.toString()).sentinel).toBe(true);
  });

  it('fails closed when page.type() spells a token, and never forwards the completing keystroke', async () => {
    const sid = await setup();
    const tok = tokenStore.issueForSession('site:password', 'real-secret-42', sid).id;

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
    tokenStore.issueForSession('site:password', 'real-secret-42', sid);
    expect(tokenStore.sessionValues(sid)).toHaveLength(1);

    client.close();
    await new Promise(r => setTimeout(r, 50));
    expect(tokenStore.sessionValues(sid)).toHaveLength(0);
    expect(cdpSessionStore.get(sid)).toBeNull();
  });
});
