/**
 * End-to-end CDP injection (roadmap item 15): a real Chromium, driven by
 * Playwright through coatcheck's CDP proxy. Two hostnames resolve to one
 * local HTTP server; login tickets are bound to `http://login.test` only.
 */
import { describe, it, expect, beforeAll, afterAll, vi } from 'vitest';
import http from 'node:http';
import net, { type AddressInfo } from 'node:net';
import { chromium, type Browser } from 'playwright';
import { TokenStore } from '../token-store.js';
import { CdpSessionStore } from '../cdp-session-store.js';
import { startCdpProxy, type CdpProxyHandle } from './proxy.js';
import { parseHostPattern, type HostPattern } from '../host-matcher.js';

const REAL = { user: 'alice', email: 'alice@example.com', pass: 'hunter2-real-pw' };

const FORM = `<!doctype html><form method="post" action="/submit">
  <input id="user" name="user" type="text">
  <input id="email" name="email" type="email">
  <input id="pass" name="pass" type="password">
  <button id="go" type="submit">Sign in</button>
</form>`;

let server: http.Server;
let httpPort: number;
/** Every request the site received: host and raw body. */
const received: Array<{ host: string; body: string }> = [];
let launched: Browser;
let tokenStore: TokenStore;
let cdpSessionStore: CdpSessionStore;
let proxy: CdpProxyHandle;

function startSite(): Promise<void> {
  server = http.createServer((req, res) => {
    let body = '';
    req.on('data', c => { body += c; });
    req.on('end', () => {
      received.push({ host: (req.headers.host ?? '').split(':')[0], body });
      res.writeHead(200, { 'Content-Type': 'text/html' });
      res.end(req.url === '/submit' ? '<p id="done">ok</p>' : FORM);
    });
  });
  return new Promise(resolve => server.listen(0, '127.0.0.1', () => {
    httpPort = (server.address() as AddressInfo).port;
    resolve();
  }));
}

function freePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const probe = net.createServer().listen(0, '127.0.0.1', () => {
      const { port } = probe.address() as AddressInfo;
      probe.close(() => resolve(port));
    }).on('error', reject);
  });
}

/**
 * Launch Chromium (Playwright's build and flags) with an extra CDP port, and
 * return its browser WebSocket URL: the "remote browser" behind coatcheck.
 */
async function launchChrome(): Promise<string> {
  const cdpPort = await freePort();
  launched = await chromium.launch({
    args: [`--remote-debugging-port=${cdpPort}`, '--host-resolver-rules=MAP login.test 127.0.0.1, MAP evil.test 127.0.0.1'],
  });
  const version = await (await fetch(`http://127.0.0.1:${cdpPort}/json/version`)).json() as { webSocketDebuggerUrl: string };
  return version.webSocketDebuggerUrl;
}

beforeAll(async () => {
  await startSite();
  const browserWsUrl = await launchChrome();
  tokenStore = new TokenStore();
  cdpSessionStore = new CdpSessionStore();
  proxy = await startCdpProxy({ tokenStore, cdpSessionStore, port: 0, bindHost: '127.0.0.1' });
  // As a browser adapter would after rewriting a session-create response.
  (globalThis as { __sid?: string }).__sid = cdpSessionStore.register(browserWsUrl, 'test');
}, 30_000);

afterAll(async () => {
  await proxy?.close();
  tokenStore?.destroy();
  cdpSessionStore?.destroy();
  await launched?.close();
  server?.close();
});

describe('CDP injection e2e (Playwright + Chromium)', () => {
  it('page.fill substitutes on the allowed origin and is refused on another origin', async () => {
    const sid = (globalThis as { __sid?: string }).__sid!;
    const allowedHosts = [parseHostPattern('http://login.test') as HostPattern];
    const opts = { sessionId: sid, allowedHosts };
    const tickets = {
      user: tokenStore.issue('example-login:user', REAL.user, opts).id,
      email: tokenStore.issue('example-login:email', REAL.email, opts).id,
      pass: tokenStore.issue('example-login:password', REAL.pass, opts).id,
    };

    const browser: Browser = await chromium.connectOverCDP(`ws://127.0.0.1:${proxy.port}/cdp/${sid}`);
    try {
      const context = browser.contexts()[0] ?? await browser.newContext();
      const page = await context.newPage();

      // Allowed origin: text, email and password inputs all receive the real value.
      await page.goto(`http://login.test:${httpPort}/`);
      await page.fill('#user', tickets.user);
      await page.fill('#email', tickets.email);
      await page.fill('#pass', tickets.pass);
      await Promise.all([page.waitForSelector('#done'), page.click('#go')]);
      const login = received.find(r => r.host === 'login.test' && r.body !== '');
      expect(new URLSearchParams(login!.body)).toEqual(new URLSearchParams(REAL));

      // Attack: same tickets, page on another origin. The fill is refused and
      // the site never sees the real value.
      await page.goto(`http://evil.test:${httpPort}/`);
      // Playwright retries any CDP error that isn't a JavaScript or session-closed
      // error, so every retry is refused until the action times out.
      const warn = vi.spyOn(console, 'warn');
      try {
        await expect(page.fill('#pass', tickets.pass, { timeout: 2000 })).rejects.toThrow(/Timeout 2000ms exceeded/);
        const denials = warn.mock.calls.map(c => String(c[0])).filter(l => l.includes('origin binding refused Input.insertText secrets=example-login:password'));
        expect(denials.length).toBeGreaterThan(0);
      } finally {
        warn.mockRestore();
      }
      expect(await page.inputValue('#pass')).toBe('');
      await page.fill('#user', 'not-a-ticket'); // ordinary typing still works there
      await Promise.all([page.waitForSelector('#done'), page.click('#go')]);
      const evil = received.filter(r => r.host === 'evil.test' && r.body !== '');
      expect(evil).toHaveLength(1);
      expect(new URLSearchParams(evil[0].body).get('user')).toBe('not-a-ticket');
      expect(new URLSearchParams(evil[0].body).get('pass')).toBe('');
      expect(received.filter(r => r.host !== 'login.test').map(r => r.body).join('')).not.toContain(REAL.pass);
    } finally {
      await browser.close();
    }
  }, 60_000);
});
