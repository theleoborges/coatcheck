/**
 * End-to-end broker-performed login (roadmap item 20): a real Chromium, driven
 * by Playwright through coatcheck's CDP proxy. The agent calls the login
 * controller (what `POST /_vault/{name}/login` invokes); coatcheck fills and
 * submits the form itself over the CDP connection. No credential ticket ever
 * enters the browser. Two hostnames resolve to one local HTTP server; the login
 * is bound to `http://login.test` only.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import http from 'node:http';
import net, { type AddressInfo } from 'node:net';
import { chromium, type Browser } from 'playwright';
import { TokenStore } from '../token-store.js';
import { CdpSessionStore, type LoginRequest } from '../cdp-session-store.js';
import { startCdpProxy, type CdpProxyHandle, type CdpConnection } from './proxy.js';
import { parseHostPattern, type HostPattern } from '../host-matcher.js';

const REAL = { user: 'alice', email: 'alice@example.com', pass: 'hunter2-real-pw' };

const FORM = `<!doctype html><form method="post" action="/submit">
  <input id="user" name="user" type="text">
  <input id="email" name="email" type="email">
  <input id="pass" name="pass" type="password">
  <button id="go" type="submit">Sign in</button>
</form>`;

// An SPA-style login: submit is handled in-page (no navigation); on click the
// page's own script reveals #done. Used for until.selector and the field-clear
// and listener tests, where the document must persist across the submit.
const SPA = `<!doctype html><form id="f" onsubmit="return false">
  <input id="user" name="user" type="text">
  <input id="email" name="email" type="email">
  <input id="pass" name="pass" type="password">
  <button id="go" type="button">Sign in</button>
</form>
<script>
  document.getElementById('go').addEventListener('click', () => {
    const p = document.createElement('p'); p.id = 'done'; p.textContent = 'ok';
    document.body.appendChild(p);
  });
</script>`;

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
      res.end(req.url === '/submit' ? '<p id="done">ok</p>' : (req.url?.startsWith('/spa') ? SPA : FORM));
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
  (globalThis as { __wsUrl?: string }).__wsUrl = browserWsUrl;
}, 30_000);

/** A fresh sid for one test (the proxy revokes a sid when its connection closes). */
function newSid(): string {
  return cdpSessionStore.register((globalThis as { __wsUrl?: string }).__wsUrl!, 'test');
}

afterAll(async () => {
  await proxy?.close();
  tokenStore?.destroy();
  cdpSessionStore?.destroy();
  await launched?.close();
  server?.close();
});

const loginHosts = (...h: string[]) => h.map(x => parseHostPattern(x) as HostPattern);

/** The login request the vault handler would build for the test credential. */
function loginReq(over: Partial<LoginRequest> = {}): LoginRequest {
  return {
    fields: { user: '#user', email: '#email', password: '#pass' },
    values: { user: REAL.user, email: REAL.email, password: REAL.pass },
    cleartextFields: [],
    secretName: 'example-login',
    allowedHosts: loginHosts('http://login.test'),
    submit: { selector: '#go' },
    until: { kind: 'navigation' },
    timeoutMs: 8000,
    ...over,
  };
}

describe('broker-performed login e2e (Playwright + Chromium)', () => {
  it('fills and submits a full-page login on the allowed origin; the agent never sends the values', async () => {
    const sid = newSid();
    const browser: Browser = await chromium.connectOverCDP(`ws://127.0.0.1:${proxy.port}/cdp/${sid}`);
    try {
      const context = browser.contexts()[0] ?? await browser.newContext();
      const page = await context.newPage();
      await page.goto(`http://login.test:${httpPort}/`);
      await new Promise(r => setTimeout(r, 200)); // let attach/frameNavigated settle

      const conn = cdpSessionStore.controller(sid) as unknown as CdpConnection;
      tokenStore.registerSessionValues(sid, [{ value: REAL.pass, secretName: 'example-login:password' }]);
      const result = await conn.login(loginReq());

      expect(result.status).toBe(200);
      const login = received.find(r => r.host === 'login.test' && r.body !== '');
      expect(login).toBeDefined();
      expect(new URLSearchParams(login!.body)).toEqual(new URLSearchParams(REAL));
    } finally {
      await browser.close();
    }
  }, 60_000);

  it('refuses a login on a disallowed origin (403); the site never receives the real password', async () => {
    const sid = newSid();
    const browser: Browser = await chromium.connectOverCDP(`ws://127.0.0.1:${proxy.port}/cdp/${sid}`);
    try {
      const context = browser.contexts()[0] ?? await browser.newContext();
      const page = await context.newPage();
      await page.goto(`http://evil.test:${httpPort}/`);
      await new Promise(r => setTimeout(r, 200));

      const conn = cdpSessionStore.controller(sid) as unknown as CdpConnection;
      const result = await conn.login(loginReq());
      expect(result.status).toBe(403);
      // Nothing the site received on evil.test carries the real password.
      expect(received.filter(r => r.host === 'evil.test').map(r => r.body).join('')).not.toContain(REAL.pass);
    } finally {
      await browser.close();
    }
  }, 60_000);

  it('logs in an SPA-style form via until.selector, then the password field is empty', async () => {
    const sid = newSid();
    const browser = await chromium.connectOverCDP(`ws://127.0.0.1:${proxy.port}/cdp/${sid}`);
    try {
      const page = (browser.contexts()[0] ?? await browser.newContext()).pages()[0] ?? await (browser.contexts()[0]).newPage();
      await page.goto(`http://login.test:${httpPort}/spa`);
      await new Promise(r => setTimeout(r, 200));
      const conn = cdpSessionStore.controller(sid) as unknown as CdpConnection;
      const result = await conn.login(loginReq({ until: { kind: 'selector', selector: '#done' } }));
      expect(result.status).toBe(200);
      // After success coatcheck empties the still-mounted field.
      expect(await page.inputValue('#pass')).toBe('');
    } finally {
      await browser.close();
    }
  }, 60_000);

  it('empties the filled fields when the success condition times out', async () => {
    const sid = newSid();
    const browser = await chromium.connectOverCDP(`ws://127.0.0.1:${proxy.port}/cdp/${sid}`);
    try {
      const page = (browser.contexts()[0] ?? await browser.newContext()).pages()[0] ?? await (browser.contexts()[0]).newPage();
      await page.goto(`http://login.test:${httpPort}/spa`);
      await new Promise(r => setTimeout(r, 200));
      const conn = cdpSessionStore.controller(sid) as unknown as CdpConnection;
      // #never never appears → timeout; fields coatcheck filled are emptied first.
      const result = await conn.login(loginReq({ until: { kind: 'selector', selector: '#never' }, timeoutMs: 1500 }));
      expect(result).toMatchObject({ status: 409, reason: 'no-success', cleared: true });
      expect(await page.inputValue('#pass')).toBe('');
    } finally {
      await browser.close();
    }
  }, 60_000);

  it('a pre-installed input listener and a registered new-document script see nothing', async () => {
    const sid = newSid();
    const browser = await chromium.connectOverCDP(`ws://127.0.0.1:${proxy.port}/cdp/${sid}`);
    try {
      const page = (browser.contexts()[0] ?? await browser.newContext()).pages()[0] ?? await (browser.contexts()[0]).newPage();
      // The agent registers a new-document script (via CDP) before navigating.
      await page.addInitScript(() => { (window as unknown as Record<string, unknown>).__newDocRan = true; });
      await page.goto(`http://login.test:${httpPort}/spa`);
      // ...and installs an input listener on the live document that would exfiltrate values.
      await page.evaluate(() => {
        const w = window as unknown as Record<string, unknown>;
        w.__leaked = [] as string[];
        document.addEventListener('input', e => (w.__leaked as string[]).push((e.target as HTMLInputElement).value), true);
      });
      await new Promise(r => setTimeout(r, 200));

      const conn = cdpSessionStore.controller(sid) as unknown as CdpConnection;
      const result = await conn.login(loginReq({ until: { kind: 'selector', selector: '#done' } }));
      expect(result.status).toBe(200); // the fill happened on the reloaded document

      // The new-document script was removed before the reload, so it didn't run;
      // the listener lived on the old document, which the reload discarded.
      const newDocRan = await page.evaluate(() => (window as unknown as Record<string, unknown>).__newDocRan);
      const leaked = await page.evaluate(() => (window as unknown as Record<string, unknown>).__leaked);
      expect(newDocRan).toBeFalsy();
      expect(leaked).toBeFalsy();
    } finally {
      await browser.close();
    }
  }, 60_000);

  it('refuses the login with 409 when the agent has request interception enabled', async () => {
    const sid = newSid();
    const browser = await chromium.connectOverCDP(`ws://127.0.0.1:${proxy.port}/cdp/${sid}`);
    try {
      const context = browser.contexts()[0] ?? await browser.newContext();
      const page = context.pages()[0] ?? await context.newPage();
      await page.route('**/*', route => route.continue()); // enables Fetch interception
      await page.goto(`http://login.test:${httpPort}/`);
      await new Promise(r => setTimeout(r, 200));
      const conn = cdpSessionStore.controller(sid) as unknown as CdpConnection;
      const result = await conn.login(loginReq());
      expect(result).toMatchObject({ status: 409, reason: 'interception-active' });
    } finally {
      await browser.close();
    }
  }, 60_000);

  // The four reads from examples/agents/browser-login/attack-transform.md: the
  // agent tries to read the password back in transformed forms. After a login
  // there is no live value to read (the fill ran while the agent was quiesced,
  // on a document it could not instrument, and the field is gone/cleared).
  it('the four transform reads return nothing derived from the password', async () => {
    const sid = newSid();
    const browser = await chromium.connectOverCDP(`ws://127.0.0.1:${proxy.port}/cdp/${sid}`);
    try {
      const context = browser.contexts()[0] ?? await browser.newContext();
      const page = context.pages()[0] ?? await context.newPage();
      await page.goto(`http://login.test:${httpPort}/`);
      await new Promise(r => setTimeout(r, 200));
      const conn = cdpSessionStore.controller(sid) as unknown as CdpConnection;
      const result = await conn.login(loginReq());
      expect(result.status).toBe(200);

      // raw, base64, reversed, char codes — of whatever the password field holds now.
      const reads = await page.evaluate(() => {
        const el = document.querySelector('#pass') as HTMLInputElement | null;
        const v = el ? el.value : '';
        return { raw: v, b64: v ? btoa(v) : '', reversed: v.split('').reverse().join(''), codes: v.split('').map(c => c.charCodeAt(0)).join(',') };
      });

      // None of the four reads yields material derived from the real password.
      const pass = REAL.pass;
      const derived = [pass, Buffer.from(pass).toString('base64'), pass.split('').reverse().join(''), pass.split('').map(c => c.charCodeAt(0)).join(',')];
      const haystack = Object.values(reads).join('\u0000');
      for (const form of derived) expect(haystack.includes(form)).toBe(false);
    } finally {
      await browser.close();
    }
  }, 60_000);
});
