import { describe, it, expect } from 'vitest';
import { browserbaseAdapter, builtinBrowserAdapters, createBrowserbaseAdapter } from './browser-adapters.js';

const register = (u: string) => `ws://local/cdp/${Buffer.from(u).toString('hex').slice(0, 8)}`;
function rewrite(body: unknown) {
  const seen: string[] = [];
  const changed = browserbaseAdapter.rewriteJson(body, u => { seen.push(u); return register(u); });
  return { body, seen, changed };
}

describe('Browserbase adapter', () => {
  it('rewrites Browserbase ws(s) URLs by value, under any key and in arrays', () => {
    const { body, seen, changed } = rewrite({
      connectUrl: 'wss://connect.browserbase.com?signingKey=SK',
      nested: { anything: 'wss://connect.usw2.browserbase.com/debug/x' },
      list: ['ws://browserbase.com/y', 'plain string'],
    });
    expect(changed).toBe(true);
    expect(seen).toEqual(['wss://connect.browserbase.com?signingKey=SK', 'wss://connect.usw2.browserbase.com/debug/x', 'ws://browserbase.com/y']);
    expect(JSON.stringify(body)).not.toContain('browserbase.com');
    expect((body as { list: string[] }).list[1]).toBe('plain string');
  });

  it('checks the parsed hostname, not a substring', () => {
    const input = { a: 'wss://evilbrowserbase.com/x', b: 'wss://browserbase.com.evil.test/x', c: 'https://connect.browserbase.com/x' };
    const { body, seen, changed } = rewrite({ ...input });
    expect(seen).toEqual([]);
    expect(changed).toBe(false);
    expect(body).toEqual(input);
  });

  it('rewrites connectUrl on any host (it is the CDP endpoint by definition)', () => {
    const { seen } = rewrite({ connectUrl: 'wss://connect.newvendor-domain.test/s' });
    expect(seen).toEqual(['wss://connect.newvendor-domain.test/s']);
  });

  it('deletes signingKey and viewer URLs that embed a Browserbase ws target', () => {
    const { body, changed } = rewrite({
      signingKey: 'SK',
      liveView: 'https://www.browserbase.com/devtools/inspector.html?wss=connect.browserbase.com/debug/x',
      schemed: 'https://viewer.test/?target=wss%3A%2F%2Fconnect.browserbase.com%2Fdebug%2Fx',
      debuggerUrl: 'https://www.browserbase.com/sessions/x/pages/y/fullscreen',
      keep: 'https://example.com/?wss=connect.example.org/x',
    });
    expect(changed).toBe(true);
    expect(body).toEqual({ keep: 'https://example.com/?wss=connect.example.org/x' });
  });

  it('deletes seleniumRemoteUrl from a session response (an HTTP route past the CDP proxy)', () => {
    const { body, changed } = rewrite({ id: 's1', status: 'RUNNING', seleniumRemoteUrl: 'https://connect.browserbase.com/webdriver', signingKey: 'SK' });
    expect(changed).toBe(true);
    expect(body).toEqual({ id: 's1', status: 'RUNNING' });
  });

  it('leaves unrelated responses unchanged', () => {
    const input = { id: 's1', status: 'RUNNING', region: 'us-west-2', projectId: 'p' };
    const { body, changed } = rewrite({ ...input });
    expect(changed).toBe(false);
    expect(body).toEqual(input);
  });

  it('strips extensionId from a session-create request body (top level and browserSettings)', () => {
    const body: Record<string, unknown> = { projectId: 'p', extensionId: 'ext-1', browserSettings: { extensionId: 'ext-2', viewport: { width: 1280, height: 720 } } };
    const changed = browserbaseAdapter.rewriteRequestJson!(body);
    expect(changed).toBe(true);
    expect(body).toEqual({ projectId: 'p', browserSettings: { viewport: { width: 1280, height: 720 } } });
  });

  it('leaves a request body with no extension params unchanged', () => {
    const body = { projectId: 'p', browserSettings: { viewport: { width: 1280, height: 720 } } };
    expect(browserbaseAdapter.rewriteRequestJson!({ ...body, browserSettings: { ...body.browserSettings } })).toBe(false);
  });

  it('defaults to api.browserbase.com and allows a host override', () => {
    expect(browserbaseAdapter.hosts).toEqual(['api.browserbase.com']);
    expect(createBrowserbaseAdapter('127.0.0.1').hosts).toEqual(['127.0.0.1']);
  });

  it('resolves built-ins by name', () => {
    expect(builtinBrowserAdapters(['browserbase'])).toEqual([browserbaseAdapter]);
    expect(() => builtinBrowserAdapters(['nope'])).toThrow(/unknown browser adapter/);
  });
});
