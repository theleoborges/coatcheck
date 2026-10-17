import { describe, it, expect } from 'vitest';
import { OriginTracker } from './origin-tracker.js';

const nav = (url: string, opts: { sessionId?: string; frameId?: string; parentId?: string } = {}) => ({
  method: 'Page.frameNavigated',
  ...(opts.sessionId !== undefined ? { sessionId: opts.sessionId } : {}),
  params: { frame: { id: opts.frameId ?? 'F1', url, ...(opts.parentId ? { parentId: opts.parentId } : {}) } },
});

describe('OriginTracker', () => {
  it('records the main frame per flattened session', () => {
    const t = new OriginTracker();
    t.onInbound(nav('https://Login.Example.com/a?x', { sessionId: 'A' }));
    t.onInbound(nav('http://other.test:8080/', { sessionId: 'B' }));
    expect(t.originFor('A')).toEqual({ target: { host: 'login.example.com', scheme: 'https' } });
    expect(t.originFor('B')).toEqual({ target: { host: 'other.test', scheme: 'http' } });
    expect(t.originFor('C')).toEqual({ unknown: expect.stringContaining('no committed navigation') });
    expect(t.originFor(undefined)).toEqual({ unknown: expect.any(String) });
  });

  it('ignores child-frame navigations (iframes)', () => {
    const t = new OriginTracker();
    t.onInbound(nav('https://login.example.com/', { sessionId: 'A' }));
    t.onInbound(nav('https://attacker.example/frame', { sessionId: 'A', frameId: 'F2', parentId: 'F1' }));
    expect(t.originFor('A')).toEqual({ target: { host: 'login.example.com', scheme: 'https' } });
  });

  it('treats non-http(s) pages as unknown', () => {
    const t = new OriginTracker();
    for (const url of ['about:blank', 'data:text/html,<input>', 'chrome-error://chromewebdata/', 'file:///etc/passwd']) {
      t.onInbound(nav(url, { sessionId: 'A' }));
      expect(t.originFor('A')).toEqual({ unknown: expect.stringContaining('not http(s)') });
    }
  });

  it('is unknown from an outbound navigation until it commits', () => {
    const t = new OriginTracker();
    t.onInbound(nav('https://login.example.com/', { sessionId: 'A' }));
    for (const method of ['Page.navigate', 'Page.reload', 'Page.navigateToHistoryEntry']) {
      t.onOutbound({ id: 1, sessionId: 'A', method, params: {} });
      expect(t.originFor('A')).toEqual({ unknown: 'a navigation is in progress' });
      t.onInbound(nav('https://attacker.example/', { sessionId: 'A' }));
      expect(t.originFor('A')).toEqual({ target: { host: 'attacker.example', scheme: 'https' } });
    }
    // Other sessions are unaffected.
    t.onInbound(nav('https://b.example/', { sessionId: 'B' }));
    t.onOutbound({ id: 2, sessionId: 'A', method: 'Page.navigate', params: {} });
    expect(t.originFor('B')).toEqual({ target: { host: 'b.example', scheme: 'https' } });
  });

  it('clears a navigate that commits nothing: same-document or failed', () => {
    const t = new OriginTracker();
    t.onInbound(nav('https://login.example.com/', { sessionId: 'A' }));
    t.onOutbound({ id: 7, sessionId: 'A', method: 'Page.navigate', params: { url: '#top' } });
    expect(t.awaitingNavigateResponse).toBe(true);
    t.onInbound({ id: 7, sessionId: 'A', result: { frameId: 'F1' } });
    expect(t.awaitingNavigateResponse).toBe(false);
    expect(t.originFor('A')).toEqual({ target: { host: 'login.example.com', scheme: 'https' } });

    t.onOutbound({ id: 8, sessionId: 'A', method: 'Page.navigate', params: {} });
    t.onInbound({ id: 8, sessionId: 'A', result: { frameId: 'F1', loaderId: 'L', errorText: 'net::ERR_ABORTED' } });
    expect(t.originFor('A')).toEqual({ target: { host: 'login.example.com', scheme: 'https' } });

    // A cross-document navigate stays in flux after its response, until commit.
    t.onOutbound({ id: 9, sessionId: 'A', method: 'Page.navigate', params: {} });
    t.onInbound({ id: 9, sessionId: 'A', result: { frameId: 'F1', loaderId: 'L2' } });
    expect(t.originFor('A')).toEqual({ unknown: 'a navigation is in progress' });
    // A response with the same id on another session doesn't count.
    t.onOutbound({ id: 10, sessionId: 'A', method: 'Page.navigate', params: {} });
    t.onInbound({ id: 10, sessionId: 'B', result: {} });
    expect(t.awaitingNavigateResponse).toBe(true);
  });

  it('is unknown between a main-frame frameStartedLoading and frameNavigated / frameStoppedLoading', () => {
    const t = new OriginTracker();
    t.onInbound(nav('https://login.example.com/', { sessionId: 'A' }));
    t.onInbound({ method: 'Page.frameStartedLoading', sessionId: 'A', params: { frameId: 'F2' } }); // child frame
    expect(t.originFor('A')).toHaveProperty('target');
    t.onInbound({ method: 'Page.frameStartedLoading', sessionId: 'A', params: { frameId: 'F1' } });
    expect(t.originFor('A')).toEqual({ unknown: 'a navigation is in progress' });
    t.onInbound({ method: 'Page.frameStoppedLoading', sessionId: 'A', params: { frameId: 'F1' } });
    expect(t.originFor('A')).toHaveProperty('target');
  });

  it('forgets a detached session', () => {
    const t = new OriginTracker();
    t.onInbound(nav('https://login.example.com/', { sessionId: 'A' }));
    t.onInbound({ method: 'Target.detachedFromTarget', params: { sessionId: 'A' } });
    expect(t.originFor('A')).toHaveProperty('unknown');
  });
});
