import type { MatchTarget } from '../host-matcher.js';

/**
 * Tracks each flattened CDP session's committed main-frame origin, for the
 * origin binding on `Input.insertText` (design: v1-decisions.md §3, "CDP
 * origin binding details").
 *
 * The origin comes from inbound `Page.frameNavigated` events for the main
 * frame (no `parentId`); those come from the browser, which the agent can't
 * forge. While a main-frame navigation is in progress the origin is unknown,
 * so a fill sent right after a navigation is never checked against the page
 * being left.
 */

interface SessionState {
  mainFrameId?: string;
  url?: string;
  /** A main-frame navigation has started and not yet committed or stopped. */
  navigating: boolean;
}

interface CdpMessage {
  id?: unknown;
  method?: unknown;
  sessionId?: unknown;
  params?: Record<string, unknown>;
  result?: Record<string, unknown>;
  error?: unknown;
}

/** Outbound commands that navigate the session's main frame. */
const NAVIGATING_COMMANDS = new Set(['Page.navigate', 'Page.reload', 'Page.navigateToHistoryEntry']);

/** Frames without a `sessionId` (non-flattened) share this key. */
const ROOT = '';

function sessionKey(msg: CdpMessage): string {
  return typeof msg.sessionId === 'string' ? msg.sessionId : ROOT;
}

export class OriginTracker {
  private sessions = new Map<string, SessionState>();
  /** `${session}\0${id}` of outbound `Page.navigate` calls awaiting a response. */
  private pendingNavigates = new Set<string>();

  private state(key: string): SessionState {
    let s = this.sessions.get(key);
    if (!s) {
      s = { navigating: false };
      this.sessions.set(key, s);
    }
    return s;
  }

  /** True while a `Page.navigate` response is awaited (inbound responses must then be inspected). */
  get awaitingNavigateResponse(): boolean {
    return this.pendingNavigates.size > 0;
  }

  /** Observe an agent → browser frame (already parsed). */
  onOutbound(msg: CdpMessage): void {
    if (typeof msg.method !== 'string' || !NAVIGATING_COMMANDS.has(msg.method)) return;
    const key = sessionKey(msg);
    this.state(key).navigating = true;
    if (msg.method === 'Page.navigate' && (typeof msg.id === 'number' || typeof msg.id === 'string')) {
      this.pendingNavigates.add(`${key}\0${msg.id}`);
    }
  }

  /** Observe a browser → agent frame (already parsed). */
  onInbound(msg: CdpMessage): void {
    const key = sessionKey(msg);

    if (msg.method === undefined && msg.id !== undefined) {
      const pending = `${key}\0${String(msg.id)}`;
      if (!this.pendingNavigates.delete(pending)) return;
      // Same-document navigation (no loaderId) or a failed one: nothing more
      // will commit for it, so stop treating the origin as in flux.
      const r = msg.result;
      if (msg.error !== undefined || !r || typeof r.loaderId !== 'string' || typeof r.errorText === 'string') {
        const s = this.sessions.get(key);
        if (s) s.navigating = false;
      }
      return;
    }

    switch (msg.method) {
      case 'Page.frameNavigated': {
        const frame = msg.params?.frame as { id?: unknown; parentId?: unknown; url?: unknown } | undefined;
        if (!frame || frame.parentId !== undefined || typeof frame.url !== 'string') return;
        const s = this.state(key);
        s.mainFrameId = typeof frame.id === 'string' ? frame.id : undefined;
        s.url = frame.url;
        s.navigating = false;
        return;
      }
      case 'Page.frameStartedLoading':
      case 'Page.frameStoppedLoading': {
        const s = this.sessions.get(key);
        if (!s || s.mainFrameId === undefined || msg.params?.frameId !== s.mainFrameId) return;
        s.navigating = msg.method === 'Page.frameStartedLoading';
        return;
      }
      case 'Target.detachedFromTarget': {
        const detached = msg.params?.sessionId;
        if (typeof detached === 'string') this.sessions.delete(detached);
        return;
      }
    }
  }

  /**
   * The committed main-frame origin of `sessionId` as a match target, or a
   * reason it is unknown (never navigated, navigating, or not http(s)).
   */
  originFor(sessionId: string | undefined): { target: MatchTarget } | { unknown: string } {
    const s = this.sessions.get(sessionId ?? ROOT);
    if (!s || s.url === undefined) return { unknown: 'no committed navigation seen (enable Page and navigate first)' };
    if (s.navigating) return { unknown: 'a navigation is in progress' };
    let url: URL;
    try {
      url = new URL(s.url);
    } catch {
      return { unknown: 'unparseable page URL' };
    }
    if (url.protocol !== 'https:' && url.protocol !== 'http:') return { unknown: `page scheme '${url.protocol}' is not http(s)` };
    return { target: { host: url.hostname.replace(/^\[|\]$/g, ''), scheme: url.protocol === 'https:' ? 'https' : 'http' } };
  }
}
