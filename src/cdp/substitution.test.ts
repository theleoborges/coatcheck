import { describe, it, expect, afterEach } from 'vitest';
import { TokenStore } from '../token-store.js';
import { substituteOutbound, substituteInbound } from './substitution.js';

describe('CDP substitution', () => {
  let store: TokenStore;
  const SID = 'sess-1';

  afterEach(() => store?.destroy());

  function mint(secretName: string, value: string) {
    return store.issueForSession(secretName, value, SID).id;
  }

  // --- Outbound (token → real value) ---

  describe('substituteOutbound', () => {
    it('substitutes Input.insertText.text (page.fill)', () => {
      store = new TokenStore();
      const tok = mint('site:password', 'real-secret-42');
      const frame = JSON.stringify({ id: 1, method: 'Input.insertText', params: { text: tok } });

      const r = substituteOutbound(frame, store, SID);
      expect(r.substitutions).toBe(1);
      expect(JSON.parse(r.payload).params.text).toBe('real-secret-42');
    });

    it('substitutes Runtime.evaluate.expression (string-form injection)', () => {
      store = new TokenStore();
      const tok = mint('site:password', 'real-secret-42');
      const frame = JSON.stringify({
        id: 2,
        method: 'Runtime.evaluate',
        params: { expression: `el.value = '${tok}'` },
      });

      const r = substituteOutbound(frame, store, SID);
      expect(r.substitutions).toBe(1);
      expect(JSON.parse(r.payload).params.expression).toBe(`el.value = 'real-secret-42'`);
    });

    it('substitutes Runtime.callFunctionOn arguments at any index', () => {
      store = new TokenStore();
      const tok = mint('site:password', 'real-secret-42');
      // token padded behind internal context args, as Playwright does
      const frame = JSON.stringify({
        id: 3,
        method: 'Runtime.callFunctionOn',
        params: {
          functionDeclaration: 'function(a){...}',
          arguments: [{ value: 'ctx0' }, { value: 'ctx1' }, { value: tok }],
        },
      });

      const r = substituteOutbound(frame, store, SID);
      expect(r.substitutions).toBe(1);
      expect(JSON.parse(r.payload).params.arguments[2].value).toBe('real-secret-42');
    });

    it('passes through non-token text unchanged', () => {
      store = new TokenStore();
      mint('site:password', 'real-secret-42');
      const frame = JSON.stringify({ id: 4, method: 'Input.insertText', params: { text: 'hello world' } });
      const r = substituteOutbound(frame, store, SID);
      expect(r.substitutions).toBe(0);
      expect(r.payload).toBe(frame);
    });

    it('does not substitute another session\'s token', () => {
      store = new TokenStore();
      const otherTok = store.issueForSession('site:password', 'real-secret-42', 'sess-other').id;
      const frame = JSON.stringify({ id: 5, method: 'Input.insertText', params: { text: otherTok } });
      const r = substituteOutbound(frame, store, SID);
      expect(r.substitutions).toBe(0);
      expect(JSON.parse(r.payload).params.text).toBe(otherTok);
    });

    it('flags a token seen in an unsupported method', () => {
      store = new TokenStore();
      const tok = mint('site:password', 'real-secret-42');
      const frame = JSON.stringify({ id: 6, method: 'Network.setExtraHTTPHeaders', params: { headers: { Authorization: tok } } });
      const r = substituteOutbound(frame, store, SID);
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
      store.issueForSession('site:password', 'real-secret-42', 'sess-other');
      const frame = JSON.stringify({ id: 9, result: { value: 'real-secret-42' } });
      // SID has no active values, so this is a clean passthrough
      const r = substituteInbound(frame, store, SID);
      expect(r.dropped).toBe(false);
      expect(r.redactions).toBe(0);
    });
  });
});
