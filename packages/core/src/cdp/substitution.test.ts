import { describe, it, expect, afterEach } from 'vitest';
import { TokenStore } from '../token-store.js';
import { substituteInbound } from './substitution.js';

describe('CDP inbound redaction', () => {
  let store: TokenStore;
  const SID = 'sess-1';

  afterEach(() => store?.destroy());

  /** Register a real value in the session's inbound-redaction set. */
  function register(secretName: string, value: string) {
    store.registerSessionValues(SID, [{ value, secretName }]);
  }

  it('redacts an echoed-back real value', () => {
    store = new TokenStore();
    register('site:password', 'real-secret-42');
    const frame = JSON.stringify({ id: 7, result: { result: { value: 'real-secret-42' } } });

    const r = substituteInbound(frame, store, SID);
    expect(r.dropped).toBe(false);
    expect(r.redactions).toBe(1);
    expect(JSON.parse(r.payload as string).result.result.value).toBe('[REDACTED:site:password]');
  });

  it('passes through frames with no active value', () => {
    store = new TokenStore();
    register('site:password', 'real-secret-42');
    const frame = JSON.stringify({ id: 8, result: { result: { value: 'nothing sensitive' } } });
    const r = substituteInbound(frame, store, SID);
    expect(r.dropped).toBe(false);
    expect(r.redactions).toBe(0);
    expect(r.payload).toBe(frame);
  });

  it('drops an unparseable frame that still carries the real value (byte floor)', () => {
    store = new TokenStore();
    register('site:password', 'real-secret-42');
    const frame = 'GARBAGE real-secret-42 GARBAGE'; // not valid JSON but contains the cleartext
    const r = substituteInbound(frame, store, SID);
    expect(r.dropped).toBe(true);
    expect(r.payload).toBeNull();
  });

  it('only considers the calling session\'s values', () => {
    store = new TokenStore();
    store.registerSessionValues('sess-other', [{ value: 'real-secret-42', secretName: 'site:password' }]);
    const frame = JSON.stringify({ id: 9, result: { value: 'real-secret-42' } });
    const r = substituteInbound(frame, store, SID); // SID has no values → clean passthrough
    expect(r.dropped).toBe(false);
    expect(r.redactions).toBe(0);
  });

  // --- Browser-applied encodings (percent, HTML entities, JSON) ---
  // The browser can report a value back in one of a few fixed encodings. These
  // are redacted. (Agent-applied transforms like base64/reversal are out of
  // scope by design — item 20 stops the agent running script over a live value.)

  it('redacts a percent-encoded value (form body)', () => {
    store = new TokenStore();
    const value = 'p@ss word/42&x';
    register('site:password', value);
    const frame = JSON.stringify({ method: 'Network.requestWillBeSent', params: { request: { postData: `pw=${encodeURIComponent(value)}&y=1` } } });
    const r = substituteInbound(frame, store, SID);
    expect(r.dropped).toBe(false);
    expect(r.payload).not.toContain(encodeURIComponent(value));
    expect(r.payload).toContain('[REDACTED:site:password]');
  });

  it('redacts an HTML-entity-escaped value (markup echo)', () => {
    store = new TokenStore();
    const value = 'a<b>&"c';
    register('site:password', value);
    const htmlEscaped = 'a&lt;b&gt;&amp;&quot;c';
    const frame = JSON.stringify({ result: { outerHTML: `<input value="${htmlEscaped}">` } });
    const r = substituteInbound(frame, store, SID);
    expect(r.dropped).toBe(false);
    expect(r.payload).not.toContain(htmlEscaped);
    expect(r.payload).toContain('[REDACTED:site:password]');
  });

  it('redacts a JSON-string-escaped value (double-encoded echo)', () => {
    store = new TokenStore();
    const value = 'line1\nquote"end';
    register('site:password', value);
    // The agent asked for JSON.stringify(field.value); the browser returns the
    // JSON-escaped string as a plain string value.
    const inner = JSON.stringify(value).slice(1, -1);
    const frame = JSON.stringify({ result: { result: { value: inner } } });
    const r = substituteInbound(frame, store, SID);
    expect(r.dropped).toBe(false);
    expect(r.payload).not.toContain(inner);
  });

  it('drops a frame whose encoded value survives redaction unparseable', () => {
    store = new TokenStore();
    register('site:password', 'secret-xyz');
    // percent-encoded value embedded in a non-JSON frame
    const frame = `not json ${encodeURIComponent('secret-xyz')}`;
    const r = substituteInbound(frame, store, SID);
    // 'secret-xyz' has no special chars so encodeURIComponent == value; byte floor drops it.
    expect(r.dropped).toBe(true);
  });
});
