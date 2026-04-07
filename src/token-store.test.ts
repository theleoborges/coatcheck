import { describe, it, expect, afterEach } from 'vitest';
import { TokenStore } from './token-store.js';

describe('TokenStore', () => {
  let store: TokenStore;

  afterEach(() => {
    store?.destroy();
  });

  it('issues tokens with tok_ prefix', () => {
    store = new TokenStore();
    const token = store.issue('my-secret', 'real-value-123');
    expect(token.id).toMatch(/^tok_[a-f0-9]{64}$/);
    expect(token.ttlSeconds).toBe(300);
  });

  it('resolves a valid token to its real value', () => {
    store = new TokenStore();
    const token = store.issue('my-secret', 'real-value-123');
    expect(store.resolve(token.id)).toBe('real-value-123');
  });

  it('returns null for unknown tokens', () => {
    store = new TokenStore();
    expect(store.resolve('tok_unknown')).toBeNull();
  });

  it('replaces tokens in strings', () => {
    store = new TokenStore();
    const t1 = store.issue('api-key', 'sk-real-key');
    const t2 = store.issue('token', 'usr-real-token');

    const input = `https://api.trello.com/1/boards?key=${t1.id}&token=${t2.id}`;
    const result = store.replaceAll(input);
    expect(result).toBe('https://api.trello.com/1/boards?key=sk-real-key&token=usr-real-token');
  });

  it('replaces tokens in headers', () => {
    store = new TokenStore();
    const token = store.issue('notion-key', 'secret_abc123');

    const header = `Authorization: Bearer ${token.id}`;
    const result = store.replaceAll(header);
    expect(result).toBe('Authorization: Bearer secret_abc123');
  });

  it('returns input unchanged when no tokens match', () => {
    store = new TokenStore();
    store.issue('key', 'value');

    const input = 'no tokens here';
    expect(store.replaceAll(input)).toBe(input);
  });

  it('returns input unchanged when store is empty', () => {
    store = new TokenStore();
    const input = 'Authorization: Bearer tok_fake';
    expect(store.replaceAll(input)).toBe(input);
  });

  it('does not resolve expired tokens', async () => {
    store = new TokenStore();
    const token = store.issue('key', 'value', 0); // 0 second TTL = immediately expired

    // Small delay to ensure expiry
    await new Promise(r => setTimeout(r, 10));

    expect(store.resolve(token.id)).toBeNull();
  });

  it('does not replace expired tokens in strings', async () => {
    store = new TokenStore();
    const token = store.issue('key', 'real-value', 0);

    await new Promise(r => setTimeout(r, 10));

    const input = `key=${token.id}`;
    expect(store.replaceAll(input)).toBe(input);
  });

  it('tracks active token count', () => {
    store = new TokenStore();
    expect(store.size).toBe(0);

    store.issue('a', 'val-a');
    store.issue('b', 'val-b');
    expect(store.size).toBe(2);
  });

  it('handles multiple replacements of the same token', () => {
    store = new TokenStore();
    const token = store.issue('key', 'real');

    const input = `${token.id} and ${token.id}`;
    expect(store.replaceAll(input)).toBe('real and real');
  });

  it('uses custom TTL', () => {
    store = new TokenStore();
    const token = store.issue('key', 'val', 60);
    expect(token.ttlSeconds).toBe(60);
    expect(store.resolve(token.id)).toBe('val');
  });
});
