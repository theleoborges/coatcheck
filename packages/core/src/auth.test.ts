import { describe, it, expect } from 'vitest';
import type http from 'node:http';
import { createApiAuth, isOpenVaultPath } from './auth.js';

const TOKEN = 'k'.repeat(40);
const req = (headers: http.IncomingHttpHeaders) => ({ headers }) as http.IncomingMessage;
const basic = (raw: string) => `Basic ${Buffer.from(raw).toString('base64')}`;

describe('createApiAuth', () => {
  it('lets everything through when no token is configured', () => {
    const auth = createApiAuth(undefined);
    expect(auth.vault(req({}))).toBe(true);
    expect(auth.proxy(req({}))).toBe(true);
  });

  it('accepts the vault bearer token with any scheme casing, and nothing else', () => {
    const auth = createApiAuth(TOKEN);
    expect(auth.vault(req({ authorization: `Bearer ${TOKEN}` }))).toBe(true);
    expect(auth.vault(req({ authorization: `bearer ${TOKEN}` }))).toBe(true);
    for (const authorization of [undefined, TOKEN, `Bearer ${TOKEN}x`, `Bearer ${TOKEN.slice(1)}`, basic(`u:${TOKEN}`), 'Bearer']) {
      expect(auth.vault(req({ authorization })), String(authorization)).toBe(false);
    }
  });

  it('accepts proxy Basic (token as password, any user) or Bearer', () => {
    const auth = createApiAuth(TOKEN);
    for (const h of [basic(`coatcheck:${TOKEN}`), basic(`:${TOKEN}`), `Bearer ${TOKEN}`, `BASIC ${Buffer.from(`u:${TOKEN}`).toString('base64')}`]) {
      expect(auth.proxy(req({ 'proxy-authorization': h })), h).toBe(true);
    }
    for (const h of [undefined, basic(TOKEN), basic(`${TOKEN}:x`), 'Basic !!!not-base64', `Digest ${TOKEN}`]) {
      expect(auth.proxy(req({ 'proxy-authorization': h })), String(h)).toBe(false);
    }
    expect(auth.proxy(req({ authorization: `Bearer ${TOKEN}` }))).toBe(false);
  });
});

describe('isOpenVaultPath', () => {
  it('opens only the exact health and CA paths', () => {
    expect(isOpenVaultPath('/_health')).toBe(true);
    expect(isOpenVaultPath('/_ca')).toBe(true);
    for (const p of ['/_vault', '/_health/../_vault', '/_ca?x', '/_secret/x', '/']) expect(isOpenVaultPath(p), p).toBe(false);
  });
});
