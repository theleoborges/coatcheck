import { describe, it, expect, afterEach, beforeAll } from 'vitest';
import { createHash } from 'node:crypto';
import tls from 'node:tls';
import { SignatureV4 } from '@smithy/signature-v4';
import { HttpRequest } from '@smithy/protocol-http';
import { S3Client, ListBucketsCommand, PutObjectCommand } from '@aws-sdk/client-s3';
import { HttpsProxyAgent } from 'https-proxy-agent';
import {
  captureLogs, cleanups, closed, connect, hosts, readResponses, runCleanups, Sha256, startHttpsUpstream, startHttpUpstream,
  startProxy, startTls, testCas, viaProxy, type Echo, type Responder,
} from './test-helpers.js';
import { createMemoryProvider } from './memory-provider.js';
import { parsePolicy } from './policy.js';
import {
  amzDateOf, canonicalRequest, parseSigV4Authorization, payloadMode, stringToSign, uriEncode, type SigV4Authorization, type SigV4Credential,
} from './signing/sigv4.js';
import type { SignableRequest } from './signing/request.js';
import type { CertAuthority } from './ca.js';
import type { TokenStore } from './token-store.js';

/**
 * Signing processors end to end (design: docs/design/signing-processors.md
 * §6, "Integration"). The agent's side is played by `@smithy/signature-v4`
 * (and the real `@aws-sdk/client-s3`) signing with the ticket; every request
 * that reaches the upstream is checked against the same independent signer
 * using the real credential.
 */

const REAL: SigV4Credential = { scheme: 'aws-sigv4', accessKeyId: 'AKIAREALKEYID0000001', secretAccessKey: 'real/Secret+Key0123456789abcdefghijklmn' };
const SESSION: SigV4Credential = {
  scheme: 'aws-sigv4', accessKeyId: 'ASIAREALSESSION00001', secretAccessKey: 'real/Session+Secret0123456789abcdefghij',
  sessionToken: 'FwoGZXIvYXdzERealSessionToken//0123456789+abcdefghij==',
};
const DATE = new Date('2026-10-18T12:00:00Z');

let proxyCa: CertAuthority;
let upstreamCa: CertAuthority;
beforeAll(async () => ({ proxyCa, upstreamCa } = await testCas()));
afterEach(runCleanups);

// Test 4 collects everything that crossed the wire or was logged in this file.
const seen = { wire: [] as Buffer[], logs: [] as string[], signed: [] as Echo[], tickets: [] as string[] };

/** A proxy, an HTTPS upstream on 127.0.0.1, and captured logs; all recorded for test 4. */
async function setup(opts: { respond?: Responder; mitm?: 'bound' | 'always'; policy?: string; provider?: ReturnType<typeof createMemoryProvider>; maxSwapBodyBytes?: number } = {}) {
  const logs = captureLogs();
  const upstream = await startHttpsUpstream(opts.respond);
  const proxy = await startProxy({
    ...(opts.mitm ? { mitm: opts.mitm } : {}),
    ...(opts.policy ? { policy: parsePolicy(opts.policy, []) } : {}),
    ...(opts.provider ? { provider: opts.provider } : {}),
    ...(opts.maxSwapBodyBytes ? { maxSwapBodyBytes: opts.maxSwapBodyBytes } : {}),
  });
  cleanups.push(() => {
    seen.wire.push(...upstream.raw);
    seen.logs.push(...logs);
    seen.signed.push(...upstream.received.filter(r => String(r.headers.authorization ?? '').startsWith('AWS4-HMAC-SHA256')));
  });
  return { logs, upstream, ...proxy };
}

function issue(store: TokenStore, credential: SigV4Credential = REAL, host = '127.0.0.1', name = 'aws-reports'): string {
  const { id } = store.issue(name, '', { allowedHosts: hosts(host), signing: credential });
  seen.tickets.push(id);
  return id;
}

interface AgentRequest {
  host: string;
  method?: string;
  path?: string;
  query?: Record<string, string>;
  headers?: Record<string, string>;
  body?: Buffer | string;
  service?: string;
  region?: string;
  sessionToken?: string;
}

/** The agent: an unmodified SDK signer using the ticket as key id and secret. Returns the raw HTTP/1.1 head and body. */
async function agentSign(ticket: string, r: AgentRequest): Promise<{ head: string; body: Buffer; headers: Record<string, string> }> {
  const method = r.method ?? 'GET';
  const path = r.path ?? '/';
  const query = r.query ?? {};
  const body = r.body === undefined ? Buffer.alloc(0) : Buffer.from(r.body);
  const service = r.service ?? 's3';
  const headers: Record<string, string> = { host: r.host, ...r.headers, ...(body.length > 0 ? { 'content-length': String(body.length) } : {}) };
  const signed = await new SignatureV4({
    credentials: { accessKeyId: ticket, secretAccessKey: ticket, ...(r.sessionToken ? { sessionToken: r.sessionToken } : {}) },
    region: r.region ?? 'us-east-1', service, sha256: Sha256, uriEscapePath: service !== 's3', applyChecksum: false,
  }).sign(new HttpRequest({ method, protocol: 'https:', hostname: r.host, path, query, headers, body }), { signingDate: DATE });
  const qs = Object.entries(query).map(([k, v]) => `${uriEncode(k)}=${uriEncode(v)}`).join('&');
  const out = signed.headers as Record<string, string>;
  const head = [`${method} ${path}${qs ? `?${qs}` : ''} HTTP/1.1`, ...Object.entries(out).map(([k, v]) => `${k}: ${v}`)].join('\r\n');
  return { head, body, headers: out };
}

/** The upstream got a request signed with `credential`, exactly as the independent signer signs it. */
async function expectSignedWith(echo: Echo, credential: SigV4Credential): Promise<SigV4Authorization> {
  const authorization = String(echo.headers.authorization);
  const auth = parseSigV4Authorization(authorization) as SigV4Authorization;
  expect(auth.accessKeyId).toBe(credential.accessKeyId);
  const q = echo.url.indexOf('?');
  const path = q === -1 ? echo.url : echo.url.slice(0, q);
  const query = Object.fromEntries((q === -1 ? '' : echo.url.slice(q + 1)).split('&').filter(Boolean).map(p => {
    const eq = p.indexOf('=');
    return eq === -1 ? [decodeURIComponent(p), ''] : [decodeURIComponent(p.slice(0, eq)), decodeURIComponent(p.slice(eq + 1))];
  }));
  const headers = Object.fromEntries(auth.signedHeaders.map(h => [h, String(echo.headers[h])]));
  const amzDate = String(echo.headers['x-amz-date']);
  const signingDate = new Date(`${amzDate.slice(0, 4)}-${amzDate.slice(4, 6)}-${amzDate.slice(6, 8)}T${amzDate.slice(9, 11)}:${amzDate.slice(11, 13)}:${amzDate.slice(13, 15)}Z`);
  const expected = await new SignatureV4({
    credentials: { accessKeyId: credential.accessKeyId, secretAccessKey: credential.secretAccessKey, ...(credential.sessionToken ? { sessionToken: credential.sessionToken } : {}) },
    region: auth.region, service: auth.service, sha256: Sha256, uriEscapePath: auth.service !== 's3', applyChecksum: false,
  }).sign(new HttpRequest({ method: echo.method, protocol: 'https:', hostname: 'unused', path, query, headers, body: echo.rawBody }), { signingDate });
  expect(authorization).toBe(expected.headers.authorization);
  return auth;
}

/** Open a MITM'd tunnel to the upstream and send raw bytes. */
async function tunnel(proxyPort: number, upstreamPort: number, host = '127.0.0.1'): Promise<tls.TLSSocket> {
  const { status, socket } = await connect(proxyPort, `${host}:${upstreamPort}`);
  expect(status).toBe('HTTP/1.1 200 Connection Established');
  return startTls(socket, proxyCa.caCertPem, host);
}

const send = (t: tls.TLSSocket, r: { head: string; body: Buffer }) => t.write(Buffer.concat([Buffer.from(`${r.head}\r\n\r\n`), r.body]));
const LIST_XML = '<?xml version="1.0" encoding="UTF-8"?><ListAllMyBucketsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">' +
  '<Owner><ID>owner</ID></Owner><Buckets><Bucket><Name>reports</Name><CreationDate>2026-01-01T00:00:00.000Z</CreationDate></Bucket></Buckets></ListAllMyBucketsResult>';

describe('signing: AWS SigV4 through the proxy', () => {
  it('1. an unmodified @aws-sdk/client-s3 signs with the ticket; the upstream sees the real key id and a valid signature; a 2 MiB upload streams', async () => {
    const provider = createMemoryProvider({ secrets: { 'aws-reports': JSON.stringify({ access_key_id: REAL.accessKeyId, secret_access_key: REAL.secretAccessKey }) } });
    const { logs, upstream, port } = await setup({
      provider,
      policy: JSON.stringify({ secrets: { 'aws-reports': { allowed_hosts: ['127.0.0.1'], signing: 'aws-sigv4' } } }),
      respond: (req, _body, res) => {
        if (req.method === 'GET') {
          res.setHeader('content-type', 'application/xml');
          res.end(LIST_XML);
        } else {
          res.setHeader('etag', '"0123"');
          res.end();
        }
      },
    });
    const mint = await viaProxyVault(port, '/_vault/aws-reports');
    expect(mint.signing).toBe('aws-sigv4');
    const ticket = mint.token as string;
    seen.tickets.push(ticket);

    const s3 = new S3Client({
      region: 'us-east-1',
      endpoint: `https://127.0.0.1:${upstream.port}`,
      forcePathStyle: true,
      maxAttempts: 1,
      credentials: { accessKeyId: ticket, secretAccessKey: ticket },
      requestHandler: { httpsAgent: new TrustingProxyAgent(`http://127.0.0.1:${port}`, proxyCa.caCertPem) },
    });
    cleanups.push(() => s3.destroy());

    const list = await s3.send(new ListBucketsCommand({}));
    expect(list.Buckets?.map(b => b.Name)).toEqual(['reports']);
    await expectSignedWith(upstream.received[0], REAL);

    const big = Buffer.alloc(2 * 1024 * 1024, 'r');
    await s3.send(new PutObjectCommand({ Bucket: 'reports', Key: 'reports/release report.md', Body: big }));
    const put = upstream.received[1];
    expect(put.method).toBe('PUT');
    expect(put.headers['x-amz-content-sha256']).toBeDefined();
    expect(put.rawBody!.length).toBeGreaterThanOrEqual(big.length);
    await expectSignedWith(put, REAL);
    expect(logs.filter(l => l.includes('result=signed signing=aws-sigv4 secrets=aws-reports'))).toHaveLength(2);
    expect(logs.join('\n')).not.toContain('body-unscanned');
  });

  it('2. a non-S3 request without a payload-hash header is buffered, hashed and re-signed; past the cap it is refused before anything is forwarded', async () => {
    const { logs, upstream, tokenStore, port } = await setup();
    const ticket = issue(tokenStore);
    const host = `127.0.0.1:${upstream.port}`;
    const t = await tunnel(port, upstream.port);
    send(t, await agentSign(ticket, { host, method: 'POST', service: 'sts', headers: { 'content-type': 'application/json' }, body: '{"Action":"GetCallerIdentity"}' }));
    const [res] = await readResponses(t, 1);
    expect(res.head).toMatch(/^HTTP\/1.1 200/);
    expect(upstream.received[0].body).toBe('{"Action":"GetCallerIdentity"}');
    await expectSignedWith(upstream.received[0], REAL);

    for (const chunked of [false, true]) {
      const t2 = await tunnel(port, upstream.port);
      const big = Buffer.alloc(2 * 1024 * 1024, 'x');
      const signed = await agentSign(ticket, { host, method: 'POST', service: 'sts', body: big });
      const head = chunked ? signed.head.replace(/content-length: \d+/, 'transfer-encoding: chunked') : signed.head;
      const body = chunked ? Buffer.concat([Buffer.from(`${big.length.toString(16)}\r\n`), big, Buffer.from('\r\n0\r\n\r\n')]) : big;
      t2.write(Buffer.concat([Buffer.from(`${head}\r\n\r\n`), body]));
      const [refused] = await readResponses(t2, 1);
      expect(refused.head).toMatch(/^HTTP\/1.1 403/);
      expect(refused.head).toContain('X-Coatcheck-Denied: unsignable');
      expect(JSON.parse(refused.body)).toEqual(expect.objectContaining({ reason: 'unsignable', detail: 'body-too-large' }));
      await closed(t2);
    }
    expect(upstream.received).toHaveLength(1);
    expect(logs.filter(l => l.includes('result=unsignable secrets=aws-reports reason=body-too-large'))).toHaveLength(2);
  });

  it('3. a signing ticket sent to another host is refused and the tunnel closed; under bound mode such a host is a raw tunnel carrying only the literal', async () => {
    const attacker = await startHttpsUpstream(undefined, 'localhost');
    const { logs, tokenStore, port } = await setup({ mitm: 'always' });
    const ticket = issue(tokenStore);
    const t = await tunnel(port, attacker.port, 'localhost');
    send(t, await agentSign(ticket, { host: `localhost:${attacker.port}` }));
    const [res] = await readResponses(t, 1);
    expect(res.head).toMatch(/^HTTP\/1.1 403/);
    expect(res.head).toContain('X-Coatcheck-Denied: host-mismatch');
    await closed(t);
    expect(attacker.received).toHaveLength(0);
    expect(logs.some(l => l.includes('result=denied secrets=aws-reports'))).toBe(true);

    // Default `bound`: localhost isn't in the policy and no ticket is bound to it, so no MITM at all.
    const bound = await startProxy();
    const id = issue(bound.tokenStore);
    const { status, socket } = await connect(bound.port, `localhost:${attacker.port}`);
    expect(status).toBe('HTTP/1.1 200 Connection Established');
    const direct = await startTls(socket, upstreamCa.caCertPem, 'localhost');
    send(direct, await agentSign(id, { host: `localhost:${attacker.port}` }));
    await readResponses(direct, 1);
    const leaked = String(attacker.received[0].headers.authorization);
    expect(leaked).toContain(`Credential=${id}/`);
    expect(leaked).not.toContain(REAL.accessKeyId);
    seen.wire.push(...attacker.raw);
  });

  it('5. a signing ticket used as a literal bearer is forwarded unchanged (signing-skipped)', async () => {
    const { logs, upstream, tokenStore, port } = await setup();
    const ticket = issue(tokenStore);
    const t = await tunnel(port, upstream.port);
    t.write(`GET /x HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer ${ticket}\r\n\r\n`);
    await readResponses(t, 1);
    expect(upstream.received[0].headers.authorization).toBe(`Bearer ${ticket}`);
    expect(logs.some(l => l.includes('result=signing-skipped secrets=aws-reports where=signing'))).toBe(true);
  });

  it('6. a signed header changed after signing gets 403 signature-mismatch and nothing is forwarded', async () => {
    const { logs, upstream, tokenStore, port } = await setup();
    const ticket = issue(tokenStore);
    const t = await tunnel(port, upstream.port);
    const signed = await agentSign(ticket, { host: `127.0.0.1:${upstream.port}`, path: '/reports/a.md', headers: { 'x-amz-meta-owner': 'agent' } });
    send(t, { ...signed, head: signed.head.replace('x-amz-meta-owner: agent', 'x-amz-meta-owner: someone-else') });
    const [res] = await readResponses(t, 1);
    expect(res.head).toMatch(/^HTTP\/1.1 403/);
    expect(res.head).toContain('X-Coatcheck-Denied: signature-mismatch');
    expect(JSON.parse(res.body)).toEqual(expect.objectContaining({ reason: 'signature-mismatch', secrets: ['aws-reports'] }));
    await closed(t);
    expect(upstream.received).toHaveLength(0);
    expect(logs.some(l => l.includes('result=signature-mismatch secrets=aws-reports'))).toBe(true);
  });

  it('7. a session-token credential: the token is set and signed, replacing whatever the agent sent', async () => {
    const { upstream, tokenStore, port } = await setup();
    const ticket = issue(tokenStore, SESSION);
    const t = await tunnel(port, upstream.port);
    send(t, await agentSign(ticket, { host: `127.0.0.1:${upstream.port}`, sessionToken: ticket }));
    await readResponses(t, 1);
    const echo = upstream.received[0];
    expect(echo.headers['x-amz-security-token']).toBe(SESSION.sessionToken);
    const auth = await expectSignedWith(echo, SESSION);
    expect(auth.signedHeaders).toContain('x-amz-security-token');

    // An agent that set no token at all: one is added.
    const t2 = await tunnel(port, upstream.port);
    send(t2, await agentSign(ticket, { host: `127.0.0.1:${upstream.port}`, path: '/other' }));
    await readResponses(t2, 1);
    await expectSignedWith(upstream.received[1], SESSION);
    // And a credential without a token removes one the agent sent.
    const plain = issue(tokenStore, REAL, '127.0.0.1', 'aws-plain');
    const t3 = await tunnel(port, upstream.port);
    send(t3, await agentSign(plain, { host: `127.0.0.1:${upstream.port}`, sessionToken: 'agent-set-something' }));
    await readResponses(t3, 1);
    expect(upstream.received[2].headers['x-amz-security-token']).toBeUndefined();
    await expectSignedWith(upstream.received[2], REAL);
  });

  it('8. unsupported shapes: SigV4a and streaming signed payloads are refused; a presigned URL leaves as a literal', async () => {
    const { logs, upstream, tokenStore, port } = await setup();
    const ticket = issue(tokenStore);
    const host = `127.0.0.1:${upstream.port}`;
    const sigv4a = await tunnel(port, upstream.port);
    sigv4a.write(`GET / HTTP/1.1\r\nHost: ${host}\r\nX-Amz-Date: 20261018T120000Z\r\n` +
      `Authorization: AWS4-ECDSA-P256-SHA256 Credential=${ticket}/20261018/s3/aws4_request, SignedHeaders=host;x-amz-date, Signature=3045\r\n\r\n`);
    const [a] = await readResponses(sigv4a, 1);
    expect(JSON.parse(a.body)).toEqual(expect.objectContaining({ reason: 'unsignable', detail: 'sigv4a' }));

    const streaming = await tunnel(port, upstream.port);
    send(streaming, await agentSign(ticket, { host, method: 'PUT', path: '/reports/x', headers: { 'x-amz-content-sha256': 'STREAMING-AWS4-HMAC-SHA256-PAYLOAD' }, body: 'chunked' }));
    const [b] = await readResponses(streaming, 1);
    expect(JSON.parse(b.body)).toEqual(expect.objectContaining({ reason: 'unsignable', detail: 'streaming-signed-payload' }));
    expect(upstream.received).toHaveLength(0);

    const presigned = await tunnel(port, upstream.port);
    presigned.write(`GET /reports/x?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=${ticket}%2F20261018%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Signature=${'0'.repeat(64)} HTTP/1.1\r\nHost: ${host}\r\n\r\n`);
    await readResponses(presigned, 1);
    expect(upstream.received[0].url).toContain(ticket);
    expect(logs.some(l => l.includes('result=placement-skipped secrets=aws-reports where=url'))).toBe(true);
    expect(logs.filter(l => l.includes('result=unsignable')).map(l => /reason=(\S+)/.exec(l)?.[1])).toEqual(['sigv4a', 'streaming-signed-payload']);
  });

  it('9. keep-alive: two signed requests on one tunnel are each verified and re-signed', async () => {
    const { logs, upstream, tokenStore, port } = await setup();
    const ticket = issue(tokenStore);
    const host = `127.0.0.1:${upstream.port}`;
    const t = await tunnel(port, upstream.port);
    const first = await agentSign(ticket, { host, path: '/one' });
    const second = await agentSign(ticket, { host, method: 'POST', service: 'sts', path: '/', body: 'Action=GetCallerIdentity', headers: { 'content-type': 'application/x-www-form-urlencoded' } });
    t.write(Buffer.concat([Buffer.from(`${first.head}\r\n\r\n`), first.body, Buffer.from(`${second.head}\r\n\r\n`), second.body]));
    await readResponses(t, 2);
    expect(upstream.received.map(r => r.url)).toEqual(['/one', '/']);
    for (const r of upstream.received) await expectSignedWith(r, REAL);
    expect(logs.filter(l => l.includes('result=signed'))).toHaveLength(2);
  });

  it('10. forward path: plain HTTP re-signs with an http:// binding; without one it is 403 host-mismatch (loopback-listener attack)', async () => {
    const logs = captureLogs();
    const upstream = await startHttpUpstream();
    const { tokenStore, port } = await startProxy();
    const bound = issue(tokenStore, REAL, 'http://127.0.0.1');
    const host = `127.0.0.1:${upstream.port}`;
    const signed = await agentSign(bound, { host, path: '/reports/', query: { prefix: 'reports/', 'list-type': '2' } });
    const res = await viaProxy(port, `http://${host}/reports/?prefix=reports%2F&list-type=2`, signed.headers);
    expect(res.status).toBe(200);
    await expectSignedWith(upstream.received[0], REAL);
    expect(logs.some(l => l.includes('scheme=http') && l.includes('result=signed signing=aws-sigv4'))).toBe(true);

    const httpsOnly = issue(tokenStore, REAL, '127.0.0.1', 'aws-https-only');
    const attack = await agentSign(httpsOnly, { host });
    const denied = await viaProxy(port, `http://${host}/`, attack.headers);
    expect(denied.status).toBe(403);
    expect(denied.headers['x-coatcheck-denied']).toBe('host-mismatch');
    expect(upstream.received).toHaveLength(1);

    // Forward path, body hashed and past the cap: refused, nothing forwarded.
    const big = await agentSign(bound, { host, method: 'POST', service: 'sts', body: Buffer.alloc(2 * 1024 * 1024, 'y') });
    const tooBig = await viaProxy(port, `http://${host}/`, big.headers, 'POST', big.body);
    expect(tooBig.status).toBe(403);
    expect(tooBig.headers['x-coatcheck-denied']).toBe('unsignable');
    // A forward-path request with a small body is hashed and re-signed.
    const small = await agentSign(bound, { host, method: 'POST', service: 'sts', body: 'Action=GetCallerIdentity' });
    expect((await viaProxy(port, `http://${host}/`, small.headers, 'POST', small.body)).status).toBe(200);
    await expectSignedWith(upstream.received[1], REAL);
    seen.logs.push(...logs);
    seen.signed.push(...upstream.received);
  });

  it('11. swap + sign: a swap_body ticket in a signed body is swapped first and the signature covers the swapped body', async () => {
    const { upstream, tokenStore, port } = await setup();
    const ticket = issue(tokenStore);
    const payload = tokenStore.issue('payload', 'real-payload-value-longer-than-a-ticket-is-not-needed', { allowedHosts: hosts('127.0.0.1'), swapBody: true }).id;
    const t = await tunnel(port, upstream.port);
    send(t, await agentSign(ticket, { host: `127.0.0.1:${upstream.port}`, method: 'POST', service: 'sts', headers: { 'content-type': 'application/json' }, body: `{"v":"${payload}"}` }));
    await readResponses(t, 1);
    const echo = upstream.received[0];
    expect(echo.body).toBe('{"v":"real-payload-value-longer-than-a-ticket-is-not-needed"}');
    expect(echo.headers['content-length']).toBe(String(Buffer.byteLength(echo.body!)));
    const auth = await expectSignedWith(echo, REAL);
    expect(auth.signedHeaders).toContain('content-length');
  });

  it('13. bound mode MITMs the signing host on the live ticket before the policy names it', async () => {
    const { logs, upstream, tokenStore, port } = await setup();
    const ticket = issue(tokenStore);
    const t = await tunnel(port, upstream.port);
    send(t, await agentSign(ticket, { host: `127.0.0.1:${upstream.port}` }));
    await readResponses(t, 1);
    expect(logs.some(l => l.includes(`[connect] host=127.0.0.1:${upstream.port} mode=mitm reason=ticket`))).toBe(true);
    await expectSignedWith(upstream.received[0], REAL);
  });

  it('4. no key material on the wire or in the logs, across every signed request in this file', () => {
    expect(seen.signed.length).toBeGreaterThanOrEqual(10);
    const wire = Buffer.concat(seen.wire).toString('latin1');
    const logs = seen.logs.join('\n');
    expect(wire.length).toBeGreaterThan(2 * 1024 * 1024);
    for (const c of [REAL, SESSION]) {
      expect(wire).not.toContain(c.secretAccessKey);
      expect(logs).not.toContain(c.secretAccessKey);
    }
    // The session token must reach AWS on the wire; it never reaches a log.
    expect(logs).not.toContain(SESSION.sessionToken);
    for (const id of seen.tickets) expect(logs).not.toContain(id);
    expect(logs).not.toMatch(/[0-9a-f]{64}/);
    for (const echo of seen.signed) {
      const auth = parseSigV4Authorization(String(echo.headers.authorization)) as SigV4Authorization;
      const req: SignableRequest = { method: echo.method!, target: echo.url, headers: Object.entries(echo.headers).map(([k, v]) => [k, String(v)]) };
      const mode = payloadMode(req);
      const hash = mode.kind === 'header' ? mode.value : createHash('sha256').update(echo.rawBody ?? '').digest('hex');
      const canonical = canonicalRequest(req, auth.signedHeaders, hash, auth.service);
      const sts = stringToSign(amzDateOf(req)!, `${auth.date}/${auth.region}/${auth.service}/aws4_request`, canonical);
      for (const text of [canonical, sts]) {
        expect(logs).not.toContain(text);
        expect(wire).not.toContain(text);
      }
      // The signature is on the wire (that is the point); never in a log.
      expect(logs).not.toContain(auth.signature);
    }
  });
});

/** `HTTPS_PROXY` agent whose inner TLS (to the MITM) trusts coatcheck's CA. */
class TrustingProxyAgent extends HttpsProxyAgent<string> {
  constructor(proxy: string, private readonly ca: string) { super(proxy); }
  override connect(req: Parameters<HttpsProxyAgent<string>['connect']>[0], opts: Parameters<HttpsProxyAgent<string>['connect']>[1]) {
    // https-proxy-agent drops `host` from the inner TLS options, so an IP target would be checked as "localhost".
    const host = opts.host ?? '';
    if (!opts.secureEndpoint) return super.connect(req, opts);
    return super.connect(req, { ...opts, ca: this.ca, checkServerIdentity: (_h, cert) => tls.checkServerIdentity(host, cert) });
  }
}

/** GET a vault route on the proxy port (origin-form). */
async function viaProxyVault(port: number, path: string): Promise<Record<string, unknown>> {
  const res = await fetch(`http://127.0.0.1:${port}${path}`);
  return await res.json() as Record<string, unknown>;
}
