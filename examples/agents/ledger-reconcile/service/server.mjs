// ledger: a small HMAC-protected internal API for the ledger-reconcile example.
// node:https + node:crypto, no dependencies. Auth, modelled on the common
// exchange recipe:
//   X-Ledger-Key        key id
//   X-Ledger-Timestamp  unix seconds, accepted within ±30 s
//   X-Ledger-Signature  base64(HMAC-SHA256(secret, timestamp + method + path_query + body))
// Two keys: auditor (read-only) and operator (may POST). Logs one line per
// request with the key id and outcome; never signatures or secrets.
import https from 'node:https';
import fs from 'node:fs';
import { createHmac, timingSafeEqual } from 'node:crypto';

const env = name => {
  const v = process.env[name];
  if (!v) throw new Error(`${name} is required`);
  return v;
};
const KEYS = new Map([
  [env('LEDGER_AUDITOR_KEY_ID'), { secret: env('LEDGER_AUDITOR_SECRET'), role: 'auditor' }],
  [env('LEDGER_OPERATOR_KEY_ID'), { secret: env('LEDGER_OPERATOR_SECRET'), role: 'operator' }],
]);
const WINDOW_S = 30;
const MAX_BODY = 1024 * 1024;
const data = JSON.parse(fs.readFileSync(new URL('./data.json', import.meta.url), 'utf8'));
const transfers = [];

function send(res, status, body) {
  const text = JSON.stringify(body);
  res.writeHead(status, { 'content-type': 'application/json', 'content-length': Buffer.byteLength(text) });
  res.end(text);
}

function authenticate(req, body) {
  const keyId = req.headers['x-ledger-key'];
  const ts = req.headers['x-ledger-timestamp'];
  const sig = req.headers['x-ledger-signature'];
  if (typeof keyId !== 'string' || typeof ts !== 'string' || typeof sig !== 'string') return { error: 'missing-auth-headers' };
  const key = KEYS.get(keyId);
  if (!key) return { error: 'unknown-key' };
  if (!/^\d{1,12}$/.test(ts) || Math.abs(Date.now() / 1000 - Number(ts)) > WINDOW_S) return { error: 'stale-timestamp', keyId };
  const expected = createHmac('sha256', key.secret)
    .update(Buffer.concat([Buffer.from(ts + req.method + req.url, 'utf8'), body]))
    .digest('base64');
  const a = Buffer.from(sig);
  const b = Buffer.from(expected);
  if (a.length !== b.length || !timingSafeEqual(a, b)) return { error: 'bad-signature', keyId };
  return { keyId, role: key.role };
}

function route(req, body, auth) {
  const url = new URL(req.url, 'https://ledger');
  const parts = url.pathname.split('/').filter(Boolean);
  if (req.method === 'GET' && url.pathname === '/v1/accounts') {
    return [200, { accounts: data.accounts.map(({ id, name, currency, balance, as_of }) => ({ id, name, currency, balance, as_of })) }];
  }
  if (req.method === 'GET' && parts.length === 3 && parts[0] === 'v1' && parts[1] === 'accounts') {
    const account = data.accounts.find(a => a.id === parts[2]);
    return account ? [200, account] : [404, { error: 'no such account' }];
  }
  if (req.method === 'GET' && parts.length === 4 && parts[0] === 'v1' && parts[1] === 'accounts' && parts[3] === 'transactions') {
    if (!data.accounts.some(a => a.id === parts[2])) return [404, { error: 'no such account' }];
    const since = url.searchParams.get('since') ?? '';
    return [200, { account: parts[2], transactions: data.transactions.filter(t => t.account === parts[2] && t.date >= since) }];
  }
  if (req.method === 'POST' && url.pathname === '/v1/transfers') {
    if (auth.role !== 'operator') return [403, { error: 'this key is read-only' }];
    let transfer;
    try { transfer = JSON.parse(body.toString('utf8')); } catch { return [400, { error: 'invalid JSON' }]; }
    transfers.push(transfer);
    return [201, { id: `tr_${transfers.length}`, status: 'accepted' }];
  }
  return [404, { error: 'not found' }];
}

const server = https.createServer({
  key: fs.readFileSync(process.env.LEDGER_TLS_KEY ?? '/certs/ledger.key'),
  cert: fs.readFileSync(process.env.LEDGER_TLS_CERT ?? '/certs/ledger.crt'),
}, (req, res) => {
  const chunks = [];
  let size = 0;
  req.on('error', () => res.destroy());
  req.on('data', c => {
    size += c.length;
    if (size > MAX_BODY) { send(res, 413, { error: 'body too large' }); req.destroy(); return; }
    chunks.push(c);
  });
  req.on('end', () => {
    if (size > MAX_BODY) return;
    const body = Buffer.concat(chunks);
    const auth = authenticate(req, body);
    const path = req.url.split('?')[0];
    if (auth.error) {
      console.log(`[ledger] ${req.method} ${path} key=${auth.keyId ?? '-'} outcome=401 reason=${auth.error}`);
      return send(res, 401, { error: 'unauthorized', reason: auth.error });
    }
    const [status, out] = route(req, body, auth);
    console.log(`[ledger] ${req.method} ${path} key=${auth.keyId} role=${auth.role} outcome=${status}`);
    send(res, status, out);
  });
});
server.listen(Number(process.env.PORT ?? 8443), () => console.log(`[ledger] listening on ${server.address().port}`));
process.on('SIGTERM', () => server.close(() => process.exit(0)));
