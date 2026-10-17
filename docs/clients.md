# Client integration guide

How code running next to coatcheck (an agent, its scripts, its tools) obtains
tickets and uses them so the swap actually happens.

Assumed setup: coatcheck listening on `127.0.0.1:3128`, and the client
environment has

```bash
export HTTP_PROXY=http://127.0.0.1:3128
export HTTPS_PROXY=http://127.0.0.1:3128
export NO_PROXY=localhost,127.0.0.1,169.254.169.254,169.254.170.2
```

## 1. Trust the coatcheck CA

coatcheck terminates TLS with its own CA. Fetch the CA certificate from
`/_ca` at startup, after `/_health` responds, and install it before starting
any long-lived process:

```bash
PROXY=http://127.0.0.1:3128
for i in $(seq 1 30); do curl -sf "$PROXY/_health" >/dev/null && break; sleep 1; done

curl -sf "$PROXY/_ca" -o /tmp/coatcheck-ca.crt

# System store (curl, git, most CLIs; Debian/Ubuntu shown)
cp /tmp/coatcheck-ca.crt /usr/local/share/ca-certificates/coatcheck-ca.crt
update-ca-certificates

# Node reads this only at process start
export NODE_EXTRA_CA_CERTS=/tmp/coatcheck-ca.crt

# Python requests/httpx bundle certifi and ignore the system store
export REQUESTS_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt
export SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt
```

The CA is generated in memory on every start unless `CA_DIR` is set and
persists across restarts. If it is regenerated, clients must re-fetch it.

## 2. Get a ticket

| Endpoint | Returns |
|---|---|
| `GET /_vault` | `{"secrets": ["name", …]}` (names only) |
| `GET /_vault/{name}?check=1` | `{"exists": true\|false}` |
| `GET /_vault/{name}` | simple secret: `{"token": "tok_…", "expires_in": 900}`; JSON secret: `{"type": "multi", "fields": [...]}` |
| `GET /_vault/{name}?field=f` | `{"token": …}`, or `{"value": …, "cleartext": true}` if `f` is listed in the secret's `_cleartext` |
| `GET /_secret/{name}` | ticket for an allowlisted shared secret |
| `POST /_vault/{name}/refresh` | refreshes an OAuth secret server-side, returns a ticket for the new `access_token` |
| `POST /_vault/mint-tokens` | session-bound login tickets for browser injection (section 6) |

Errors: 404 when the secret is missing, 400 for an unknown field, 403 for a
shared secret outside the allowlist.

```bash
TOK=$(curl -sf http://127.0.0.1:3128/_vault/example-api-key | jq -er .token)
```

Talk to these endpoints directly (`http://127.0.0.1:3128/_vault/…`), not as a
proxied request.

A ticket is a placeholder. Seeing `tok_…` where you expected a secret is
correct. Tickets expire after 15 minutes by default; re-fetch for longer
workflows rather than caching.

## 3. Use the ticket: the literal-substring rule

coatcheck replaces tickets wherever they appear **verbatim** in the request
line (URL, including query string) or headers. Nothing else is inspected.

Works:

```bash
curl -H "Authorization: Bearer $TOK" https://api.example.com/v1/items
curl -H "Authorization: token $TOK"  https://api.example.com/v1/items
curl -H "X-API-Key: $TOK"            https://api.example.com/v1/items
curl "https://api.example.com/v1/items?api_key=$TOK"
```

Fails silently (the upstream receives `tok_…` and returns 401/403):

- **HTTP Basic auth.** `curl -u user:$TOK`, `https://user:$TOK@host/`,
  `.netrc`, credential helpers. The client base64-encodes `user:tok_…` into
  `Authorization: Basic …`, which hides the literal.
- **Ticket in the request body** (JSON, form-encoded, multipart). Bodies are
  forwarded unchanged.
- **Any transform of the ticket**: hashing, HMAC signing with it, URL- or
  base64-encoding it, splitting it.
- **Traffic that bypasses the proxy** (section 4).
- **A connection opened before any ticket existed** (section 5).

A 401/403 when using a ticket almost always means the swap did not happen.
Debug the call path; the stored secret is usually fine. coatcheck logs
`[swap] … result=miss unswapped_tok_literals=N` when a `tok_` literal reaches
an upstream unswapped.

Also avoid `Transfer-Encoding: chunked` request bodies (send a
`Content-Length`; `curl -d` and most clients do).

## 4. Make sure the request goes through coatcheck

| Client | Honours `HTTPS_PROXY`? | What to do |
|---|---|---|
| curl, wget | yes | nothing |
| git (HTTPS) | yes | nothing (see section 7 for auth) |
| Python `requests`, `httpx` | yes | set CA bundle vars (section 1) |
| Node `https` / `http` modules | **no** | pass an explicit agent |
| Node global `fetch` (undici) | not by default | `NODE_USE_ENV_PROXY=1` on Node versions that support it, or undici `EnvHttpProxyAgent` / `ProxyAgent` as dispatcher |
| Playwright `connectOverCDP` | n/a | connects to the URL you give it; use the rewritten URL (section 6) |

Node `https` with `https-proxy-agent`:

```js
// https-proxy-agent v5 (CommonJS): default export, do not destructure.
// v7+ is ESM and exports { HttpsProxyAgent }.
const HttpsProxyAgent = require('https-proxy-agent');
const https = require('https');

const agent = new HttpsProxyAgent(process.env.HTTPS_PROXY);
https.request({
  hostname: 'api.example.com',
  path: '/v1/items',
  method: 'GET',
  headers: { Authorization: `Bearer ${tok}` },
  agent,                       // without this the request goes direct and fails
}, res => { /* ... */ }).end();
```

### `NO_PROXY`

Put in `NO_PROXY` everything that must **not** be intercepted:

- loopback (`localhost,127.0.0.1`), so calls to coatcheck's own endpoints are
  not proxied to itself;
- cloud metadata and credential endpoints (`169.254.169.254`, `169.254.170.2`);
- internal services that never need a ticket;
- hosts you reach with non-HTTP/1.1 protocols over CONNECT (WebSocket
  endpoints, gRPC/HTTP2-only services). Once any ticket exists, coatcheck
  MITMs every CONNECT and parses it as HTTP/1.1; an upgraded or non-HTTP
  stream will stall.

Never put a host in `NO_PROXY` that you need a ticket swapped for.

## 5. Connection reuse

coatcheck decides at CONNECT time whether to intercept a tunnel. If no ticket
exists yet, the tunnel is a raw passthrough for its whole lifetime. A
long-running process with a keep-alive pool that connected to `api.example.com`
before fetching a ticket will send the ticket down an uninspected tunnel.
Fetch the ticket first, or open a fresh connection after fetching it.

## 6. Browser logins (CDP injection)

Requires `CDP_PROXY_ENABLED=1` on coatcheck. The credential is a JSON secret
with `username` and `password` fields, addressed by its secret name.

1. Create the remote-browser session **through the proxy**, with the vendor
   API key as a ticket. coatcheck injects the real key and rewrites the
   response's `connectUrl` to `ws://127.0.0.1:8444/cdp/{sid}`:

   ```js
   const apiTok = (await getJson('http://127.0.0.1:3128/_secret/browser-api-key')).token;
   const session = await postViaProxy('https://api.browser-vendor.example/v1/sessions',
                                      { 'x-api-key': apiTok }, { /* session options */ });
   const sid = session.connectUrl.match(/\/cdp\/([a-f0-9]+)/)?.[1];
   if (!sid) throw new Error('connectUrl not rewritten: CDP proxy disabled or request not proxied');
   ```

   Use the vendor session id for vendor REST calls; use `sid` (from the
   rewritten URL) for coatcheck.

2. Mint session-bound tickets:

   ```bash
   curl -s -X POST http://127.0.0.1:3128/_vault/mint-tokens \
     -H 'Content-Type: application/json' \
     -d "$(jq -n --arg n example-login --arg s "$SID" '{secretName:$n, sessionId:$s}')"
   # {"username_token":"tok_…","password_token":"tok_…","expires_in":600}
   ```

   Optional `expires_in` (seconds, capped at 1800). These tickets work only
   inside that CDP session and are revoked when its WebSocket closes. They do
   not work on the HTTPS path.

3. Connect to the rewritten URL and fill with **`page.fill()`**:

   ```js
   const browser = await chromium.connectOverCDP(session.connectUrl); // the ws://127.0.0.1 URL
   const page = browser.contexts()[0]?.pages()[0] ?? await browser.newPage();
   await page.goto('https://site.example/login');
   await page.fill('input[name=email]', usernameToken);
   await page.fill('input[name=password]', passwordToken);
   await page.click('button[type=submit]');
   ```

Rules:

- **`page.fill()`, never `page.type()`** for ticket values. `fill()` sends one
  `Input.insertText` frame that coatcheck substitutes. `type()` sends one key
  event per character; coatcheck cannot substitute that and fails the final
  keystroke with a CDP error ("credential-flow violation").
  `page.evaluate(fn, ticket)` and string `page.evaluate` are also substituted.
- **Never connect to the vendor's raw `connectUrl`** or any debug/live-view
  URL; substitution and redaction only apply on coatcheck's listener.
- **Do not screenshot during login, do not toggle "show password", and do not
  read a credential field's `.value` back.** Inbound frames containing the
  real value are redacted to `[REDACTED:<name>]` or dropped (a dropped
  response makes the awaiting call hang until timeout).
- **One CDP connection at a time.** A second concurrent connection is refused
  (close code 1013).
- A sid is single-use: after the WebSocket closes, create a new session.
- Close the browser and release the vendor session when done; coatcheck does
  not release it.
- Sites that require 2FA/OTP at login are not supported.

## 7. git over HTTPS

git defaults to Basic auth, which hides the ticket. Send it as a Bearer header
instead. GitHub, GitLab, Gitea, and Bitbucket Cloud accept Bearer tokens for
smart-HTTP.

```bash
TOK=$(curl -sf http://127.0.0.1:3128/_vault/git-token | jq -er .token)
git -c http.extraHeader="Authorization: Bearer ${TOK}" clone https://git.example.com/org/repo.git
```

`-c` scopes the header to one invocation; nothing is written to
`~/.gitconfig`. For a multi-step workflow:

```bash
git_auth() { git -c http.extraHeader="Authorization: Bearer ${TOK}" "$@"; }
git_auth clone https://git.example.com/org/repo.git
cd repo
# local commands need no auth
git_auth push
```

Do not use any of these with a ticket: `https://user:$TOK@host/…`, a
credential helper, `GIT_ASKPASS`, `.netrc`. All end in Basic auth.

## 8. Shell wrapper example

```bash
#!/usr/bin/env bash
# get-secret.sh <name> [--field f] [--check]   -> prints a ticket (or cleartext field)
set -euo pipefail
NAME=$1; shift
BASE=${COATCHECK_URL:-http://127.0.0.1:3128}
QS=""; CHECK=0
while [[ $# -gt 0 ]]; do
  case $1 in --field) QS="?field=$2"; shift 2;; --check) CHECK=1; shift;; *) shift;; esac
done
if [[ $CHECK == 1 ]]; then
  [[ $(curl -sf "$BASE/_vault/$NAME?check=1" | jq -r .exists) == true ]] && echo EXISTS || { echo NOT_FOUND; exit 2; }
  exit 0
fi
RESP=$(curl -s -w '\n%{http_code}' "$BASE/_vault/$NAME$QS")
CODE=${RESP##*$'\n'}; BODY=${RESP%$'\n'*}
[[ $CODE -ge 400 ]] && { echo "$(jq -r '.error // "not found"' <<<"$BODY")" >&2; exit 2; }
case $(jq -r '.type // (if .cleartext then "clear" else "tok" end)' <<<"$BODY") in
  multi) jq -c .fields <<<"$BODY" ;;
  clear) jq -j .value <<<"$BODY" ;;
  *)     jq -j .token <<<"$BODY" ;;
esac
```

Pipe the output straight into the consuming command (`KEY=$(get-secret.sh x)
curl -H "X-API-Key: $KEY" …`). Tickets are not secrets, but treating them as
opaque and short-lived keeps agent prompts and logs clean.
