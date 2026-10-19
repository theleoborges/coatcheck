# Client integration guide

How code running next to coatcheck (an agent, its scripts, its tools) obtains
tickets and uses them so the swap actually happens. The tools themselves don't
change: anything that honours `HTTPS_PROXY` and trusts coatcheck's CA works,
including SDKs that sign requests (AWS SigV4, HMAC APIs), which sign with the
ticket and are re-signed by coatcheck (section 3, "Signing tickets").

Assumed setup: coatcheck listening on `127.0.0.1:3128`, and the client
environment has

```bash
export HTTP_PROXY=http://127.0.0.1:3128
export HTTPS_PROXY=http://127.0.0.1:3128
export NO_PROXY=localhost,127.0.0.1,169.254.169.254,169.254.170.2
```

If coatcheck runs with `COATCHECK_API_TOKEN` (required whenever it listens on
anything but loopback), put the token in the proxy URL and send it as a bearer
token to the API:

```bash
export HTTPS_PROXY=http://coatcheck:$COATCHECK_API_TOKEN@coatcheck:3128   # user name is ignored
export HTTP_PROXY=$HTTPS_PROXY
AUTH=(-H "Authorization: Bearer $COATCHECK_API_TOKEN")                    # for /_vault and /_secret
```

Clients send proxy credentials from the URL as `Proxy-Authorization: Basic`;
coatcheck also accepts `Proxy-Authorization: Bearer <token>`. Missing or wrong
credentials get `407` from the proxy and `401` from the API. `/_health` and
`/_ca` never need the token. The examples below omit `"${AUTH[@]}"` for
brevity; add it when the token is set.

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

The CA is generated in memory on every start unless `COATCHECK_CA_DIR` is set and
persists across restarts. If it is regenerated, clients must re-fetch it.

## 2. Get a ticket

| Endpoint | Returns |
|---|---|
| `GET /_vault` | `{"secrets": ["name", …]}` (names only) |
| `GET /_vault/{name}?check=1` | `{"exists": true\|false}` |
| `GET /_vault/{name}` | simple secret: `{"token": "cct_…", "expires_in": 900}`; JSON secret: `{"type": "multi", "fields": [...]}` |
| `GET /_vault/{name}?field=f` | `{"token": …}`, or `{"value": …, "cleartext": true}` if `f` is listed in the secret's `_cleartext` |
| `GET /_secret/{name}` | ticket for an allowlisted shared secret |
| `POST /_vault/{name}/refresh` | refreshes an OAuth secret server-side, returns a ticket for the new `access_token` |
| `POST /_vault/{name}/login` | broker-performed browser login (section 6) |

Ticket responses also carry `allowed_hosts`: the only hosts the ticket will be
swapped for. Sending it anywhere else gets `403` with
`X-Coatcheck-Denied: host-mismatch`, and the request is not forwarded. They
carry `"swap_body": true` when the secret allows its ticket in request bodies,
`"swap_url": true` when it allows it in the URL, and `"swap_headers": […]`
for headers besides `Authorization` it may go in (section 3).

Errors: 404 when the secret is missing (with `vault_url` when the operator set
`COATCHECK_MISSING_SECRET_URL`), 400 for an unknown field or an invalid secret
name, 403 for a shared secret outside the allowlist or a secret with no allowed
hosts, 401 without the API token when one is configured.

```bash
TOK=$(curl -sf http://127.0.0.1:3128/_vault/example-api-key | jq -er .token)
```

Talk to these endpoints directly (`http://127.0.0.1:3128/_vault/…`), not as a
proxied request.

A ticket is a placeholder. Seeing `cct_…` where you expected a secret is
correct. Tickets expire after 15 minutes by default; re-fetch for longer
workflows rather than caching.

## 3. Use the ticket: the literal-substring rule

coatcheck replaces tickets where they appear **verbatim** in the value of the
`Authorization` header. Other headers, the request line (URL, including query
string) and the request body are swapped only for secrets the operator opted
in there (`swap_headers`, `swap_url`, `swap_body`; the ticket response lists
them), because an API that echoes those parts back would hand the agent the
real value.

Works:

```bash
curl -H "Authorization: Bearer $TOK" https://api.example.com/v1/items
curl -H "Authorization: token $TOK"  https://api.example.com/v1/items
curl -H "X-API-Key: $TOK"            https://api.example.com/v1/items  # "swap_headers": ["x-api-key"]
curl "https://api.example.com/v1/items?api_key=$TOK"                  # "swap_url": true
curl -u "me@example.com:$TOK"        https://api.example.com/v1/items  # Basic: decoded, swapped, re-encoded
```

A ticket in `Authorization: Basic` (`curl -u`, `https://user:$TOK@host/`,
`.netrc`, git credential helpers) is swapped in the user name or password.
A real value with a control character, or a `:` in the user name slot, is
refused with `403 invalid-value`.

Fails silently (the upstream receives `cct_…` and returns 401/403):

- **Ticket outside `Authorization`** (another header, the URL), unless the
  secret opts in there. The request is forwarded with the literal and
  coatcheck logs `result=placement-skipped where=…`.
- **Ticket in the request body**, unless the secret opts in (`swap_body` in
  the policy file or `_swap_body: true` in the secret; the ticket response
  then shows `"swap_body": true`). Without it, the body is forwarded
  unchanged and coatcheck logs `result=body-skipped`. With it, coatcheck
  swaps body tickets (JSON-escaped for `application/json`, percent-encoded
  for form bodies, raw otherwise), but not in compressed bodies
  (`Content-Encoding` other than `identity`) or bodies larger than
  `COATCHECK_MAX_SWAP_BODY_BYTES` (default 1 MiB; logged as
  `result=body-unscanned`).
- **Any transform of the ticket**: hashing, HMAC signing with it,
  base64-encoding it, splitting it. The exception is a signing ticket
  (below), which is meant to be used as a key.
- **Traffic that bypasses the proxy** (section 4).
- **A connection opened before any ticket existed** (section 5).

### Signing tickets (AWS SigV4, HMAC)

A mint response with `"signing": "aws-sigv4"` is a **signing ticket**: use it
as both `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY` (or the SDK's
`accessKeyId` and `secretAccessKey`) and send the request through the proxy.
coatcheck parses `Authorization: AWS4-HMAC-SHA256 Credential=cct_…/…`,
recomputes the agent's signature with the ticket as the key over the request
it received, applies the ordinary swaps, and re-signs with the real key and
session token. Design: `docs/design/signing-processors.md`.

```bash
TOK=$(curl -s "$COATCHECK_URL/_vault/aws-reports" | jq -r .token)
AWS_ACCESS_KEY_ID=$TOK AWS_SECRET_ACCESS_KEY=$TOK aws sts get-caller-identity
AWS_ACCESS_KEY_ID=$TOK AWS_SECRET_ACCESS_KEY=$TOK aws s3 cp report.md s3://reports-bucket/reports/
```

- The ticket is never swapped as a literal anywhere. `Authorization: Bearer
  cct_…` with it is forwarded unchanged (`result=signing-skipped`) and the
  upstream rejects it.
- **Presigned URLs don't work.** `aws s3 presign` puts the ticket in
  `X-Amz-Credential`; it leaves as a literal (`result=placement-skipped
  where=url`) and S3 answers `InvalidAccessKeyId`.
- **Bodies.** S3 clients send `x-amz-content-sha256`, so uploads stream at
  any size. Other services hash the body: it is buffered up to
  `COATCHECK_MAX_SWAP_BODY_BYTES`, and past it the request is refused with
  `403 unsignable reason=body-too-large`.
- **Refused shapes** (`403`, `X-Coatcheck-Denied: unsignable`, nothing
  forwarded): SigV4a (`reason=sigv4a`), per-chunk signed streaming payloads
  (`STREAMING-AWS4-HMAC-SHA256-PAYLOAD`, `reason=streaming-signed-payload`;
  SDK defaults stream unsigned), an `Authorization` that doesn't parse
  (`reason=malformed-authorization`).
- **`403 signature-mismatch`**: the agent's signature doesn't match the request
  coatcheck received. A header changed after signing, a client library that
  canonicalises differently, or a key other than the ticket.
- `?field=secret_access_key` is `400`: there is no literal ticket for the key.
  Other fields get normal tickets; `_cleartext` fields (`region`) return values.

| `[swap] result=` | Meaning |
|---|---|
| `signed signing=aws-sigv4\|hmac secrets=…` | Verified and re-signed; forwarded. |
| `signature-mismatch secrets=…` | `403`, not forwarded. |
| `unsignable secrets=… reason=…` | `403`, not forwarded. |
| `signing-skipped secrets=…` | The signing ticket was used as a literal; forwarded as is. |

**HMAC.** A mint response with `"signing": {"type": "hmac", …}` carries the
operator's recipe: `hash`, `encoding`, `key_header`, `signature_header` and
`message`, the parts concatenated in order (`method` as sent, `path`, `query`
without `?`, `path_query`, `body` bytes as sent, `header:<name>` trimmed with
repeats joined by `,`, `literal:<text>`). The ticket is both the API key and
the HMAC secret: send it as the whole value of `key_header` and sign the
message with it as a UTF-8 key. With no SDK, a few lines of bash do:

```bash
TOK=$(curl -s "$COATCHECK_URL/_vault/ledger" | jq -r .token)
TS=$(date +%s); PQ='/v1/accounts'
SIG=$(printf '%s' "${TS}GET${PQ}" | openssl dgst -sha256 -hmac "$TOK" -binary | base64)
curl -H "X-Ledger-Key: $TOK" -H "X-Ledger-Timestamp: $TS" -H "X-Ledger-Signature: $SIG" "https://ledger:8443$PQ"
```

coatcheck verifies that signature (unless the recipe says `"verify": false`),
replaces `key_header` with the real `key_id` (or removes it when there is
none), and overwrites `signature_header`. A key header that is repeated or
holds more than the ticket is `403 unsignable reason=malformed-key-header`;
`?field=secret` is `400`. A recipe that signs the key header sees the ticket
on your side and the `key_id` upstream; you don't need to do anything about
that. Timestamps and nonces are yours to set; replay windows are the API's.

A 401/403 when using a ticket almost always means the swap did not happen.
Debug the call path; the stored secret is usually fine. coatcheck logs
`[swap] … result=miss unswapped_ticket_literals=N` when a `cct_` literal reaches
an upstream unswapped.

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
- hosts you reach with non-HTTP/1.1 protocols over CONNECT (gRPC or other
  HTTP/2-only services, raw TCP). coatcheck MITMs a CONNECT when a ticket
  could be swapped for its host (`COATCHECK_MITM=bound`, the default) or
  always (`COATCHECK_MITM=always`), and speaks only HTTP/1.1 on intercepted
  tunnels. WebSocket upgrades work: after `101` the tunnel is a raw pipe.

Never put a host in `NO_PROXY` that you need a ticket swapped for.

## 5. Connection reuse

coatcheck decides at CONNECT time whether to intercept a tunnel, and the
decision lasts for the tunnel's lifetime. Hosts in the operator's policy file
are always intercepted. A host allowed only by a secret's own
`_allowed_hosts` is intercepted only once a live ticket names it, so a
long-running process with a keep-alive pool that connected to
`api.example.com` before fetching that ticket sends it down an uninspected
tunnel (the upstream sees `cct_…` and rejects it). Fetch the ticket first, or
open a fresh connection after fetching it.

## 6. Browser logins (CDP injection)

Requires `COATCHECK_CDP_ENABLED=1` on coatcheck. The credential is a JSON secret
with one field per form input (usually `username` and `password`), addressed by
its secret name, with allowed hosts like any other secret.

1. Create the remote-browser session **through the proxy**, with the vendor
   API key as a ticket. coatcheck injects the real key and rewrites the
   response's `connectUrl` to `ws://127.0.0.1:8444/cdp/{sid}` (host and port
   from `COATCHECK_CDP_ADVERTISE_HOST` and `COATCHECK_CDP_PORT`). For
   Browserbase it also removes `signingKey`, `seleniumRemoteUrl` and live-view
   URLs from responses, and strips `extensionId` from the session-create
   body (a body to that host it can't read as JSON is refused with `403
   uninspectable-body`; `multipart/form-data` uploads are the exception):

   ```js
   const COATCHECK = 'http://127.0.0.1:3128';
   const apiTok = (await getJson(`${COATCHECK}/_secret/browser-api-key`)).token;
   // The policy entry lists the vendor's key header: "swap_headers": ["x-api-key"].
   const session = await postViaProxy('https://api.browser-vendor.example/v1/sessions',
                                      { 'x-api-key': apiTok }, { /* session options */ });
   const sid = session.connectUrl.match(/\/cdp\/([a-f0-9]+)/)?.[1];
   if (!sid) throw new Error('connectUrl not rewritten: CDP proxy disabled or request not proxied');
   ```

   Use the vendor session id for vendor REST calls; use `sid` (from the
   rewritten URL) for coatcheck.

2. Connect to the rewritten URL, navigate to the login page, and ask coatcheck
   to log in. coatcheck fills and submits the form itself over the CDP
   connection; the agent never holds a credential ticket:

   ```js
   const browser = await chromium.connectOverCDP(session.connectUrl); // the ws://127.0.0.1 URL
   const page = browser.contexts()[0]?.pages()[0] ?? await browser.newPage();
   await page.goto('https://site.example/login');

   // Direct to coatcheck, not through the proxy.
   const res = await postJson(`${COATCHECK}/_vault/example-login/login`, {
     sessionId: sid,
     fields: { username: 'input[name=email]', password: 'input[name=password]' },
     submit: 'button[type=submit]',
     until: 'navigation',
   });
   // res.status === 'ok' → logged in; carry on with the page.
   ```

   `fields` maps each field of the login secret to a CSS selector resolved in
   the main document. `submit` is a selector to click or `{"press":"Enter"}`.
   `until` is `"navigation"` (default), `{"selector":"…"}` or `{"urlPrefix":"…"}`
   — the last two cover SPA logins. `timeoutMs` defaults to 15 000 (max 60 000).
   If more than one page is open, add `page: {"url": "<url prefix>"}` to pick
   the one to log in on.

   Responses:

   | Status | Body | Meaning |
   |---|---|---|
   | 200 | `{"status":"ok","url":…}` | logged in; `url` is the page's URL after login |
   | 400 | `{"error":…}` | malformed request body |
   | 403 | `{"error":"credential-origin violation: …"}` | page origin unknown, navigating, not http(s), or not an allowed host (or the secret has no allowed hosts); nothing filled |
   | 404 | `{"status":"unknown-sid-or-secret"}` | no live CDP connection for `sessionId`, or no such secret |
   | 404 | `{"status":"selector-not-found","field":…}` | a field selector matched nothing |
   | 409 | `{"status":"page-ambiguous"}` | zero or several matching pages |
   | 409 | `{"status":"interception-active"}` | request interception is on for the page |
   | 409 | `{"status":"no-success","cleared":true}` | `until` not met in time; filled fields were emptied |
   | 501 | `{"error":…}` | the secret is not a JSON login secret with the requested fields |
   | 502 | `{"status":"upstream-closed"}` or `{"status":"driver-error","cleared":true}` | the browser connection dropped, or a CDP command failed |

Rules:

- **Navigate to the login page and let it load before calling `/login`.** The
  page's committed main-frame origin must be one of the login secret's allowed
  hosts, or the login is refused with `403`. Before filling, coatcheck removes
  any scripts you added with `addInitScript` (`Page.addScriptToEvaluateOnNewDocument`)
  and reloads the page, so in-page state and init scripts do not survive the
  login. Re-add them afterwards if you need them.
- **Don't enable request interception on the login page** (`page.route(...)`,
  `Fetch.enable`): coatcheck refuses the login with `409 interception-active`
  rather than silently disabling your interception. Turn it off, log in, turn
  it back on.
- **Outside the login call there are no credential tickets in the browser**, so
  `page.type()`, `page.evaluate()` and screenshots are all fine. On a timeout
  coatcheck empties the fields it filled before returning (`409 no-success`).
- **Never connect to the vendor's raw `connectUrl`** or any debug/live-view
  URL; the login driver and inbound redaction only apply on coatcheck's listener.
- **One CDP connection at a time.** A second concurrent connection is refused
  (close code 1013).
- A sid is single-use: after the WebSocket closes, create a new session.
- Close the browser and release the vendor session when done; coatcheck does
  not release it.
- Logins inside a cross-origin iframe don't work: selectors resolve in the
  main document only, so the fields aren't found (`404 selector-not-found`).
  Navigate to the identity provider's own page first. Sites that require 2FA/OTP are not supported.

## 7. git over HTTPS

git sends credentials as `Authorization: Basic`. coatcheck decodes Basic
credentials, swaps tickets in the user name or password, and re-encodes them,
so a credential helper can hand git a ticket as the password. Mint a fresh one
per request so a cached ticket never outlives its TTL:

```bash
# The empty entry drops earlier helpers (e.g. osxkeychain), which would store
# the ticket and hand it back after it expires.
git config --global --add credential.https://git.example.com.helper ''
git config --global --add credential.https://git.example.com.helper \
  '!f() { test "$1" = get || exit 0; echo username=x-access-token;
          echo "password=$(curl -sf http://127.0.0.1:3128/_vault/git-token | jq -er .token)"; }; f'
git clone https://git.example.com/org/repo.git
```

(`x-access-token` is GitHub's convention for a token as the password; most
hosts accept any user name with a token.) `GIT_ASKPASS` and `.netrc` work the
same way, but a ticket written to a file expires after 15 minutes. A Bearer
header works too, on hosts that accept Bearer tokens for smart-HTTP:

```bash
TOK=$(curl -sf http://127.0.0.1:3128/_vault/git-token | jq -er .token)
git -c http.extraHeader="Authorization: Bearer ${TOK}" clone https://git.example.com/org/repo.git
```

## 8. Shell wrapper example

```bash
#!/usr/bin/env bash
# get-secret.sh <name> [--field f] [--check]   -> prints a ticket (or cleartext field)
set -euo pipefail
NAME=$1; shift
BASE=${COATCHECK_URL:-http://127.0.0.1:3128}
AUTH=(); [[ -n ${COATCHECK_API_TOKEN:-} ]] && AUTH=(-H "Authorization: Bearer $COATCHECK_API_TOKEN")
QS=""; CHECK=0
while [[ $# -gt 0 ]]; do
  case $1 in --field) QS="?field=$2"; shift 2;; --check) CHECK=1; shift;; *) shift;; esac
done
if [[ $CHECK == 1 ]]; then
  [[ $(curl -sf "${AUTH[@]}" "$BASE/_vault/$NAME?check=1" | jq -r .exists) == true ]] && echo EXISTS || { echo NOT_FOUND; exit 2; }
  exit 0
fi
RESP=$(curl -s "${AUTH[@]}" -w '\n%{http_code}' "$BASE/_vault/$NAME$QS")
CODE=${RESP##*$'\n'}; BODY=${RESP%$'\n'*}
[[ $CODE -ge 400 ]] && { echo "$(jq -r '.error // "not found"' <<<"$BODY")" >&2; exit 2; }
case $(jq -r '.type // (if .cleartext then "clear" else "tok" end)' <<<"$BODY") in
  multi) jq -c .fields <<<"$BODY" ;;
  clear) jq -j .value <<<"$BODY" ;;
  *)     jq -j .token <<<"$BODY" ;;
esac
```

Pipe the output straight into the consuming command (`KEY=$(get-secret.sh x)
curl -H "Authorization: Bearer $KEY" …`). Tickets are not secrets, but treating them as
opaque and short-lived keeps agent prompts and logs clean.
