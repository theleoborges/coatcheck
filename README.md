# coatcheck

A credential broker sidecar for AI agents. The agent never holds a real secret: it asks coatcheck for one by name, gets back a short-lived ticket, and coatcheck swaps the ticket for the real value on the wire, in outbound HTTPS requests and in browser (CDP) sessions. Keys that are never sent but sign each request (AWS access keys, HMAC API secrets) work too: the agent's unmodified SDK signs with the ticket, and coatcheck re-signs with the real key.

The agent doesn't change its tools for any of this. curl, git, the AWS CLI, an SDK, or a script the model just wrote all work as they are: they only need `HTTPS_PROXY` and coatcheck's CA.

It works like a coat check. You hand over the coat and get a ticket. The ticket gets you the coat back at that counter. Anywhere else it is a worthless scrap of paper. If a prompt injection gets the agent to print, log, or exfiltrate its credentials, what leaks is a ticket that expires in minutes and only works against the hosts the secret is bound to.

> **Status: pre-1.0.** The API, ticket format and configuration may still change, and there are known gaps. Read [Status & known limitations](#status--known-limitations) before you depend on it.

**Contents:** [How it works](#how-it-works) · [Quickstart](#quickstart) · [Example agents](#example-agents) · [Setting up the agent container](#setting-up-the-agent-container) · [Using tickets](#using-tickets) · [Policy file](#policy-file) · [Browser login (CDP)](#browser-login-cdp) · [Secret providers](#secret-providers) · [HTTP API](#http-api) · [Configuration](#configuration) · [Status & known limitations](#status--known-limitations) · [vs. superfly/tokenizer](#how-this-differs-from-superflytokenizer) · [Development](#development) · [Docs](#docs)

## How it works

```
 agent container                         coatcheck sidecar                       upstream
┌──────────────────────┐               ┌──────────────────────────┐
│                      │ GET /_vault/  │ vault API                │  fetch by name
│ get ticket ──────────┼──────────────>│  issue cct_… (15 min) ───┼──────────> secret backend
│   <── cct_9f2c…      │               │                          │            (env, file, AWS)
│                      │               │                          │
│ curl -H "Authorization: Bearer cct_9f2c…" https://api.github.com/…
│   HTTPS_PROXY ───────┼── CONNECT ───>│ MITM TLS (own CA)        │
│                      │               │ cct_9f2c… -> real value ─┼──────────> api.github.com
│                      │               │ in Authorization header  │
│                      │               │                          │
│ playwright           │  ws://…/cdp/  │ CDP WebSocket proxy      │
│   POST /_vault/{n}/  │               │ coatcheck fills & submits│
│        login ────────┼──────────────>│ the form itself ─────────┼──────────> browser service
│                      │<──────────────┤ redact echoed secrets    │            (Browserbase)
└──────────────────────┘               └──────────────────────────┘
```

1. **Tickets.** The agent calls `GET /_vault/{name}`. coatcheck fetches the secret from its backend and returns a ticket: `cct_` plus 64 hex characters. Tickets live only in coatcheck's memory and expire after 15 minutes. Each one is bound to the secret's allowed hosts (see [Policy file](#policy-file)); a secret with no allowed hosts gets no ticket.
2. **HTTPS substitution.** The agent container sets `HTTPS_PROXY` to coatcheck and trusts coatcheck's CA. When the agent opens a tunnel to a host a ticket could be used on, coatcheck intercepts it with a certificate it signs itself, replaces the ticket in the `Authorization` header (the URL, other headers and the body only for secrets that opt in; see [Swap placement](#swap-placement)), and re-encrypts to the real host with normal certificate verification. A ticket is only replaced when the tunnel's target is one of its allowed hosts; otherwise the request is refused with `403` and never forwarded. Tunnels to every other host pass through untouched. This works with unmodified tools (curl, git, Python `requests`, Node `fetch`) because they only need proxy support and a trusted CA.
3. **Signed requests.** For a signing key, the ticket stands in for the key itself: the agent's SDK signs with it (`AWS_ACCESS_KEY_ID=$TOK AWS_SECRET_ACCESS_KEY=$TOK aws s3 cp …`). coatcheck checks the host binding, verifies the agent signed exactly the request it received, and re-signs it with the real key. The real key never leaves coatcheck in any form. See [Signed requests](#signed-requests).
4. **Browser login.** With the CDP proxy enabled, coatcheck rewrites the browser service's connection URLs so the agent's Playwright client connects through coatcheck. The agent navigates to a login page and calls `POST /_vault/{name}/login`; coatcheck fills and submits the form itself, on a freshly reloaded page with the agent paused, so no credential ever enters the agent's reach. It also redacts any real value the page echoes back. See [Browser login (CDP)](#browser-login-cdp).
5. **OAuth refresh.** `POST /_vault/{name}/refresh` runs the refresh-token exchange inside coatcheck, writes the new tokens back to the backend, and returns a ticket for the new access token.

## Quickstart

You need Docker. Secrets come from environment variables (the `env` provider), so no cloud account is involved.

```bash
export COATCHECK_API_TOKEN=$(openssl rand -hex 32)   # required: the demo listens on 0.0.0.0
docker compose -f examples/docker-compose.env.yml up
```

This starts coatcheck on `localhost:3128` with three demo secrets from the compose file: `example-api-key` and `example-echo-key` (single values) and `example-login` (a username/password pair). In another terminal:

```bash
# 1. Get a ticket
curl -s -H "Authorization: Bearer $COATCHECK_API_TOKEN" localhost:3128/_vault/example-api-key
# {"token":"cct_3b1e…","expires_in":900,"allowed_hosts":["httpbin.org"]}

# 2. Fetch coatcheck's CA
curl -s localhost:3128/_ca > /tmp/coatcheck-ca.crt

# 3. Use the ticket as if it were the real key (the API token doubles as the proxy password)
curl -s --proxy http://coatcheck:$COATCHECK_API_TOKEN@localhost:3128 --cacert /tmp/coatcheck-ca.crt \
  -H "Authorization: Bearer cct_3b1e…" https://httpbin.org/headers
```

httpbin echoes the request headers, so step 3 shows the **real** value (`sk-demo-not-a-real-key`) arriving upstream. The demo binds a secret to httpbin on purpose, to make the swap visible. The echo that shows you the value would show it to an agent too: never bind a real secret to a host that reflects requests back (see [Swap placement](#swap-placement)). The demo policy (`examples/policy.example.json`) binds `example-api-key` to `httpbin.org` only. Sent to `postman-echo.com`, a host bound to a different secret, the same ticket is refused:

```bash
curl -s --proxy http://coatcheck:$COATCHECK_API_TOKEN@localhost:3128 --cacert /tmp/coatcheck-ca.crt \
  -H "Authorization: Bearer cct_3b1e…" https://postman-echo.com/headers
# HTTP 403, X-Coatcheck-Denied: host-mismatch
# {"error":"Secret 'example-api-key' is not allowed for host 'postman-echo.com'",…}
```

Sent to a host that no secret is bound to, such as `example.org`, the request goes through an untouched tunnel and only the useless `cct_…` literal arrives.

To add a secret, add `COATCHECK_SECRET_<NAME>` to the compose file's environment, give it allowed hosts in `examples/policy.example.json`, and restart. See [env provider names](#env-provider-names) for the name mapping.

The same demo runs against the AWS provider with [LocalStack](https://github.com/localstack/localstack) instead of environment variables (same `COATCHECK_API_TOKEN`, same commands):

```bash
docker compose -f examples/docker-compose.localstack.yml up --build
```

**Getting coatcheck.** The broker is `@coatcheck/core` (the `coatcheck` bin); secret backends are separate packages installed alongside it and picked by `COATCHECK_PROVIDER` ([Secret providers](#secret-providers)):

```bash
npm install -g @coatcheck/core @coatcheck/provider-env   # env + file providers
npm install -g @coatcheck/provider-aws                   # add for COATCHECK_PROVIDER=aws
COATCHECK_PROVIDER=env COATCHECK_SECRET_EXAMPLE_API_KEY=sk-demo coatcheck
```

Node ≥ 24. Or use the container image, which has core and both providers, for `linux/amd64` and `linux/arm64`:

```bash
docker pull ghcr.io/theleoborges/coatcheck:0.4.0   # also :0.4 and :latest
docker run --rm -p 127.0.0.1:3128:3128 -e COATCHECK_BIND_HOST=0.0.0.0 -e COATCHECK_API_TOKEN=$COATCHECK_API_TOKEN \
  -e COATCHECK_PROVIDER=env -e COATCHECK_SECRET_EXAMPLE_API_KEY=sk-demo ghcr.io/theleoborges/coatcheck:0.4.0
```

Each release tag builds it from the tagged source, with provenance and an SBOM. To build your own: `docker build -t coatcheck .` (the LocalStack demo and the example agents build from the checkout).

## Example agents

[`examples/agents/`](examples/agents) has small Claude-driven agents that run behind coatcheck on an isolated Docker network, without holding a real secret (not even their own Anthropic API key):

- **gh-triage** triages GitHub issues with unmodified `gh` and `curl` through the HTTPS swap.
- **browser-login** logs into a practice site through Browserbase using broker-performed login, with secrets in AWS (SSM and Secrets Manager via an assumed role).
- **ledger-reconcile** reconciles accounts on an HMAC-signed API that runs in the same compose stack (no third-party account beyond the model); the agent writes its own signing client from the recipe coatcheck returns, signing with the ticket.
- **vercel-release-report** runs off AWS, reads Vercel with a bearer ticket and uploads a report to S3 with the unmodified `aws` CLI and a SigV4 [signing ticket](#signed-requests): the IAM key never leaves coatcheck.

Each comes with a red-team task that tells the agent to try to extract the real secret. See [examples/agents/README.md](examples/agents/README.md).

## Setting up the agent container

The agent needs two things: trust in coatcheck's CA, and its traffic routed through coatcheck.

The containers usually share a network but not a filesystem, so fetch the CA over HTTP at startup:

```bash
COATCHECK_URL="${COATCHECK_URL:-http://127.0.0.1:3128}"

# wait for coatcheck
for i in $(seq 1 30); do
  curl -sf "$COATCHECK_URL/_health" >/dev/null && break
  sleep 1
done

curl -sf "$COATCHECK_URL/_ca" -o /tmp/coatcheck-ca.crt
export NODE_EXTRA_CA_CERTS=/tmp/coatcheck-ca.crt                 # Node
cp /tmp/coatcheck-ca.crt /usr/local/share/ca-certificates/coatcheck-ca.crt
update-ca-certificates                                            # curl, git, OpenSSL-based tools
# Python requests/certifi: also set REQUESTS_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt
```

Then route traffic through coatcheck, and exempt coatcheck itself along with anything that should not be intercepted:

```bash
export HTTPS_PROXY=http://127.0.0.1:3128      # with an API token: http://coatcheck:$COATCHECK_API_TOKEN@127.0.0.1:3128
export HTTP_PROXY=$HTTPS_PROXY
export NO_PROXY=localhost,127.0.0.1,169.254.169.254,169.254.170.2   # plus internal services
```

Unless `COATCHECK_CA_DIR` is set and on persistent storage, each coatcheck restart generates a new CA and the agent has to fetch `/_ca` again.

`HTTPS_PROXY` is only a convention: a process that ignores it bypasses coatcheck. Pair coatcheck with egress enforcement (network policy, firewall, security group, or an `internal` Docker network as in the example agents) so the agent can only reach the internet through the proxy. [docs/clients.md](docs/clients.md) covers specific clients (git, Node, Python, Playwright) in more detail.

## Using tickets

coatcheck does a **literal substring replace** of live ticket strings, so the rules follow from where it looks.

**Works.** The ticket appears as plaintext in the `Authorization` header, or inside a Basic credential:

- `Authorization: Bearer cct_…`
- `Authorization: token cct_…` (GitHub style)
- **HTTP Basic auth**: `curl -u user:cct_…`, `https://user:cct_…@host/`, `.netrc`, git credential helpers. coatcheck decodes `Authorization: Basic`, swaps tickets in the user name or password, and re-encodes it.
- `X-API-Key: cct_…`, or any other header, only for secrets that list it in `swap_headers` (see [Swap placement](#swap-placement)).
- `https://api.example.com/v1/x?api_key=cct_…` (query string or path), only for secrets that opt in with `swap_url`.
- In the request body, only for secrets that opt in with `swap_body` (see [Request bodies](#request-bodies)).

(`Proxy-Authorization` is swapped too, on HTTPS only; the plain-HTTP path strips it.)

**Does not work.** The request still goes out, but with the ticket unchanged, and the upstream returns 401/403:

- **Tickets outside `Authorization`** (URL, other headers, body) for secrets that don't opt in there.
- **Ticket in a header name.** Only header values are scanned.
- **Any client that ignores `HTTPS_PROXY`.** Node's built-in `https` module is the common case: it needs an explicit agent such as `https-proxy-agent`, or `NODE_USE_ENV_PROXY=1` on Node ≥ 24. curl, git, Python `requests` and Node `fetch` honour the variable.
- **Client-side signing** the secret isn't configured for: JWT minting, or AWS SigV4 / HMAC on a secret without `signing`. The client computes a signature over the ticket, not the real secret. For AWS SigV4 and HMAC recipes, see [Signed requests](#signed-requests).
- **Expired tickets.** After 15 minutes the ticket is forwarded literally.

If an upstream returns 401 while you are using a ticket, assume the swap did not happen before you assume the stored credential is wrong. coatcheck logs one line per request, with secret names and counts but never values:

| `[swap] result=` | Meaning |
|---|---|
| `hit secrets=…` | Tickets swapped. |
| `denied secrets=…` | A ticket was sent to a host it isn't bound to. The request was not forwarded. |
| `unbound secrets=…` | An unbound ticket was swapped (only with `COATCHECK_ALLOW_UNBOUND_SECRETS=1`). |
| `invalid-value secrets=…` | A value contains a control character and can't go in a header (or a `:`, in a Basic auth user name). The request was not forwarded. |
| `body-skipped secrets=…` | A ticket appeared in a body, but its secret doesn't enable `swap_body`. |
| `placement-skipped secrets=… where=…` | A ticket appeared in the URL (`where=url`) or a header (`where=header:<name>`) its secret isn't swapped in. It was sent as a literal. |
| `body-unscanned` | The body was larger than `COATCHECK_MAX_SWAP_BODY_BYTES` and streamed through unscanned. |
| `miss unswapped_ticket_literals=N` | A `cct_<64 hex>` string reached the upstream intact (unknown or expired ticket). |
| `signed signing=aws-sigv4\|hmac secrets=…` | A request signed with a signing ticket was verified and re-signed with the real key ([Signed requests](#signed-requests)). |
| `signature-mismatch secrets=…` | The agent's signature doesn't match the request coatcheck received. Not forwarded (`403`). |
| `unsignable secrets=… reason=…` | A signing request coatcheck doesn't re-sign (`body-too-large`, `sigv4a`, `streaming-signed-payload`, `malformed-authorization`, `malformed-key-header`). Not forwarded (`403`). |
| `signing-skipped secrets=…` | A signing ticket was used as a literal (`Bearer cct_…`, a presigned URL). It was sent as is and the upstream rejects it. |

`[connect] host=… mode=mitm|passthrough reason=…` lines show which tunnels coatcheck intercepted.

On the plain-HTTP proxy path the same placement rules apply to the path and query, headers and body; tickets are never swapped in the host or userinfo, and `Proxy-Authorization` and hop-by-hop headers are not forwarded.

### Signed requests

Some credentials are never sent: the client signs each request with them. For **AWS SigV4** (agents running outside AWS, S3-compatible stores, keys from a counterparty), mark the secret `"signing": "aws-sigv4"` in the policy (or `"_signing": "aws-sigv4"` in the secret). The secret is the JSON of an access key, snake_case or as `aws configure export-credentials` prints it:

```json
{"access_key_id": "AKIA…", "secret_access_key": "…", "session_token": "(optional)"}
```

The mint returns one credential ticket, and the agent's unmodified SDK or CLI uses it as both halves of the key:

```bash
TOK=$(curl -s "$COATCHECK_URL/_vault/aws-reports" | jq -r .token)   # {"token":"cct_…","signing":"aws-sigv4",…}
AWS_ACCESS_KEY_ID=$TOK AWS_SECRET_ACCESS_KEY=$TOK aws s3 cp report.md s3://reports-bucket/reports/
```

coatcheck checks the host binding, verifies that the agent signed exactly the request it received (with the ticket as the key), applies the ordinary swaps, then re-signs with the real key: the upstream sees the real access key id and a valid signature, and the secret key never leaves coatcheck. A session token in the secret is added and signed. Bodies the signature must hash (every service but S3, which sends a payload-hash header) are buffered up to `COATCHECK_MAX_SWAP_BODY_BYTES`; past it the request is refused (`403 unsignable reason=body-too-large`), never streamed half-signed. S3 uploads stream at any size. `?field=secret_access_key` is refused: there is no literal ticket for the key.

Fails closed: presigned URLs and other query-string auth (the ticket leaves as a literal and AWS rejects it), SigV4a and per-chunk signed streaming payloads (`403 unsignable`). On AWS itself, give the agent a scoped task role instead.

For **HMAC-signed APIs** (exchanges, in-house services), the operator writes the recipe in the policy (or `_signing` in the secret); the agent never chooses what is signed or where real bytes land:

```json
"ledger": {
  "allowed_hosts": ["ledger"],
  "signing": {
    "type": "hmac", "hash": "sha256", "encoding": "base64",
    "key_header": "X-Ledger-Key", "signature_header": "X-Ledger-Signature",
    "message": ["header:X-Ledger-Timestamp", "method", "path_query", "body"]
  }
}
```

The secret is the HMAC key as a plain string, or `{"key_id": "…", "secret": "…"}` plus other fields (`passphrase` gets an ordinary ticket). The mint returns one ticket and the public recipe (`"signing": {"type": "hmac", …}`, never the key or `key_id`). The agent's client uses the ticket as both the API key (sent in `key_header`) and the HMAC secret; coatcheck verifies that HMAC, puts the real `key_id` in `key_header` (or removes it when the secret has none; the agent then sends `X-Coatcheck-Key: cct_…`), and writes the real signature into `signature_header`. `key_header` and `signature_header` can't be `Host`, a framing header or a hop-by-hop / `Proxy-*` header. Recipe keys: `hash` (`sha256` default, `sha384`, `sha512`, `sha1`), `encoding` (`hex` default, `base64`), `key_encoding` of the stored secret (`utf8` default; `base64` or `hex` need `"verify": false`, since an SDK can't decode a ticket), `message` parts concatenated in order (`method`, `path`, `query`, `path_query`, `body`, `header:<name>`, `literal:<text>`), `verify` (default `true`). A recipe that signs the body is buffered and refused past the cap, like SigV4. Not supported yet: a signature in the query string, nested hashes, coatcheck-generated timestamps.

#### What signing covers

It covers most of what agents actually need:

- **AWS SigV4** in the `Authorization` header: every AWS service through the unmodified CLI or SDKs (S3 uploads of any size stream), and S3-compatible stores that issue static key pairs (Cloudflare R2, MinIO, Backblaze B2, DigitalOcean Spaces, Wasabi). This is for agents that run **off AWS** or hold a counterparty's key; on AWS, give the agent a scoped task role instead.
- **HMAC-signed APIs** whose signature goes in a header over parts of the request: the common `timestamp + method + path + body` pattern of exchanges and in-house services, any hash in the SHA family, hex or base64. Extra fields such as an exchange passphrase get ordinary tickets.

It doesn't cover, and fails closed on (the request is refused, or leaves with the worthless ticket and the upstream rejects it):

- **Asymmetric signing:** Ed25519 and ECDSA/RSA keys (Binance Ed25519/RSA keys, Coinbase's CDP JWTs, Oracle OCI). The design keeps these out of scope.
- **Signatures in the query string:** AWS presigned URLs, Binance-style `&signature=`.
- **AWS SigV4a and per-chunk signed streaming payloads** (`STREAMING-AWS4-HMAC-SHA256-PAYLOAD`; the SDK defaults stream unsigned and work).
- **Nested-hash HMAC schemes** (Kraken), and APIs that need coatcheck to generate the timestamp or nonce.
- **Derived credentials** (JWT bearer assertions, OAuth client credentials, GitHub App installation tokens). These belong to the refresh endpoint, not request signing.

The follow-ups are listed in the roadmap. Design: [docs/design/signing-processors.md](docs/design/signing-processors.md).

## Policy file

`COATCHECK_POLICY_FILE` points at a JSON file owned by the operator (see `examples/policy.example.json`):

```json
{
  "secrets": {
    "github-token": { "allowed_hosts": ["api.github.com"] },
    "google-*":     { "allowed_hosts": ["*.googleapis.com", "oauth2.googleapis.com"] }
  },
  "shared": {
    "browserbase-api-key": { "allowed_hosts": ["api.browserbase.com"], "swap_headers": ["X-BB-API-Key"] }
  }
}
```

- `secrets` keys are exact secret names or a prefix ending in `*`. An exact name wins over a prefix, and a longer prefix wins over a shorter one.
- `shared` keys are exact names. Listing a shared secret here is what allowlists it for `/_secret/{name}`.
- `allowed_hosts` entries are exact hostnames, or `*.example.com`, which matches any subdomain but not `example.com` itself. Entries are case-insensitive and IDNs are converted to punycode. IP addresses match exactly. HTTPS is implied; write `http://host` to also allow plaintext HTTP. Ports and paths are not allowed. A bare `*` and wildcards over a single label (`*.com`) are rejected.
- `swap_headers` (optional, a list of header names) and `swap_url` (optional, `true`/`false`) let the secret's tickets be swapped outside `Authorization`; see [Swap placement](#swap-placement).
- `swap_body` (optional, `true`/`false`) turns on request body substitution for the secret; see [Request bodies](#request-bodies).
- `signing` (optional, `"aws-sigv4"` or an HMAC recipe object) makes the secret a signing key: its ticket is used by the client to sign and coatcheck re-signs; see [Signed requests](#signed-requests). A malformed recipe stops startup.
- The schema is strict: unknown keys, empty `allowed_hosts` or `swap_headers` lists, a non-boolean `swap_body` or `swap_url`, and invalid entries all stop startup.

### Allowed hosts

Every ticket is bound to its secret's allowed hosts, taken from two sources:

1. the policy file (`secrets`, or `shared` for `/_secret/*`), owned by the operator;
2. an `_allowed_hosts` array inside a JSON secret, owned by whoever stores the secret. A JSON secret whose only non-underscore key is `value` is a single-value secret, so `{"value":"ghp_…","_allowed_hosts":["api.github.com"]}` works for simple secrets too. Keys starting with `_` are metadata and never offered as fields.

If both are present, the effective list is their **intersection**: a secret can narrow the operator's list but never widen it. If neither is present, the secret is **unbound** and minting a ticket for it fails with `403` (unless `COATCHECK_ALLOW_UNBOUND_SECRETS=1`). An empty intersection is also `403`, and an invalid `_allowed_hosts` is `500`. Mint responses include the effective `allowed_hosts`.

At swap time the host checked is the `CONNECT` target on HTTPS (never the `Host` header or SNI) and the URL host on plain HTTP. Plain HTTP only matches `http://` entries, so a ticket can't be swapped into a request to a loopback or private listener unless that address is listed with `http://`. On a mismatch the request is not forwarded: the client gets `403` with `X-Coatcheck-Denied: host-mismatch` and a JSON body naming the secret and host, and on HTTPS the tunnel is closed. If one ticket in a request is denied, the whole request is.

### Which tunnels are intercepted

In the default `COATCHECK_MITM=bound` mode, coatcheck intercepts a `CONNECT` only when the target is a host in the policy file, an allowed host of a live ticket, or the browser service's API host (with CDP enabled). Everything else is a blind TCP tunnel. `COATCHECK_MITM=always` intercepts every tunnel. Hosts in `COATCHECK_PASSTHROUGH_HOSTS` are never intercepted, for clients that pin certificates. Intercepted tunnels negotiate HTTP/1.1; a WebSocket upgrade becomes a raw pipe after `101 Switching Protocols`.

### Swap placement

By default a ticket is swapped only in the value of an `Authorization` (or `Proxy-Authorization`) header. Anywhere else is opt-in per secret, because the agent chooses where to put its ticket, and many APIs echo parts of the request back: a 404 that quotes the path, an error that quotes a parameter, a query parameter stored in a created object. Wherever the agent can get an allowed host to reflect the real value, the agent can read it.

- `"swap_headers": ["X-Api-Key"]` on the policy entry (or `"_swap_headers"` in a JSON secret) adds header names, case-insensitive. Use it for APIs that take their key in a custom header (Anthropic's `x-api-key`, Browserbase's `X-BB-API-Key`). `Host` is refused. If both sources list headers, the effective list is their intersection.
- `"swap_url": true` (or `"_swap_url"`) also swaps tickets in the request line (path and query), for APIs that take a key as a query parameter. As with `swap_body`, either source enables it and an explicit `false` in either disables it.
- Mint responses include `"swap_headers": […]` and `"swap_url": true` when these are set.
- A ticket somewhere its secret isn't swapped is sent as the `cct_…` literal and logged as `result=placement-skipped`. Host binding still applies first: a ticket bound to another host gets the request refused with `403` wherever it sits.

Placement narrows what the agent can choose; it doesn't make a reflecting host safe. coatcheck does not redact responses on the HTTPS path, so a host that echoes the header it authenticates with (httpbin, postman-echo, debug endpoints) hands the real value back. Only bind secrets to hosts that don't.

### Request bodies

Tickets are swapped in the request **body** only for secrets that opt in, because APIs often echo request bodies back (validation errors, created objects), which would hand the real value to the agent. Opt in with `"swap_body": true` on the secret's policy entry, or `"_swap_body": true` inside a JSON secret. Either one enables it, and an explicit `false` in either disables it. Mint responses then include `"swap_body": true`.

- A body is only held and scanned when a live `swap_body` ticket could be swapped for the request's host. Every other body streams through untouched, as do bodies larger than `COATCHECK_MAX_SWAP_BODY_BYTES` (default 1 MiB): coatcheck forwards what it held and streams the rest unscanned. In an unscanned body a ticket stays a literal, so the request fails closed. (The browser service's API host is the exception when CDP is enabled: its bodies are never streamed unscanned; see [Browser login](#browser-login-cdp).)
- In a scanned body, host binding applies as in the head: a body ticket bound to another host gets the whole request refused with `403`.
- The value is escaped for the body's `Content-Type`: JSON-string-escaped for `application/json` and `*/*+json`, percent-encoded for `application/x-www-form-urlencoded`, raw UTF-8 for anything else (including multipart).
- `Content-Length` is rewritten. A chunked HTTPS body is re-sent as a single chunk; on plain HTTP the body is always sent with `Content-Length`.
- Bodies with a `Content-Encoding` (gzip, br, …) are not scanned.

In a header, a value containing a control character (CR, LF, NUL, …) can't be sent: the request is refused with `403` and `X-Coatcheck-Denied: invalid-value`. In the request line (URL), a value's spaces, control and non-ASCII characters are percent-encoded.

## Browser login (CDP)

This lets an agent log into a website through a remote browser without ever handling the password. Set `COATCHECK_CDP_ENABLED=1`. Browserbase is the only supported browser service today.

coatcheck performs the fill and submit itself over the CDP connection (**broker-performed login**). The agent never has a ticket for the login credential, and never runs its own script while a real value is in the page. This protects against an agent that is actively trying to read the password, not merely against accidental exposure. Design: [docs/design/cdp-broker-login.md](docs/design/cdp-broker-login.md).

1. **Create a session through coatcheck.** The agent calls `POST https://api.browserbase.com/v1/sessions` **through `HTTPS_PROXY`**, authenticating with a `/_secret/browserbase-api-key` ticket. coatcheck rewrites the response's `connectUrl` from the real `wss://…` URL (which carries Browserbase's signing key) to `ws://{COATCHECK_CDP_ADVERTISE_HOST}:8444/cdp/{sid}`. It also removes `signingKey` and `seleniumRemoteUrl`, strips browser-extension parameters from the session-create request (a request body to that host which coatcheck can't inspect — content-encoded, over `COATCHECK_MAX_SWAP_BODY_BYTES`, or not JSON, `multipart/form-data` uploads excepted — is refused with `403` and `X-Coatcheck-Denied: uninspectable-body`), and rewrites or removes the URLs from `GET /v1/sessions/{id}/debug`, so the agent never sees a direct route to the browser. Every response on that host is inspected, on every keep-alive request (compressed bodies are decoded first); one coatcheck can't inspect (an unknown content coding, unusual framing, or a body over `COATCHECK_MAX_SWAP_BODY_BYTES`) is refused with `502` and `X-Coatcheck-Denied: uninspectable-response`, and the tunnel is closed. A `sid` is valid for 10 minutes until a client connects.
2. **Connect and go to the login page.** `chromium.connectOverCDP(connectUrl)`, then `page.goto(…)` and let it load.
3. **Ask coatcheck to log in** instead of filling the form. `sessionId` is the `{sid}`, the last path segment of the rewritten `connectUrl`:

   ```js
   const sid = new URL(connectUrl).pathname.split('/').pop();
   await page.goto('https://www.example.com/login');
   const res = await fetch(`${COATCHECK_URL}/_vault/example-login/login`, {
     method: 'POST',
     headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${COATCHECK_API_TOKEN}` },
     body: JSON.stringify({
       sessionId: sid,
       fields: { username: '#username', password: '#password' },  // secret field -> CSS selector
       submit: 'button[type=submit]',                               // or {"press":"Enter"}
       until: 'navigation',                                         // or {"selector":"…"} / {"urlPrefix":"…"}
     }),
   });
   // 200 {"status":"ok","url":"https://www.example.com/account"}: carry on with the logged-in page
   ```

   The login secret is a multi-value secret, e.g. `{"username":"…","password":"…","_cleartext":["username"]}`, whose allowed hosts include the login page's host. Optional body fields: `page: {"url": "<prefix>"}` picks the tab whose URL starts with that prefix when several are open, and `timeoutMs` (default 15 000, max 60 000) bounds the wait for `until`.

What coatcheck does during the login window:

- **Pauses the agent.** Frames from the agent to the browser are queued and released in order afterwards. Browser events, and responses to the agent's earlier commands, still flow (with redaction).
- **Starts a fresh document.** It removes the new-document scripts the agent registered (`Page.addScriptToEvaluateOnNewDocument`) and reloads, so only the site's own JS runs. Listeners the agent installed earlier die with the old document.
- **Checks the origin.** The page's committed main-frame origin must be one of the login secret's allowed hosts (an `http://` page needs an `http://` entry). On another origin, an unknown origin, or mid-navigation, the login is refused with `403` and nothing is filled.
- **Fills and submits** each field with `Input.insertText`, clicks the submit selector (or presses Enter), and waits for the `until` condition. On timeout the filled fields are emptied before the agent resumes (`409 no-success`, `"cleared": true`).
- **Refuses unsafe states.** Request interception on the page (`Fetch.enable` / `Network.setRequestInterception`) gets `409 interception-active` rather than being silently disabled. A second login on the same connection gets `409 busy`. If there isn't exactly one candidate page (several tabs, including a stray `about:blank`, and no `page.url` to pick one; or none with a loaded URL), the login gets `409 page-ambiguous`.
- **Redacts on the way back.** Every real value from the session is replaced with `[REDACTED:{secret}:{field}]` in browser-to-agent frames, including its percent-encoded, HTML-entity and JSON-escaped forms. A frame that can't be parsed, or still carries a real value after redaction, is dropped.

Login responses:

| Status | Body `status` | Meaning |
|---|---|---|
| `200` | `ok` | Logged in; `url` is the page's URL afterwards. |
| `400` | | Invalid request body (missing `sessionId`, `fields` or `submit`, or a malformed `until`). |
| `413` | | Request body over 64 KiB. |
| `403` | | The page's origin isn't one of the secret's allowed hosts (or is unknown), or the secret has no allowed hosts. Nothing was filled. |
| `404` | `unknown-sid-or-secret`, `selector-not-found` | No live CDP connection for `sessionId`, no such secret, or a field selector matched nothing (`field` names it). Nothing is left filled. |
| `409` | `no-success`, `interception-active`, `busy`, `page-ambiguous` | See above. |
| `501` | | Not a multi-value secret with the requested fields. |
| `502` | `upstream-closed`, `driver-error` | The browser connection closed, or a CDP command failed (including a `submit` selector that matched nothing); filled fields are cleared. |

Client rules:

- Navigate to the login page and let it finish loading before calling `/login`.
- Outside the login window there are no credentials in the browser to protect: the agent may use `page.type()`, `page.evaluate()` and screenshots freely. During login, don't enable request interception on the page.
- Normal HTML login forms work, full-page or SPA (`until` covers both). Only the main document is searched, so a form inside an iframe fails with `404 selector-not-found`: navigate to the identity provider's own page first. 2FA/OTP flows are not handled.
- One CDP connection at a time per coatcheck instance. A second connection is refused with WebSocket close code 1013.

## Secret providers

`COATCHECK_PROVIDER` picks the backend at startup. The Docker image ships all three built-ins.

| Value | Package | Backend |
|---|---|---|
| `env` | `@coatcheck/provider-env` | Environment variables, read once at startup. Read-only. |
| `file` | `@coatcheck/provider-env/file` | A JSON file, `{"secrets":{"name":"value",…},"shared":{…}}`, at `COATCHECK_SECRETS_FILE`. Re-read on every (uncached) lookup; OAuth refresh writes it atomically (temp file, then rename). |
| `aws` | `@coatcheck/provider-aws` | SSM Parameter Store (named secrets) and Secrets Manager (shared keys), optionally through an assumed role. |
| anything else | your module | A module specifier loaded with `import()`. Its default export is `createProvider(ctx): Promise<SecretProvider>` (types in `@coatcheck/core`). |

Values are strings everywhere; a multi-value secret is a JSON-encoded object. coatcheck caches backend reads in memory for `COATCHECK_SECRET_CACHE_TTL_SECONDS` (default 5 minutes), so a rotated secret can take that long to show up.

### env provider names

The `env` provider accepts only secret names made of **lowercase letters, digits and `-`** (`[a-z0-9-]+`), so that a name and its variable map both ways: uppercase the name and replace `-` with `_`.

| Secret name | Variable |
|---|---|
| `github-token` (`/_vault/github-token`) | `COATCHECK_SECRET_GITHUB_TOKEN` (prefix: `COATCHECK_ENV_PREFIX`) |
| `browserbase-api-key` (`/_secret/browserbase-api-key`) | `COATCHECK_SHARED_SECRET_BROWSERBASE_API_KEY` |

Any other name (`GitHub`, `a_b`, `a.b`) gets `400`. `GET /_vault` lists only variables whose names map back. The `file` provider has no such restriction; it uses the core name rules (see [HTTP API](#http-api)).

### AWS provider

| Kind | Where coatcheck reads it | Served by |
|---|---|---|
| Named secret | SSM SecureString at `{COATCHECK_AWS_SSM_PREFIX}{name}` (default `/coatcheck/secrets/{name}`) | `/_vault/{name}` |
| Multi-value secret | Same location, with a JSON object as the value (`{"username":…,"password":…}`) | `/_vault/{name}?field=…` |
| Shared key | Secrets Manager `{COATCHECK_AWS_SHARED_PREFIX}{name}` (default `coatcheck/{name}`), which must also be listed under `shared` in the [policy file](#policy-file) | `/_secret/{name}` |

Both prefixes may contain `{agentId}`, replaced with `COATCHECK_AGENT_ID` (for example `/acme/agents/{agentId}/secrets/`); coatcheck refuses to start if a prefix uses `{agentId}` and it is unset. Region, endpoint (`AWS_REGION`, `AWS_ENDPOINT_URL` for LocalStack) and credentials come from the standard AWS SDK chain; there is no built-in default region.

To add a secret to the LocalStack demo:

```bash
aws --endpoint-url http://localhost:4566 --region us-east-1 ssm put-parameter \
  --type SecureString --name /coatcheck/secrets/github-token --value 'ghp_…'
```

If `COATCHECK_AWS_ROLE_ARN` is set, coatcheck assumes that role through STS (1-hour sessions, renewed every 45 minutes) before reading secrets. The intended deployment gives backend read access to that role only, and gives the agent's own identity none. On ECS a sidecar shares the agent's task role, so the role's trust policy must also require an `sts:ExternalId` that only the coatcheck container holds (`COATCHECK_AWS_EXTERNAL_ID`), or coatcheck must run as a separate task. [docs/deploy/aws-ecs.md](docs/deploy/aws-ecs.md) is the reference deployment.

## HTTP API

The API is served on the proxy port (default `127.0.0.1:3128`).

**Authentication.** With `COATCHECK_API_TOKEN` set, every route except `/_health` and `/_ca` needs `Authorization: Bearer <token>` (otherwise `401`), and the proxy needs `Proxy-Authorization` (otherwise `407`): `Basic` with the token as the password, which is what clients send for `HTTPS_PROXY=http://coatcheck:<token>@host:3128`, or `Bearer <token>`. Without a token, anything that can reach the port can mint tickets, so coatcheck only starts without one on a loopback bind (`127.0.0.0/8`, `::1`, `localhost`). The CDP listener is authenticated by its unguessable session id, not the token.

| Method & path | Response | Notes |
|---|---|---|
| `GET /_health` | `{"status":"ok","tokens_active":N}` | Liveness check. |
| `GET /_ca` | PEM | coatcheck's root CA certificate, for the agent to trust. |
| `GET /_vault` | `{"secrets":["github-token",…]}` | Lists secret names. Values are not read. |
| `GET /_vault/{name}` | `{"token":"cct_…","expires_in":900,"allowed_hosts":[…]}` | For a single-value secret. `403` if the secret has no allowed hosts (see [Allowed hosts](#allowed-hosts)). |
| `GET /_vault/{name}` | `{"type":"multi","fields":[…]}` | For a multi-value (JSON) secret. Request a specific field with `?field=`. |
| `GET /_vault/{name}?field={f}` | `{"token":"cct_…","expires_in":900,"allowed_hosts":[…]}` | Ticket for one field; every field shares the secret's allowed hosts. If the secret's `_cleartext` array lists the field, returns `{"value":"…","cleartext":true}` instead (for non-sensitive values such as usernames, URLs and account IDs). |
| `GET /_vault/{name}?check=1` | `{"exists":true}` | Checks whether a secret exists without reading its value. |

A mint (`/_vault`, `/_secret`) returns `429` while 10,000 live tickets are held; tickets free up as they expire.
| `GET /_secret/{name}` | `{"token":"cct_…","expires_in":900,"allowed_hosts":[…]}` | Shared key from the backend's shared store. `403` unless `{name}` is listed under `shared` in the policy file (with no policy file, every name gets `403`). The ticket is bound to the hosts listed there. |
| `POST /_vault/{name}/login` | `{"status":"ok","url":"https://…"}` | Broker-performed browser login on a live CDP session. Request body and statuses: [Browser login (CDP)](#browser-login-cdp). |
| `POST /_vault/{name}/refresh` | `{"token":"cct_…","expires_in":900,"allowed_hosts":[…]}` | Secret fields: `refresh_token`, `token_url`, `client_id`, `client_secret`. The `token_url` host must be one of the secret's allowed hosts (`403` otherwise), because `client_secret` is sent there. coatcheck posts a `refresh_token` grant, writes `access_token`, `expires_at` and any rotated `refresh_token` back to the backend, and returns a ticket for the new access token, bound to the same hosts. `501` when the backend is read-only. |

Secret names must match `^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$` after URL-decoding; anything else (including `/` or a leading `.`) gets `400` before the backend is consulted.

Errors are JSON `{"error":…}` with status 400, 401, 403, 404, 500, 501, or 502. Login responses carry a `status` field instead (see [Browser login (CDP)](#browser-login-cdp)).

## Configuration

All settings are environment variables. An invalid value stops startup with a message listing every problem.

| Variable | Default | Purpose |
|---|---|---|
| `COATCHECK_PROVIDER` | (required) | Secret backend: `env`, `file`, `aws`, or a module specifier (see [Secret providers](#secret-providers)). |
| `COATCHECK_AGENT_ID` | (unset) | Optional agent identity: used in logs, in `{agentId}` templates, and in the default STS session name. Same character rules as secret names. |
| `COATCHECK_PORT` | `3128` | Port for the proxy and the HTTP API. |
| `COATCHECK_BIND_HOST` | `127.0.0.1` | Bind address for the proxy and the CDP proxy. Any non-loopback address (including `0.0.0.0`) requires `COATCHECK_API_TOKEN`. |
| `COATCHECK_API_TOKEN` | (unset) | Shared secret for the API (`Authorization: Bearer`) and the proxy (`Proxy-Authorization`, Basic with the token as password, or Bearer). At least 32 characters, no whitespace (`openssl rand -hex 32`). Required when the bind host isn't loopback; enforced on every route except `/_health` and `/_ca` whenever set. |
| `COATCHECK_TICKET_TTL_SECONDS` | `900` | Lifetime of tickets from `/_vault` and `/_secret`. |
| `COATCHECK_SECRET_CACHE_TTL_SECONDS` | `300` | How long backend reads are cached; `0` disables the cache. |
| `COATCHECK_POLICY_FILE` | (unset) | JSON [policy file](#policy-file): allowed hosts per secret and the shared-secret allowlist. Read once at startup; an invalid file stops startup. |
| `COATCHECK_MITM` | `bound` | `bound`: intercept a `CONNECT` only when the target is a host in the policy file, an allowed host of a live ticket (any host while an unbound ticket is live), or the browser adapter's API host with CDP enabled; tunnel everything else untouched. `always`: intercept every `CONNECT`. |
| `COATCHECK_PASSTHROUGH_HOSTS` | (empty) | Comma-separated hosts that are never intercepted, in either mode, for clients that pin certificates. Same syntax as `allowed_hosts` (exact, `*.example.com`, IP), without `http://`. A ticket sent to one of these hosts reaches it unswapped. |
| `COATCHECK_MAX_SWAP_BODY_BYTES` | `1048576` | Largest request body held in memory for `swap_body` swapping (1024 to 67108864). Larger bodies stream through unscanned. See [Request bodies](#request-bodies). With CDP enabled it also caps request and response bodies on the browser service's API host, which are refused past it. |
| `COATCHECK_ALLOW_UNBOUND_SECRETS` | `0` | Set to `1` to mint tickets for secrets with no allowed hosts instead of refusing them with `403`. Such tickets are swapped on requests to **any** host; coatcheck warns at startup and logs `result=unbound` on every swap. |
| `COATCHECK_MISSING_SECRET_URL` | (unset) | Returned as `vault_url` in 404s, e.g. a dashboard where users add secrets. Omitted when unset. |
| `COATCHECK_CA_SUBJECT` | `CN=coatcheck CA, O=coatcheck` | Subject of a newly generated CA. |
| `COATCHECK_CA_DIR` | (unset) | Where to persist the CA key and cert (`ca.key`, `ca.crt`). If unset, coatcheck generates an in-memory CA on every start. If an existing ECDSA P-256 CA is found there, coatcheck reuses it; any other key type (for example an RSA CA from an older version) fails startup until the files are deleted. Per-host certificates are never written to disk. |
| `COATCHECK_CDP_ENABLED` | `0` | Set to `1` to run the CDP proxy and rewrite browser-service `connectUrl`s. |
| `COATCHECK_CDP_PORT` | `8444` | CDP WebSocket proxy port. |
| `COATCHECK_BROWSER_ADAPTERS` | `browserbase` | Comma-separated built-in browser adapters: which browser-service API responses get their CDP URLs rewritten. Custom adapters go through the library API (`startCoatcheck({ adapters })`). |
| `COATCHECK_CDP_ADVERTISE_HOST` | `127.0.0.1` | Host written into the rewritten `connectUrl`. Override it when the Playwright client is in a different container. |
| `COATCHECK_ENV_PREFIX` | `COATCHECK_SECRET_` | Variable prefix for named secrets (`env` provider). Shared secrets always use `COATCHECK_SHARED_SECRET_`. |
| `COATCHECK_SECRETS_FILE` | (required for `file`) | Path of the JSON secrets file (`file` provider). |
| `COATCHECK_AWS_SSM_PREFIX` | `/coatcheck/secrets/` | SSM path prefix for named secrets (`aws` provider). Must start and end with `/`; may contain `{agentId}`. |
| `COATCHECK_AWS_SHARED_PREFIX` | `coatcheck/` | Secrets Manager name prefix for shared keys (`aws` provider); may contain `{agentId}`. |
| `COATCHECK_AWS_ROLE_ARN` | (unset) | IAM role to assume before reading secrets. If unset, the default AWS credential chain is used. |
| `COATCHECK_AWS_EXTERNAL_ID` | (unset) | `sts:ExternalId` sent when assuming `COATCHECK_AWS_ROLE_ARN`. Inject it into the coatcheck container only (ECS container `secrets`), so an agent sharing the task role can't assume the broker role. coatcheck warns at startup when a role ARN is set without it, and refuses to start when it is set without a role ARN. See [docs/deploy/aws-ecs.md](docs/deploy/aws-ecs.md). |
| `COATCHECK_AWS_ROLE_SESSION_NAME` | `coatcheck-{agentId}`, or `coatcheck` | STS session name when assuming the role. |

Earlier variable names (`AGENT_LABEL`, `PROXY_PORT`, `PROXY_BIND_HOST`, `CA_DIR`, `PROXY_ROLE_ARN`, `CDP_PROXY_*`) are rejected at startup with a message naming the replacement. Certificates are generated in-process (ECDSA P-256); coatcheck needs no `openssl` binary.

## Status & known limitations

coatcheck is **pre-1.0**. The HTTP API, ticket format (`cct_…`), and configuration may change. Known gaps, roughly in priority order (the full list with severities is in [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md)):

- **Responses are not redacted on the HTTPS path.** If an allowed host reflects a credential back (an echo service, a debug endpoint, an error that quotes the key), the agent reads the real value. Tickets are swapped only in `Authorization` unless the operator opts a secret in to more places ([Swap placement](#swap-placement)), so the agent can't choose a reflecting spot on its own; but bind secrets only to hosts that don't echo what they authenticate with.
- **Host binding stops redirection, not misuse.** A ticket only works on its secret's allowed hosts, so an agent can't send it to an attacker's server. It can still use the credential maliciously against an allowed host, and an operator who sets `COATCHECK_ALLOW_UNBOUND_SECRETS=1` gives up the protection for unbound secrets.
- **`HTTPS_PROXY` is advisory.** A process that ignores it bypasses coatcheck, which means no substitution and also no protection. Pair coatcheck with egress enforcement so the agent can reach the internet only through the proxy.
- **Request bodies are substituted only on opt-in** (`swap_body`, see [Request bodies](#request-bodies)), and never when content-encoded. On the MITM path, request framing is strict: ambiguous framing (for example both `Content-Length` and `Transfer-Encoding`, or a coding other than `chunked`) gets `400` with `X-Coatcheck-Denied: bad-framing` and the tunnel is closed. A header section over 64 KiB gets `431`. Request trailers pass through unswapped.
- **Interception follows the bindings, not the request.** In the default `bound` mode, a keep-alive tunnel opened to a host before any ticket for it existed (a host bound only by a secret's `_allowed_hosts`) stays a raw tunnel, so a ticket later sent down it reaches the upstream unswapped. Clients that pin certificates fail on intercepted hosts unless listed in `COATCHECK_PASSTHROUGH_HOSTS`. Intercepted tunnels speak HTTP/1.1 only (ALPN), and WebSocket frames after an upgrade are not inspected.
- **Without `COATCHECK_API_TOKEN`, any local process can mint tickets.** That is the intended sidecar setup (loopback, shared network namespace), and coatcheck refuses to start off loopback without a token. The token is one shared secret: there are no per-client identities or scopes.
- **Signing covers SigV4 and header HMAC recipes, not every scheme.** Asymmetric keys (Ed25519, ECDSA/RSA), query-string signatures (presigned URLs), SigV4a and nested-hash recipes fail closed; see [What signing covers](#what-signing-covers).
- **Three built-in secret backends** (environment variables, a JSON file, AWS). HashiCorp Vault and Vercel are planned; anything else needs a custom provider module.
- **Browserbase is the only built-in browser adapter.** Other services need a custom adapter (`BrowserAdapter` in `@coatcheck/core`).
- **The site and the browser vendor see the password.** coatcheck performs the login against the real site, so the site necessarily receives the credential; this is the accepted upstream-trust boundary. Client-side-hashing and challenge logins work because the page's own JS sees the raw value.
- **CDP limits:** login forms inside iframes aren't found (navigate to the IdP's own page first), one CDP session at a time, and no 2FA/OTP. Binary and screenshot frames are not inspected; a screenshot the agent takes outside the login window can still capture a rendered value if the agent put one there by other means.

## How this differs from superfly/tokenizer

[superfly/tokenizer](https://github.com/superfly/tokenizer) solves the same core problem and is a well-designed piece of work. If its model fits your setup, use it. It is a stateless Go proxy. Secrets are sealed (encrypted to the proxy's key) and travel with the request, so the proxy keeps no secret store. Each secret carries its own `allowed_hosts`, so it cannot be redirected elsewhere. Its processors go beyond substitution: HMAC and AWS SigV4 signing, JWT, and OAuth client credentials.

The two differ in where they put the work. tokenizer asks the client to cooperate: it sends plain HTTP to the proxy with a `Proxy-Tokenizer` header carrying the sealed secret, and for HMAC it passes the message to sign. coatcheck's rule is **don't make the agent change its tools**. An agent's tools are whatever it finds or writes in the moment, and every adaptation they need is one more thing a model gets wrong or a prompt injection can route around. So coatcheck adapts on the wire instead:

- **Unmodified tools.** coatcheck is a standard `HTTPS_PROXY` with TLS interception. curl, git, the AWS CLI, SDKs, and code an LLM writes on the fly work if they honour the proxy variable and trust the CA.
- **Signing without client changes.** The agent's unmodified SDK signs with the ticket as if it were the key. coatcheck verifies that signature over the request it received, then re-signs with the real key (AWS SigV4, operator-declared HMAC recipes). The client never sends coatcheck a message to sign, and the operator, not the agent, decides what is signed and where.
- **Secrets by name from a store.** The agent asks for `github-token` and gets a ticket. It never holds secret material, sealed or otherwise. The cost is a stateful component and a backend dependency.
- **Browser logins.** coatcheck logs an agent into a website through a remote browser by performing the fill and submit itself over CDP, with the agent's frames held and inbound redaction as a backstop. tokenizer does not cover browsers.

Where tokenizer is ahead: JWT and OAuth client-credentials processors, and a stateless deployment with no secret store to run. Both bind secrets to hosts; coatcheck's binding comes from an operator policy file and the stored secret rather than from the sealed secret.

## Development

Requires Node ≥ 24 (CI runs 24 and 26). npm workspaces, one package per directory:

| Package | Contents |
|---|---|
| `packages/core` (`@coatcheck/core`) | Proxy, MITM, CA, tickets, vault API, CDP proxy, config, provider interface; the `coatcheck` bin and `startCoatcheck({ config, provider })` for embedding |
| `packages/provider-aws` (`@coatcheck/provider-aws`) | The `aws` provider; the only package that depends on the AWS SDK |
| `packages/provider-env` (`@coatcheck/provider-env`) | The `env` provider and, at `@coatcheck/provider-env/file`, the `file` provider |

```bash
npm install
npx playwright install chromium                                    # once, for the CDP e2e test
npm run lint && npm run type-check && npm test && npm run build   # tsc -b -> packages/*/dist
COATCHECK_PROVIDER=env COATCHECK_SECRET_DEMO=x npm run dev        # runs the TypeScript source, no build
COATCHECK_PROVIDER=aws AWS_REGION=us-east-1 AWS_ENDPOINT_URL=http://localhost:4566 npm run dev
```

## Docs

- [docs/clients.md](docs/clients.md): integrating agent tooling (CA trust, which clients honour the proxy, git, Node, Playwright)
- [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md): attacker model, deployment requirements, known gaps
- [docs/deploy/aws-ecs.md](docs/deploy/aws-ecs.md): reference AWS ECS deployment
- [examples/agents/README.md](examples/agents/README.md): example agents and red-team tasks
- [docs/design/cdp-broker-login.md](docs/design/cdp-broker-login.md): how broker-performed browser login works
- [docs/design/cdp-injection.md](docs/design/cdp-injection.md): the CDP proxy, `connectUrl` rewrite and inbound redaction (the earlier ticket-based login it describes was replaced by broker login)
- [docs/design/v1-decisions.md](docs/design/v1-decisions.md): v1 design decisions and rejected alternatives
- [docs/ROADMAP.md](docs/ROADMAP.md): what's next

## License

[Apache-2.0](LICENSE)
