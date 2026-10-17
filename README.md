# coatcheck

A credential broker sidecar for AI agents. The agent never holds a real secret: it asks coatcheck for one by name, gets back a short-lived ticket, and coatcheck swaps the ticket for the real value on the wire, in outbound HTTPS requests and in browser (CDP) sessions.

It works like a coat check. You hand over the coat and get a ticket. The ticket gets you the coat back at that counter. Anywhere else it is a worthless scrap of paper. If a prompt injection gets the agent to print, log, or exfiltrate its credentials, what leaks is a ticket that expires in minutes.

> **Status: pre-1.0.** coatcheck runs in production as a sidecar, but it has real gaps. Read [Status & known limitations](#status--known-limitations) before you depend on it.

## How it works

```
 agent container                         coatcheck sidecar                       upstream
┌──────────────────────┐               ┌──────────────────────────┐
│                      │ GET /_vault/  │ vault API                │  fetch by name
│ get ticket ──────────┼──────────────>│  issue cct_… (15 min) ───┼──────────> secret backend
│   <── cct_9f2c…      │               │                          │            (AWS SSM / SM)
│                      │               │                          │
│ curl -H "Authorization: Bearer cct_9f2c…" https://api.github.com/…
│   HTTPS_PROXY ───────┼── CONNECT ───>│ MITM TLS (own CA)        │
│                      │               │ cct_9f2c… -> real value ─┼──────────> api.github.com
│                      │               │ in headers / URL         │
│                      │               │                          │
│ playwright           │  ws://…/cdp/  │ CDP WebSocket proxy      │
│   page.fill(cct_…) ──┼──────────────>│ swap in Input.insertText,├──────────> browser service
│                      │<──────────────┤ redact echoed secrets    │            (Browserbase)
└──────────────────────┘               └──────────────────────────┘
```

1. **Ticket issuance.** The agent calls `GET http://127.0.0.1:3128/_vault/{name}`. coatcheck fetches the secret from its backend and returns `cct_` plus 64 hex characters. Tickets live only in coatcheck's memory, with a 15-minute TTL. Each ticket is bound to the secret's allowed hosts (see [Policy file](#policy-file)); a secret with no allowed hosts gets no ticket.
2. **HTTPS substitution.** The agent container sets `HTTPS_PROXY` to coatcheck and trusts coatcheck's CA. coatcheck intercepts `CONNECT` tunnels to hosts a ticket could be used on (hosts in the policy file, hosts of a live ticket, and the browser service's API host) with a per-host certificate it signs itself, negotiating HTTP/1.1. It replaces every active ticket it finds in the request line and headers, then re-encrypts to the real host, with normal certificate verification. A ticket is only replaced when the `CONNECT` target is one of its allowed hosts; otherwise the request is refused with `403` and never forwarded. This works with unmodified tools such as curl, git over HTTPS (with a bearer header), Python `requests`, and Node `fetch`, because they only need proxy support and a trusted CA. Plain-HTTP proxy requests get the same treatment. Every other `CONNECT` is a blind TCP tunnel (see `COATCHECK_MITM`). WebSocket upgrades work through an intercepted tunnel: after `101 Switching Protocols` it becomes a raw pipe.
3. **Browser (CDP) injection.** With the CDP proxy enabled, coatcheck rewrites the `connectUrl` in the browser service's session-create response so it points at a local WebSocket proxy. The agent's Playwright client connects there. On the way out, coatcheck swaps session-scoped tickets inside `Input.insertText`, `Runtime.evaluate`, and `Runtime.callFunctionOn`. On the way back, it redacts any real value the page echoes. Keystroke-by-keystroke entry fails closed (details [below](#browser--cdp-credential-injection)).
4. **OAuth refresh.** `POST /_vault/{name}/refresh` runs the refresh-token exchange inside coatcheck. It writes the new tokens back to the backend and returns only a ticket for the new access token.

## Quickstart

> The only secret backend right now is **AWS**: SSM Parameter Store for named secrets and Secrets Manager for shared keys. For local use, the example points coatcheck at [LocalStack](https://github.com/localstack/localstack). An env/file provider is planned so you can run without AWS.

```bash
docker compose -f docker-compose.example.yml up --build
```

This starts coatcheck on `localhost:3128` and LocalStack. It also seeds two demo secrets from `examples/localstack-init.sh`: `example-api-key` (single value) and `example-login` (a username/password pair).

```bash
# 1. Get a ticket
curl -s localhost:3128/_vault/example-api-key
# {"token":"cct_3b1e…","expires_in":900,"allowed_hosts":["httpbin.org"]}

# 2. Fetch coatcheck's CA
curl -s localhost:3128/_ca > /tmp/coatcheck-ca.crt

# 3. Use the ticket as if it were the real key
curl -s --proxy http://localhost:3128 --cacert /tmp/coatcheck-ca.crt \
  -H "Authorization: Bearer cct_3b1e…" https://httpbin.org/headers
```

httpbin echoes the request headers, so step 3 shows the **real** value arriving upstream. The demo policy (`examples/policy.example.json`) binds `example-api-key` to `httpbin.org`, so the same ticket sent anywhere else is refused:

```bash
curl -s --proxy http://localhost:3128 --cacert /tmp/coatcheck-ca.crt \
  -H "Authorization: Bearer cct_3b1e…" https://example.org/
# HTTP 403, X-Coatcheck-Denied: host-mismatch
# {"error":"Secret 'example-api-key' is not allowed for host 'example.org'",…}
```

To add your own secret to LocalStack:

```bash
aws --endpoint-url http://localhost:4566 --region us-east-1 ssm put-parameter \
  --type SecureString --name /coatcheck/secrets/github-token --value 'ghp_…'
```

### Secret backend layout (AWS)

| Kind | Where coatcheck reads it | Served by |
|---|---|---|
| Named secret | SSM SecureString at `{COATCHECK_AWS_SSM_PREFIX}{name}` (default `/coatcheck/secrets/{name}`) | `/_vault/{name}` |
| Multi-value secret | Same location, with a JSON object as the value (`{"username":…,"password":…}`) | `/_vault/{name}?field=…` |
| Shared key | Secrets Manager `{COATCHECK_AWS_SHARED_PREFIX}{name}` (default `coatcheck/{name}`), which must also be listed under `shared` in the [policy file](#policy-file) | `/_secret/{name}` |

Both prefixes may contain `{agentId}`, replaced with `COATCHECK_AGENT_ID` (for example `/acme/agents/{agentId}/secrets/`); coatcheck refuses to start if a prefix uses `{agentId}` and it is unset. coatcheck caches backend reads in memory for `COATCHECK_SECRET_CACHE_TTL_SECONDS` (default 5 minutes), so a rotated secret can take that long to show up.

If `COATCHECK_AWS_ROLE_ARN` is set, coatcheck assumes that role through STS (1-hour sessions, renewed every 45 minutes) before reading secrets. The intended deployment gives backend read access to that role only, and gives the agent's own identity none.

## HTTP API

The API is served on the proxy port (default `127.0.0.1:3128`). **It has no authentication.** Anything that can reach the port can mint tickets, so keep it on loopback inside the agent's network namespace.

| Method & path | Response | Notes |
|---|---|---|
| `GET /_health` | `{"status":"ok","tokens_active":N}` | Liveness check. |
| `GET /_ca` | PEM | coatcheck's root CA certificate, for the agent to trust. |
| `GET /_vault` | `{"secrets":["github-token",…]}` | Lists secret names. Values are not decrypted. |
| `GET /_vault/{name}` | `{"token":"cct_…","expires_in":900,"allowed_hosts":[…]}` | For a single-value secret. `403` if the secret has no allowed hosts (see [Policy file](#policy-file)). |
| `GET /_vault/{name}` | `{"type":"multi","fields":[…]}` | For a multi-value (JSON) secret. Request a specific field with `?field=`. |
| `GET /_vault/{name}?field={f}` | `{"token":"cct_…","expires_in":900,"allowed_hosts":[…]}` | Ticket for one field; every field shares the secret's allowed hosts. If the secret's `_cleartext` array lists the field, returns `{"value":"…","cleartext":true}` instead (for non-sensitive values such as URLs and account IDs). |
| `GET /_vault/{name}?check=1` | `{"exists":true}` | Checks whether a secret exists without decrypting it. |
| `GET /_secret/{name}` | `{"token":"cct_…","expires_in":900,"allowed_hosts":[…]}` | Shared key from the backend's shared store. Returns 403 unless `{name}` is listed under `shared` in the policy file (with no policy file, every name gets 403). The ticket is bound to the hosts listed there. |
| `POST /_vault/mint-tokens` | `{"username_token":"cct_…","password_token":"cct_…","expires_in":600,"allowed_hosts":[…]}` | Body: `{"secretName":"example-login","sessionId":"<cdp sid>","expires_in"?:N}`. The secret must be a multi-value secret with `username` and `password`. Tickets are bound to one CDP session (see below). Default TTL is 600 s, capped at 1800 s. The login secret must have allowed hosts; they are recorded on the tickets, but the CDP path does not check them against the page yet (roadmap item 15). |
| `POST /_vault/{name}/refresh` | `{"token":"cct_…","expires_in":900,"allowed_hosts":[…]}` | Secret fields: `refresh_token`, `token_url`, `client_id`, `client_secret`. The `token_url` host must be one of the secret's allowed hosts (`403` otherwise), because `client_secret` is sent there. coatcheck posts a `refresh_token` grant, writes `access_token`, `expires_at`, and any rotated `refresh_token` back to the backend, and returns a ticket for the new access token, bound to the same hosts. |

Secret names must match `^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$` after URL-decoding; anything else (including `/` or a leading `.`) gets `400` before the backend is consulted. `refresh` returns `501` when the configured backend is read-only.

Errors are JSON `{"error":…}` with status 400, 403, 404, 500, 501, or 502.

## Configuration

| Variable | Default | Purpose |
|---|---|---|
| `COATCHECK_PROVIDER` | (required) | Secret backend. Currently `aws`. |
| `COATCHECK_AGENT_ID` | (unset) | Optional agent identity: used in logs, in `{agentId}` templates, and in the default STS session name. Same character rules as secret names. |
| `COATCHECK_PORT` | `3128` | Port for the proxy and the HTTP API. |
| `COATCHECK_BIND_HOST` | `127.0.0.1` | Bind address for the proxy and the CDP proxy. Use `0.0.0.0` only for local docker-compose. |
| `COATCHECK_TICKET_TTL_SECONDS` | `900` | Lifetime of tickets from `/_vault` and `/_secret`. |
| `COATCHECK_SECRET_CACHE_TTL_SECONDS` | `300` | How long backend reads are cached; `0` disables the cache. |
| `COATCHECK_POLICY_FILE` | (unset) | JSON [policy file](#policy-file): allowed hosts per secret and the shared-secret allowlist. Read once at startup; an invalid file stops startup. |
| `COATCHECK_MITM` | `bound` | `bound`: intercept a `CONNECT` only when the target is a host in the policy file, an allowed host of a live ticket (any host while an unbound ticket is live), or the browser adapter's API host with CDP enabled; tunnel everything else untouched. `always`: intercept every `CONNECT`. |
| `COATCHECK_PASSTHROUGH_HOSTS` | (empty) | Comma-separated hosts that are never intercepted, in either mode, for clients that pin certificates. Same syntax as `allowed_hosts` (exact, `*.example.com`, IP), without `http://`. A ticket sent to one of these hosts reaches it unswapped. |
| `COATCHECK_ALLOW_UNBOUND_SECRETS` | `0` | Set to `1` to mint tickets for secrets with no allowed hosts instead of refusing them with `403`. Such tickets are swapped on requests to **any** host; coatcheck warns at startup and logs `result=unbound` on every swap. |
| `COATCHECK_MISSING_SECRET_URL` | (unset) | Returned as `vault_url` in 404s, e.g. a dashboard where users add secrets. Omitted when unset. |
| `COATCHECK_CA_SUBJECT` | `CN=coatcheck CA, O=coatcheck` | Subject of a newly generated CA. |
| `COATCHECK_CA_DIR` | (unset) | Where to persist the CA key and cert (`ca.key`, `ca.crt`). If unset, coatcheck generates an in-memory CA on every start. If an existing ECDSA P-256 CA is found there, coatcheck reuses it; any other key type (for example an RSA CA from an older version) fails startup until the files are deleted. Per-host certificates are never written to disk. |
| `COATCHECK_CDP_ENABLED` | `0` | Set to `1` to run the CDP proxy and rewrite browser-service `connectUrl`s. |
| `COATCHECK_CDP_PORT` | `8444` | CDP WebSocket proxy port. |
| `COATCHECK_CDP_ADVERTISE_HOST` | `127.0.0.1` | Host written into the rewritten `connectUrl`. Override it when the Playwright client is in a different container. |
| `COATCHECK_AWS_SSM_PREFIX` | `/coatcheck/secrets/` | SSM path prefix for named secrets (`aws` provider). Must start and end with `/`; may contain `{agentId}`. |
| `COATCHECK_AWS_SHARED_PREFIX` | `coatcheck/` | Secrets Manager name prefix for shared keys (`aws` provider); may contain `{agentId}`. |
| `COATCHECK_AWS_ROLE_ARN` | (unset) | IAM role to assume before reading secrets. If unset, the default AWS credential chain is used. |
| `COATCHECK_AWS_ROLE_SESSION_NAME` | `coatcheck-{agentId}`, or `coatcheck` | STS session name when assuming the role. |

Region, endpoint (`AWS_REGION`, `AWS_ENDPOINT_URL` for LocalStack) and credentials come from the standard AWS SDK chain; there is no built-in default region.

Earlier variable names (`AGENT_LABEL`, `PROXY_PORT`, `PROXY_BIND_HOST`, `CA_DIR`, `PROXY_ROLE_ARN`, `CDP_PROXY_*`) are rejected at startup with a message naming the replacement. Certificates are generated in-process (ECDSA P-256); coatcheck needs no `openssl` binary.

## Policy file

`COATCHECK_POLICY_FILE` points at a JSON file owned by the operator (see `examples/policy.example.json`):

```json
{
  "secrets": {
    "github-token": { "allowed_hosts": ["api.github.com"] },
    "google-*":     { "allowed_hosts": ["*.googleapis.com", "oauth2.googleapis.com"] }
  },
  "shared": {
    "browserbase-api-key": { "allowed_hosts": ["api.browserbase.com"] }
  }
}
```

- `secrets` keys are exact secret names or a prefix ending in `*`. An exact name wins over a prefix, and a longer prefix wins over a shorter one.
- `shared` keys are exact names. Listing a shared secret here is what allowlists it for `/_secret/{name}`.
- `allowed_hosts` entries are exact hostnames, or `*.example.com`, which matches any subdomain but not `example.com` itself. Entries are case-insensitive and IDNs are converted to punycode. IP addresses match exactly. HTTPS is implied; write `http://host` to also allow plaintext HTTP. Ports and paths are not allowed. A bare `*` and wildcards over a single label (`*.com`) are rejected.
- The schema is strict: unknown keys, empty `allowed_hosts` lists and invalid entries all stop startup.

### Allowed hosts

Every ticket is bound to its secret's allowed hosts, taken from two sources:

1. the policy file (`secrets`, or `shared` for `/_secret/*`), owned by the operator;
2. an `_allowed_hosts` array inside a JSON secret, owned by whoever stores the secret. A JSON secret whose only non-underscore key is `value` is a single-value secret, so `{"value":"ghp_…","_allowed_hosts":["api.github.com"]}` works for simple secrets too. Keys starting with `_` are metadata and never offered as fields.

If both are present, the effective list is their **intersection**: a secret can narrow the operator's list but never widen it. If neither is present, the secret is **unbound** and minting a ticket for it fails with `403` (unless `COATCHECK_ALLOW_UNBOUND_SECRETS=1`). An empty intersection is also `403`, and an invalid `_allowed_hosts` is `500`. Mint responses include the effective `allowed_hosts`.

At swap time the host checked is the `CONNECT` target on HTTPS (never the `Host` header or SNI) and the URL host on plain HTTP. Plain HTTP only matches `http://` entries, so a ticket can't be swapped into a request to a loopback or private listener unless that address is listed with `http://`. On a mismatch the request is not forwarded: the client gets `403` with `X-Coatcheck-Denied: host-mismatch` and a JSON body naming the secret and host, and on HTTPS the tunnel is closed. If one ticket in a request is denied, the whole request is.

## Trusting the CA in the agent container

The agent must trust coatcheck's CA, or MITM'd connections fail TLS verification. The containers usually share a network but not a filesystem, so fetch the certificate over HTTP at startup:

```bash
PROXY_BASE="${HTTP_PROXY:-http://127.0.0.1:3128}"

# wait for coatcheck
for i in $(seq 1 30); do
  curl -sf "$PROXY_BASE/_health" >/dev/null && break
  sleep 1
done

curl -sf "$PROXY_BASE/_ca" -o /tmp/coatcheck-ca.crt
export NODE_EXTRA_CA_CERTS=/tmp/coatcheck-ca.crt                 # Node
cp /tmp/coatcheck-ca.crt /usr/local/share/ca-certificates/coatcheck-ca.crt
update-ca-certificates                                            # curl, git, OpenSSL-based tools
# Python requests/certifi: also set REQUESTS_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt
```

Then route traffic through coatcheck and exempt coatcheck itself, along with anything that should not be intercepted:

```bash
export HTTPS_PROXY=http://127.0.0.1:3128
export HTTP_PROXY=http://127.0.0.1:3128
export NO_PROXY=localhost,127.0.0.1,169.254.169.254,169.254.170.2   # plus internal services
```

Unless `COATCHECK_CA_DIR` is set and on persistent storage, each coatcheck restart generates a new CA, and the agent has to fetch `/_ca` again.

## Using tickets

coatcheck does a **literal substring replace** of active ticket strings, so the rules follow from where it looks.

**Works.** The ticket appears as plaintext in the request line or a header:

- `Authorization: Bearer cct_…`
- `Authorization: token cct_…` (GitHub style)
- `X-API-Key: cct_…`, or any custom header
- `https://api.example.com/v1/x?api_key=cct_…` (query string)

**Does not work.** The request still goes out, but with the ticket unchanged, and the upstream returns 401/403:

- **HTTP Basic auth**, e.g. `curl -u user:cct_…`, `https://user:cct_…@host/` URLs, `.netrc`, and git credential helpers. Base64 encoding hides the ticket from the substring scan. For git, send an `Authorization` header instead (`git -c http.extraHeader="Authorization: Bearer cct_…"`).
- **Tickets in request bodies** (JSON, form-encoded, multipart). Bodies are forwarded untouched.
- **Any client that ignores `HTTPS_PROXY`.** Node's built-in `https` module is the common case: it needs an explicit agent such as `https-proxy-agent`. curl, git, Python `requests`, and undici `fetch` honor the variable.
- **Client-side signing**, such as AWS SigV4, HMAC request signatures, or JWT minting. The client computes a signature over the ticket, not the real secret.
- **Expired tickets.** After 15 minutes the ticket is forwarded literally.

If an upstream returns 401 while you are using a ticket, assume the swap did not happen before you assume the stored credential is wrong. coatcheck logs one line per request with no values: `[swap] … result=hit secrets=…` on success, `result=denied secrets=…` when a ticket was sent to a host it isn't bound to (the request was not forwarded), `result=unbound` when an unbound ticket was swapped, or `result=miss unswapped_ticket_literals=N` when a `cct_<64 hex>` string reaches the upstream intact.

On the plain-HTTP path tickets are swapped only in the path, query and headers, never in the host or userinfo, and `Proxy-Authorization` and hop-by-hop headers are not forwarded.

## Browser / CDP credential injection

This lets an agent log into a website through a remote browser without the password entering its context. Set `COATCHECK_CDP_ENABLED=1`. Browserbase is the only supported browser service today.

1. The agent creates a session with `POST https://api.browserbase.com/v1/sessions` **through `HTTPS_PROXY`**, authenticating with a `/_secret/browserbase-api-key` ticket. coatcheck rewrites the response's `connectUrl` from the real `wss://…` URL, which carries Browserbase's signing key, to `ws://{COATCHECK_CDP_ADVERTISE_HOST}:8444/cdp/{sid}`. The agent never sees the real URL. A `sid` is valid for 10 minutes until a client connects.
2. The agent mints session-bound tickets with `POST /_vault/mint-tokens {"secretName":"example-login","sessionId":"{sid}"}`.
3. The agent connects (`chromium.connectOverCDP(connectUrl)`) and fills the form:

   ```js
   await page.fill('input[name=email]', usernameToken);
   await page.fill('input[name=password]', passwordToken);
   await page.click('button[type=submit]');
   ```

What the CDP proxy does:

- **Outbound.** Swaps session-bound tickets in `Input.insertText.text` (what `page.fill()` sends), `Runtime.evaluate.expression`, and `Runtime.callFunctionOn` (`functionDeclaration` and every `arguments[].value`). Other methods are forwarded unchanged, and a ticket found in them is logged.
- **Session scoping.** Session-bound tickets substitute only on their own CDP session's frames, never on the HTTPS path. They are revoked when the WebSocket closes.
- **Inbound.** Every real value from the session is replaced with `[REDACTED:{secret}:{field}]`. If a frame cannot be parsed, or still contains a real value after redaction, it is dropped.
- **Keystroke fail-closed.** `page.type()` sends one `Input.dispatchKeyEvent` per character, so the ticket never appears whole in one frame and cannot be swapped. coatcheck tracks the typed characters. When they spell an active ticket, it drops the frame and returns a CDP error telling the client to use `page.fill()`. The preceding keystrokes have already been forwarded, so the field holds a partial ticket string, never the secret.

Client rules:

- Use `page.fill()`, never `page.type()`, for credential fields.
- Don't take screenshots during login, and don't toggle "show password". Pixels are not redacted, so a rendered secret ends up in the agent's context.
- Don't read a password field's `.value` back. The frame is dropped, so the read fails.
- Normal HTML login forms work. 2FA/OTP flows are not handled.
- One CDP connection at a time per coatcheck instance. A second connection is refused with WebSocket close code 1013.

## Status & known limitations

coatcheck is **pre-1.0**. The HTTP API, ticket format (`cct_…`), and configuration may change. Known gaps, roughly in priority order:

- **Host binding stops redirection, not misuse.** A ticket only works on its secret's allowed hosts, so an agent can't send it to an attacker's server. It can still use the credential maliciously against an allowed host, and an operator who sets `COATCHECK_ALLOW_UNBOUND_SECRETS=1` gives up the protection for unbound secrets.
- **Request bodies are not substituted.** Only the request line (URL) and headers are. `Transfer-Encoding: chunked` request bodies on the MITM path are not parsed, which can misframe keep-alive connections.
- **`HTTPS_PROXY` is advisory.** A process that ignores it bypasses coatcheck, which means no substitution and also no protection. Pair coatcheck with egress enforcement (network policy, firewall, or security group) so the agent can reach the internet only through the proxy.
- **Interception follows the bindings, not the request.** In the default `bound` mode, a keep-alive tunnel opened to a host before any ticket for it existed (a host bound only by a secret's `_allowed_hosts`) stays a raw tunnel, so a ticket later sent down it reaches the upstream unswapped. Clients that pin certificates fail on intercepted hosts unless listed in `COATCHECK_PASSTHROUGH_HOSTS`. Intercepted tunnels speak HTTP/1.1 only (ALPN), and WebSocket frames after an upgrade are not inspected.
- **The API is unauthenticated.** Any process that can reach the port can list secret names and mint tickets. Keep coatcheck on loopback.
- **The secret backend is AWS-only**, with fixed path prefixes, pending a provider interface (env/file first, then others).
- **Browserbase is the only browser adapter.** The `connectUrl` rewrite is tied to `api.browserbase.com`.
- **CDP v1 limits:** one session at a time, no origin binding yet (login tickets record their allowed hosts, but a login ticket still fills any page in that session), no 2FA, no `page.type()` support, and no screenshot redaction.

## How this differs from superfly/tokenizer

[superfly/tokenizer](https://github.com/superfly/tokenizer) solves the same core problem and is a well-designed piece of work. If its model fits your setup, use it. It is a stateless Go proxy. Secrets are sealed (encrypted to the proxy's key) and travel with the request, so the proxy keeps no secret store. Each secret carries its own `allowed_hosts`, so it cannot be redirected elsewhere. Its processors cover much more than literal substitution: HMAC signing, AWS SigV4, JWT, and OAuth client credentials. The trade-off is that clients must cooperate. They send plain HTTP to the proxy with a `Proxy-Tokenizer` header that carries the sealed secret.

coatcheck makes different trade-offs:

- **Unmodified tools.** coatcheck is a standard `HTTPS_PROXY` with TLS interception, so curl, git, SDKs, and code an LLM writes on the fly work if they honor the proxy variable and trust the CA. No client changes are needed.
- **Secrets by name from a store.** The agent asks for `github-token` and gets a ticket. It never holds secret material, sealed or otherwise. The cost is a stateful component and a backend dependency.
- **Browser/CDP injection.** coatcheck fills credentials into remote-browser sessions over CDP, with inbound redaction and keystroke fail-closed. tokenizer does not cover browsers.
- **Weaker today.** coatcheck has no signing processors, an area where tokenizer is ahead. Both bind secrets to hosts; coatcheck's binding comes from an operator policy file and the stored secret rather than from the sealed secret.

## Development

```bash
npm install
npm test          # vitest
npm run build     # tsc -> dist/
COATCHECK_PROVIDER=aws AWS_REGION=us-east-1 AWS_ENDPOINT_URL=http://localhost:4566 npm run dev
```

## Docs

- [docs/clients.md](docs/clients.md): integrating agent tooling (CA trust, which clients honour the proxy, git, Node, Playwright)
- [docs/design/cdp-injection.md](docs/design/cdp-injection.md): how browser credential injection works
- [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md): attacker model, deployment requirements, known gaps
- [docs/ROADMAP.md](docs/ROADMAP.md): what's next

## License

[Apache-2.0](LICENSE)
