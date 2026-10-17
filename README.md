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

1. **Ticket issuance.** The agent calls `GET http://127.0.0.1:3128/_vault/{name}`. coatcheck fetches the secret from its backend and returns `cct_` plus 64 hex characters. Tickets live only in coatcheck's memory, with a 15-minute TTL.
2. **HTTPS substitution.** The agent container sets `HTTPS_PROXY` to coatcheck and trusts coatcheck's CA. While at least one ticket is active, coatcheck intercepts `CONNECT` tunnels with a per-host certificate it signs itself. It replaces every active ticket it finds in the request line and headers, then re-encrypts to the real host, with normal certificate verification. This works with unmodified tools such as curl, git over HTTPS (with a bearer header), Python `requests`, and Node `fetch`, because they only need proxy support and a trusted CA. Plain-HTTP proxy requests get the same treatment. When no tickets are active, `CONNECT` is a blind TCP tunnel.
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
# {"token":"cct_3b1e…","expires_in":900}

# 2. Fetch coatcheck's CA
curl -s localhost:3128/_ca > /tmp/coatcheck-ca.crt

# 3. Use the ticket as if it were the real key
curl -s --proxy http://localhost:3128 --cacert /tmp/coatcheck-ca.crt \
  -H "Authorization: Bearer cct_3b1e…" https://httpbin.org/headers
```

httpbin echoes the request headers, so step 3 shows the **real** value arriving upstream. That is the point of the demo, and also the main open gap: a ticket sent to any host gets swapped (see [limitations](#status--known-limitations)).

To add your own secret to LocalStack:

```bash
aws --endpoint-url http://localhost:4566 --region us-east-1 ssm put-parameter \
  --type SecureString --name /liv/agents/demo/user-secrets/github-token --value 'ghp_…'
```

### Secret backend layout (AWS)

| Kind | Where coatcheck reads it | Served by |
|---|---|---|
| Named secret | SSM SecureString at `/liv/agents/{AGENT_LABEL}/user-secrets/{name}` | `/_vault/{name}` |
| Multi-value secret | Same location, with a JSON object as the value (`{"username":…,"password":…}`) | `/_vault/{name}?field=…` |
| Shared key | Secrets Manager `liv/{name}`, which must also be in a compiled-in allowlist | `/_secret/{name}` |

The path prefix is hardcoded for now. It becomes configurable when the provider interface lands. coatcheck caches backend reads in memory for 5 minutes, so a rotated secret can take that long to show up.

If `PROXY_ROLE_ARN` is set, coatcheck assumes that role through STS (1-hour sessions, renewed every 45 minutes) before reading secrets. The intended deployment gives backend read access to that role only, and gives the agent's own identity none.

## HTTP API

The API is served on the proxy port (default `127.0.0.1:3128`). **It has no authentication.** Anything that can reach the port can mint tickets, so keep it on loopback inside the agent's network namespace.

| Method & path | Response | Notes |
|---|---|---|
| `GET /_health` | `{"status":"ok","tokens_active":N}` | Liveness check. |
| `GET /_ca` | PEM | coatcheck's root CA certificate, for the agent to trust. |
| `GET /_vault` | `{"secrets":["github-token",…]}` | Lists secret names. Values are not decrypted. |
| `GET /_vault/{name}` | `{"token":"cct_…","expires_in":900}` | For a single-value secret. |
| `GET /_vault/{name}` | `{"type":"multi","fields":[…]}` | For a multi-value (JSON) secret. Request a specific field with `?field=`. |
| `GET /_vault/{name}?field={f}` | `{"token":"cct_…","expires_in":900}` | Ticket for one field. If the secret's `_cleartext` array lists the field, returns `{"value":"…","cleartext":true}` instead (for non-sensitive values such as URLs and account IDs). |
| `GET /_vault/{name}?check=1` | `{"exists":true}` | Checks whether a secret exists without decrypting it. |
| `GET /_secret/{name}` | `{"token":"cct_…","expires_in":900}` | Shared key from Secrets Manager. Returns 403 unless `{name}` is in the allowlist (currently `browserbase-api-key`). |
| `POST /_vault/mint-tokens` | `{"username_token":"cct_…","password_token":"cct_…","expires_in":600}` | Body: `{"secretName":"example-login","sessionId":"<cdp sid>","expires_in"?:N}`. The secret must be a multi-value secret with `username` and `password`. Tickets are bound to one CDP session (see below). Default TTL is 600 s, capped at 1800 s. |
| `POST /_vault/{name}/refresh` | `{"token":"cct_…","expires_in":900}` | Secret fields: `refresh_token`, `token_url`, `client_id`, `client_secret`. coatcheck posts a `refresh_token` grant, writes `access_token`, `expires_at`, and any rotated `refresh_token` back to the backend, and returns a ticket for the new access token. |

Secret names must match `^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$` after URL-decoding; anything else (including `/` or a leading `.`) gets `400` before the backend is consulted. `refresh` returns `501` when the configured backend is read-only.

Errors are JSON `{"error":…}` with status 400, 403, 404, 500, 501, or 502.

## Configuration

| Variable | Default | Purpose |
|---|---|---|
| `AGENT_LABEL` | (required) | Identifies the agent. Scopes the SSM path. coatcheck exits if it is unset. |
| `PROXY_PORT` | `3128` | Port for the proxy and the HTTP API. |
| `PROXY_BIND_HOST` | `127.0.0.1` | Bind address for the proxy and the CDP proxy. Use `0.0.0.0` only for local docker-compose. |
| `CA_DIR` | (unset) | Where to persist the CA key and cert (`ca.key`, `ca.crt`). If unset, coatcheck generates an in-memory CA on every start. If an existing ECDSA P-256 CA is found there, coatcheck reuses it; any other key type (for example an RSA CA from an older version) fails startup until the files are deleted. Per-host certificates are never written to disk. |
| `CDP_PROXY_ENABLED` | off | Set to `1` to run the CDP proxy and rewrite browser-service `connectUrl`s. |
| `CDP_PROXY_PORT` | `8444` | CDP WebSocket proxy port. |
| `CDP_PROXY_ADVERTISE_HOST` | `127.0.0.1` | Host written into the rewritten `connectUrl`. Override it when the Playwright client is in a different container. |
| `AWS_REGION` | `ap-southeast-2` | Region for SSM, Secrets Manager, and STS. |
| `AWS_ENDPOINT_URL` | (unset) | Endpoint override for SSM and Secrets Manager, e.g. LocalStack. |
| `PROXY_ROLE_ARN` | (unset) | IAM role to assume before reading secrets. If unset, the default AWS credential chain is used. |

Standard AWS SDK credential variables apply. Certificates are generated in-process (ECDSA P-256); coatcheck needs no `openssl` binary.

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

Unless `CA_DIR` is set and on persistent storage, each coatcheck restart generates a new CA, and the agent has to fetch `/_ca` again.

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

If an upstream returns 401 while you are using a ticket, assume the swap did not happen before you assume the stored credential is wrong. coatcheck logs one line per request with no values: `[swap] … result=hit secrets=…` on success, or `result=miss unswapped_ticket_literals=N` when a `cct_<64 hex>` string reaches the upstream intact.

## Browser / CDP credential injection

This lets an agent log into a website through a remote browser without the password entering its context. Set `CDP_PROXY_ENABLED=1`. Browserbase is the only supported browser service today.

1. The agent creates a session with `POST https://api.browserbase.com/v1/sessions` **through `HTTPS_PROXY`**, authenticating with a `/_secret/browserbase-api-key` ticket. coatcheck rewrites the response's `connectUrl` from the real `wss://…` URL, which carries Browserbase's signing key, to `ws://{CDP_PROXY_ADVERTISE_HOST}:8444/cdp/{sid}`. The agent never sees the real URL. A `sid` is valid for 10 minutes until a client connects.
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

- **Tickets are not bound to destination hosts.** This is the top priority. Today any active ticket is swapped on a request to *any* host. A prompt-injected agent that sends `Authorization: Bearer cct_…` to an attacker's server delivers the real secret, as the httpbin quickstart shows. coatcheck currently protects against the agent *seeing* or *printing* secrets (logs, transcripts, model context), not against it *sending* them somewhere. Per-secret allowed hosts are planned.
- **Request bodies are not substituted.** Only the request line (URL) and headers are. `Transfer-Encoding: chunked` request bodies on the MITM path are not parsed, which can misframe keep-alive connections.
- **`HTTPS_PROXY` is advisory.** A process that ignores it bypasses coatcheck, which means no substitution and also no protection. Pair coatcheck with egress enforcement (network policy, firewall, or security group) so the agent can reach the internet only through the proxy.
- **Interception is all-or-nothing while any ticket is live.** With at least one active ticket, *every* `CONNECT` is MITM'd, not just connections that carry tickets. Clients that pin certificates or don't trust the CA will fail during that window.
- **The API is unauthenticated.** Any process that can reach the port can list secret names and mint tickets. Keep coatcheck on loopback.
- **The secret backend is AWS-only**, with fixed path prefixes, pending a provider interface (env/file first, then others).
- **Browserbase is the only browser adapter.** The `connectUrl` rewrite is tied to `api.browserbase.com`.
- **CDP v1 limits:** one session at a time, no origin binding (a login ticket fills any page in that session), no 2FA, no `page.type()` support, and no screenshot redaction.

## How this differs from superfly/tokenizer

[superfly/tokenizer](https://github.com/superfly/tokenizer) solves the same core problem and is a well-designed piece of work. If its model fits your setup, use it. It is a stateless Go proxy. Secrets are sealed (encrypted to the proxy's key) and travel with the request, so the proxy keeps no secret store. Each secret carries its own `allowed_hosts`, so it cannot be redirected elsewhere. Its processors cover much more than literal substitution: HMAC signing, AWS SigV4, JWT, and OAuth client credentials. The trade-off is that clients must cooperate. They send plain HTTP to the proxy with a `Proxy-Tokenizer` header that carries the sealed secret.

coatcheck makes different trade-offs:

- **Unmodified tools.** coatcheck is a standard `HTTPS_PROXY` with TLS interception, so curl, git, SDKs, and code an LLM writes on the fly work if they honor the proxy variable and trust the CA. No client changes are needed.
- **Secrets by name from a store.** The agent asks for `github-token` and gets a ticket. It never holds secret material, sealed or otherwise. The cost is a stateful component and a backend dependency.
- **Browser/CDP injection.** coatcheck fills credentials into remote-browser sessions over CDP, with inbound redaction and keystroke fail-closed. tokenizer does not cover browsers.
- **Weaker today.** coatcheck lacks host binding and signing processors, both areas where tokenizer is ahead. Host binding is next on the roadmap.

## Development

```bash
npm install
npm test          # vitest
npm run build     # tsc -> dist/
AGENT_LABEL=demo AWS_ENDPOINT_URL=http://localhost:4566 npm run dev
```

## Docs

- [docs/clients.md](docs/clients.md): integrating agent tooling (CA trust, which clients honour the proxy, git, Node, Playwright)
- [docs/design/cdp-injection.md](docs/design/cdp-injection.md): how browser credential injection works
- [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md): attacker model, deployment requirements, known gaps
- [docs/ROADMAP.md](docs/ROADMAP.md): what's next

## License

[Apache-2.0](LICENSE)
