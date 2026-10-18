# v1 design decisions

Status: **decided**, and implemented through roadmap item 19. These
decisions are the basis for `docs/ROADMAP.md`. Roadmap item 20
(`cdp-broker-login.md`) later replaced the CDP ticket flow; the sections it
superseded carry a dated note and are otherwise kept as written.
Implement them as written. If one proves wrong during implementation (for
example, a test shows it doesn't work), stop and raise it; don't redesign it
inside a roadmap item. Each section names the alternatives that were rejected
so they aren't reopened by accident.

## 1. Repo layout

npm workspaces with three published packages. The `coatcheck` bin lives in core
and loads the provider dynamically.

```
package.json            private root: workspaces ["packages/*"], shared scripts, eslint, vitest projects
tsconfig.base.json      + per-package tsconfig with project references (tsc -b)
Dockerfile, Dockerfile.dev   build all workspaces; runtime installs core + provider-aws + provider-env
examples/               docker-compose.localstack.yml, docker-compose.env.yml (zero-AWS quickstart),
                        localstack-init.sh, policy.example.json
packages/core/          @coatcheck/core: proxy, MITM, CA, tickets, vault API, CDP, browser adapters,
                        config, SecretProvider types, withCache, bin `coatcheck` -> dist/cli.js
packages/provider-aws/  @coatcheck/provider-aws: SSM + Secrets Manager + STS (only package with @aws-sdk/*)
packages/provider-env/  @coatcheck/provider-env: `.` = env provider, `./file` = JSON-file provider
```

- `COATCHECK_PROVIDER` chooses the provider at runtime:
  - `aws`, `env` and `file` map to the packages above;
  - any other value is treated as a module specifier and loaded with `import()`.

  Each provider module default-exports `createProvider(ctx): Promise<SecretProvider>`.
- Core also exports `startCoatcheck({ config, provider, adapters })` for library
  users and tests.
- Files move with `git mv`. Tests stay colocated.
- Only `config.ts` and `cli.ts` read `process.env`. An eslint
  `no-restricted-properties` rule enforces this. Providers receive the
  environment through their factory context.
- Rejected:
  - A single package with optional AWS peer dependencies: it contradicts
    `@coatcheck/*` naming and puts the AWS SDK in core's dependency surface.
  - A separate `@coatcheck/server` app package: one more package to publish,
    and it still needs the dynamic path for third-party providers.
  - Separate repos: premature.

### Packaging details (recorded while implementing roadmap item 12)

- **Providers depend on core, never the reverse.** Provider packages import
  `ConfigError`, `EnvReader`, `interpolateAgentId`, `isValidSecretName` and
  the interface types from `@coatcheck/core`, declared as a
  `peerDependency` so a deployment has exactly one copy of core. Core has no
  dependency on any provider package: `aws`, `env` and `file` are mapped to
  `@coatcheck/provider-aws`, `@coatcheck/provider-env` and
  `@coatcheck/provider-env/file` and loaded with `import()`. If the package
  isn't installed, startup fails with a `ConfigError` that names the package
  to install. Rationale: a static dependency would make the AWS SDK part of
  core's install again, which is what §1 rejects.
- **A provider module's default export is its `CreateProvider`.** A module
  without a function default export fails startup with a `ConfigError`.
  `loadConfig` accepts any non-empty `COATCHECK_PROVIDER`; whether it resolves
  is only known at `import()` time.
- **`createMemoryProvider` stays in core** and is exported for tests and
  embedding. It is not selectable through `COATCHECK_PROVIDER`.
- **Workspace resolution without a build step.** Each package's `exports` has
  a `@coatcheck/source` condition pointing at `src/*.ts` ahead of the
  `types`/`default` entries that point at `dist`. vitest
  (`resolve.conditions`) and `tsx` (`--conditions`) use it, so tests and
  `npm run dev` run against source. Published tarballs ship `dist` only;
  nobody else sets that condition. Rejected: vitest path aliases, which tsx
  would not share.
- **`type-check` is `tsc -b`.** Composite project references must emit
  declarations for downstream packages, so type-check and build are the same
  command; `build` is kept as a name for CI and the Dockerfiles.
- **A provider rejects a name with `InvalidSecretNameError`** (exported by
  core), thrown from `get`/`exists`/`put`; the vault API answers `400` with
  its message. This is how the env provider refuses names outside
  `[a-z0-9-]+` (§4) without adding a method to `SecretStore`. Any other
  provider error stays a logged `500`.
- **vitest uses inline `projects`**, one per package, from the root config.
- **The demo files move to `examples/`.** `docker-compose.example.yml`
  becomes `examples/docker-compose.localstack.yml`; both compose files build
  from the repo root. The env quickstart uses `Dockerfile` (not
  `Dockerfile.dev`) since it has nothing to iterate on.

## 2. SecretProvider interface and naming

```ts
export interface Secret {
  value: string;
  /** Provider-native host policy (e.g. tags). Unused in v1; in-band `_allowed_hosts` is parsed by core. */
  allowedHosts?: string[];
}
export interface SecretStore {
  get(name: string): Promise<Secret | null>;
  exists(name: string): Promise<boolean>;
  list(): Promise<string[]>;
  put?(name: string, value: string): Promise<void>; // absent => /_vault/{name}/refresh returns 501
}
export interface SecretProvider {
  readonly name: string;
  secrets: SecretStore;                    // per-agent secrets
  shared?: Pick<SecretStore, 'get'>;       // shared, allowlisted secrets; absent => /_secret/* returns 404
  close?(): Promise<void>;
}
export interface ProviderContext { env: Readonly<Record<string, string | undefined>>; agentId?: string }
export type CreateProvider = (ctx: ProviderContext) => Promise<SecretProvider>;
export function withCache<T extends Pick<SecretStore, 'get'> & Partial<SecretStore>>(store: T, ttlMs: number): T;
// withCache caches get() only; put() invalidates the entry.
```

- `get` returns a `Secret`, not a string, so that provider-native metadata can
  be added later without breaking the interface.
- Core validates every secret name before calling a provider:
  `^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`. The pattern rules out `/` and `..`.
  A provider may be stricter (§4).
- "Fleet" secrets are renamed to **shared** secrets. The route stays
  `/_secret/{name}`.
- `AGENT_LABEL` is renamed to **`COATCHECK_AGENT_ID`** and becomes optional. It is
  used in three places:
  - log lines;
  - the default STS session name;
  - `{agentId}` interpolation in provider prefixes.

  If a prefix template references `{agentId}` and it is unset, startup fails.
  Rejected names:
  - `scope`: collides with OAuth scopes.
  - `namespace`: collides with Kubernetes, and implies an isolation guarantee
    coatcheck doesn't provide.
- Store path prefixes become provider configuration (§4). There are no
  hard-coded deployment-specific paths. Drop the hard-coded region fallback and
  the manual `AWS_ENDPOINT_URL` plumbing; AWS SDK v3 handles both, which also
  fixes STS ignoring the endpoint today.
- Tests use a small in-memory `SecretProvider` helper in core instead of
  ad-hoc mocks.

## 3. Host-bound tickets

### Where allowed hosts come from

Each source can only narrow:

1. **The policy file**, owned by the operator. It maps secret names to hosts,
   and a trailing `*` is allowed in names (`google-*`). It also holds the
   shared-secret allowlist.
2. **An in-band `_allowed_hosts`** field in JSON secrets, next to `_cleartext`.
   The user owns it, and it covers secrets added at runtime. A JSON secret
   whose only non-underscore key is `value` is treated as a simple secret,
   which lets a single-value secret carry metadata.
3. Provider-native metadata (`Secret.allowedHosts`) has an interface slot. No
   provider fills it in v1.

A secret's effective hosts are the **intersection** of the sources that are
present. If neither source is present, the secret is **unbound**.

The agent can't write `_allowed_hosts`. The only write path is OAuth refresh,
which spreads the existing object and copies only `access_token`,
`refresh_token` and `expires_in` from the token endpoint. Mint-time narrowing
by the agent is deferred, and if it is ever added it may only narrow.

### Policy file details (recorded while implementing roadmap item 8)

- **Schema is strict.** The top level allows only `secrets` and `shared`.
  Each entry allows only `allowed_hosts`, which must be a non-empty array of
  strings. Unknown keys and empty lists fail startup. Rationale: a typo such
  as `allowed_host` would otherwise silently leave a secret unbound, and an
  empty list is almost certainly a mistake.
- **Shared names are exact.** A trailing `*` is allowed only under `secrets`.
  The shared section is an allowlist that every agent can draw on, so each
  entry should name one secret.
- **Name precedence.** When several `secrets` patterns match a name, an exact
  name wins. Among wildcards, the longest prefix wins. Rationale: the most
  specific rule should apply, and the outcome must not depend on key order.
- **`http://host` entries allow both schemes.** A bare entry allows HTTPS
  only; `http://host` additionally allows plaintext to that host. Plaintext
  is the riskier permission, so it implies the safer one.
- **Entries carry no ports or paths.** `host:port`, `https://…`, paths,
  ports, and bracketed IPv6 with a port are all rejected, because ports are
  ignored when matching and a port in an entry would suggest otherwise. Bare
  or bracketed IPv6 literals are accepted.
- **No public-suffix list.** `*.co.uk` passes the "at least two labels after
  `*.`" rule. Operators own the policy file; pulling in a PSL dependency
  isn't worth it for v1.
- **No policy file means no shared secrets.** `/_secret/*` returns `403` for
  every name.

### Host binding details (recorded while implementing roadmap item 9)

- **Intersection is computed, not deferred.** The effective list is the
  pairwise intersection of the two pattern lists: exact ∩ exact is the host
  when equal, exact ∩ wildcard is the exact host when the wildcard covers it,
  and wildcard ∩ wildcard is the narrower wildcard when one suffix contains the
  other. An entry allows plaintext only when both sides do. Rationale: one
  concrete list can be snapshotted on the ticket and shown in the mint
  response.
- **An empty intersection is refused at mint time** (`403`, naming the
  secret). The ticket could never be used, so this is the same reasoning as
  deny-at-mint for unbound secrets.
- **Underscore keys are metadata.** In a JSON secret, every key starting with
  `_` (`_cleartext`, `_allowed_hosts`, and any future one) is hidden from the
  field list and can't be requested as a field. This follows from the
  "only non-underscore key is `value`" rule.
- **`_allowed_hosts` must be a non-empty array of valid entries.** Anything
  else (not an array, empty, a non-string, an invalid entry) fails minting
  with `500`, as an invalid in-band entry does.
- **Every minting route applies the binding:** `/_vault/{name}` (all fields of
  a multi-value secret share the secret's hosts), `/_secret/{name}` (policy
  `shared` hosts ∩ in-band), `/_vault/{name}/refresh`, and
  `/_vault/mint-tokens`. Session-bound CDP tickets snapshot the login secret's
  hosts now; enforcing them against the page origin is roadmap item 15.
  Cleartext fields aren't tickets and are returned whether or not the secret
  is bound.

  > **Superseded (2026-10, roadmap item 20).** `mint-tokens` is gone. `POST /_vault/{name}/login`
  applies the same binding (unbound → `403`) and checks the page's committed
  origin against it; no CDP ticket is issued.
- **Unbound tickets in the token store.** A ticket issued without
  `allowedHosts` is unbound and substitutes for any host. The vault API only
  issues one when `COATCHECK_ALLOW_UNBOUND_SECRETS=1`; the mint response then
  carries `"allowed_hosts": null`.
- **Forward path swaps only in the path and query.** Swapping into the URL's
  host or userinfo would change the host being dialled after the check (and
  leak the value in a DNS query), so tickets there are left as literals. Only
  `http:` absolute-form URLs are forwarded; anything else gets `400`.
- **A denied MITM request closes the tunnel.** coatcheck answers `403` with
  `Connection: close` and drops the upstream connection. Requests pipelined
  ahead of it that the upstream hasn't answered yet are abandoned. Rationale:
  the parser can't interleave a synthetic response with in-flight upstream
  responses safely, and denial is an attack signal, not a normal outcome.

### Request body substitution (recorded while implementing roadmap item 17)

- **Off by default, opt-in per secret.** A body is where APIs echo input back
  (validation errors, created resources), so swapping there widens what an
  allowed host can reflect to the agent. Headers and the URL are swapped for
  every ticket; the body only for tickets whose secret opts in.
- **Two sources, deny wins.** `"swap_body": true` on a `secrets` or `shared`
  entry in the policy file, or `"_swap_body": true` in a JSON secret. Either
  one enables it; an explicit `false` in either source disables it, as the
  allowed hosts take the intersection. Both must be booleans: a policy file
  with anything else fails startup, an in-band value fails minting with
  `500`. All fields of a multi-value secret share the setting, and the
  refreshed OAuth access token inherits it.
- **The ticket snapshots it at mint**, as it does its hosts
  (`issue(name, value, { swapBody })`). Mint responses carry
  `"swap_body": true` when it is on, so the agent knows a body ticket will
  work.
- **Host binding applies unchanged.** A body-swap ticket bound to another host
  denies the whole request (`403 host-mismatch`, tunnel closed), the same as
  in a header. A ticket in the body whose secret doesn't opt in is left as a
  literal and doesn't deny: nothing is substituted, so nothing leaks. It is
  logged as `[swap] result=body-skipped secrets=…`.
- **Both paths.** On the MITM path the body comes from the item-16 framing;
  on the forward path from Node's parser. Either way it is buffered whole.
  When something is swapped:
  - a `Content-Length` body gets a rewritten `Content-Length`;
  - a chunked MITM body is re-sent as one chunk plus the last chunk and the
    original trailers, so the framing headers stay as they were;
  - the forward path always sends `Content-Length` (Node de-chunks the body).
- **Encoding follows `Content-Type`.** JSON (`application/json`, `*/*+json`)
  gets the value JSON-string-escaped, because a ticket in JSON sits inside a
  string. `application/x-www-form-urlencoded` gets it percent-encoded. Every
  other type gets the raw UTF-8 bytes. Rationale: a value holding `"` or `&`
  would otherwise break the body or add a field. Rejected: escaping for
  multipart and other formats, which have no single correct escaping.
- **Encoded bodies are not scanned.** A body with a `Content-Encoding` other
  than `identity` is forwarded as is; the ticket can't be found without
  decompressing, and recompressing changes the bytes the client signed or
  measured.
- **Bytes outside tickets are preserved exactly** (the body is handled as
  latin1, so binary bodies round-trip).

### Swap-path hardening (recorded while implementing roadmap item 19)

- **A real value must fit where its ticket sits.**
  - *Header fields:* a value containing a control character other than tab
    (CR, LF and NUL included; RFC 9110 §5.5) can't be a header value;
    spliced in, it would add header lines (and could desync the
    `Content-Length` rewrite). The request is refused before anything is
    forwarded: `403` with `X-Coatcheck-Denied: invalid-value`, logged as
    `[swap] result=invalid-value secrets=…`, tunnel closed on HTTPS. Same on
    the forward path (before, Node threw and the client got `502`). Who can
    plant such a value: the operator, or an OAuth token endpoint whose
    `access_token` is written back on refresh. The agent can't write secrets.
  - *MITM request line:* the swapped request target gets the same
    percent-encoding the forward path applies (control, space, non-ASCII), so
    a value with a space can't split the request line.
  - *Bodies* are unchanged: JSON and form values are escaped, other types
    get the raw bytes (the operator opted the secret in).
- **Bodies stream unless a swap is possible.** At the end of a request head,
  the body is buffered only when a live `swap_body` ticket could be swapped
  for the target (bound to it, or unbound). Otherwise it is forwarded as it
  arrives, as before item 17. A ticket minted after the head was read
  doesn't apply to that body, and its literal passes through (fails closed).
  In a streamed body nothing is scanned, so a `swap_body` ticket bound to
  another host leaves as its literal instead of getting `403 host-mismatch`,
  and no `body-skipped` line is logged. The value is never sent either way.
- **A buffered body is capped** at `COATCHECK_MAX_SWAP_BODY_BYTES` (default
  1 MiB, from 1 KiB to 64 MiB). Past the cap, coatcheck forwards what it has
  buffered and streams the rest, unscanned, with the original framing,
  logging `[swap] result=body-unscanned`. Rejected: `413`. It would break
  large uploads to any host that also has a body-swap secret, and a ticket in
  a body that large still fails closed as a literal.
- **Chunked bodies are decoded incrementally.** The decoder keeps its state
  between TLS records, so a chunked upload costs linear time. A streamed
  chunked body is forwarded chunk framing and all; a malformed chunk found
  mid-stream still gets `400 bad-framing` and closes both legs (the upstream
  sees a truncated request).
- **The header section is capped at 64 KiB.** A head that doesn't end within
  it gets `431` and the tunnel is closed. Before, an endless head grew the
  buffer without bound. 64 KiB is above common servers' defaults (Node: 16 KiB).
- **One pattern scan per input.** The token store finds `cct_<64 hex>`
  literals with `TICKET_PATTERN` and looks each one up, instead of a
  substring search per live ticket. Cost: one pass over the input plus the
  tickets present.
- **Shared rules carry their own `swap_body`.** `Policy.shared` maps a name to
  `{ allowedHosts, swapBody? }`, like a per-agent `PolicyRule`.
- **The MITM parses each request head once** (`parseRequestHead`): framing,
  `Content-Type`, `Content-Encoding` and `Upgrade` come from one parse. A
  bare CR or LF inside the request line or a header line is malformed
  (`400 bad-framing`): some servers treat it as a line break, so a
  `Content-Length` hidden behind one would desync the framing.
- **Substitution is one pass** over the input (`TICKET_PATTERN`), so a real
  value that contains another ticket's literal is never substituted again.
- **Flow control on the MITM tunnel.** Streaming moved bodies out of
  coatcheck's buffers and into the upstream socket's write queue, which a
  slow or stalled upstream lets grow without bound. coatcheck now pauses
  reading from the client while the upstream socket is full (until
  `drain`), while more than 1 MiB is held before the upstream connects, and
  while more than 64 KiB arrives during a pending upgrade. TCP backpressure
  then reaches the client. Attack tests use an upstream that never reads.
- **`close()` destroys open tunnels.** CONNECT sockets leave the HTTP
  server's connection tracking, and a tunnel paused for backpressure doesn't
  see the client's EOF, so shutdown destroys them explicitly.
  - Residual: there is no idle timeout on tunnels. A client that disconnects
    while its tunnel is paused against an upstream that never reads again
    holds both sockets until the upstream closes. The same is true of
    passthrough tunnels today.

### Default: deny, at mint time

- `/_vault/{name}` for an unbound secret returns `403` with an error naming the
  secret. Failing at mint time is easier to debug than a silent miss at swap
  time.
- `COATCHECK_ALLOW_UNBOUND_SECRETS=1` is the explicit opt-out. It logs a warning
  at startup and logs `result=unbound` on every swap.
- Rejected: allow by default (ships the HIGH gap open), and deny at swap time
  only (the agent holds a ticket that silently never works).

### Matching

- An entry is either an exact hostname or `*.example.com`. The wildcard matches
  one or more labels; it does not match the apex.
- Entries are normalised: lowercased, trailing dot removed, and
  `url.domainToASCII` applied.
- IP literals match exactly.
- Ports are ignored.
- HTTPS is implied. An entry must be written `http://host` to allow plaintext.
- These entries are rejected: bare `*`, and wildcards with fewer than two
  labels after `*.`.
- Invalid entries fail closed. In the policy file, startup fails. In an in-band
  field, minting fails with `500`.
- Rejected: regular expressions (unescaped dots and missing anchors are
  footguns) and arbitrary globs (there is no use case beyond the suffix
  wildcard).

### Enforcement

- Tickets take a snapshot of `allowedHosts` at mint time.
  `TokenStore.issue(name, value, { ttlSeconds, allowedHosts, sessionId })`
  replaces both `issue` and `issueForSession`. (Later: item 17 added
  `swapBody`; item 20 removed `sessionId`, since there are no session-bound
  tickets.)
- `replaceAll(input, target: { host, scheme })` requires the target, so the
  compiler finds every call site.
- **HTTPS MITM path.** The key is the validated CONNECT target. Upstream TLS
  verification makes that host the real recipient. The key is never the
  `Host` header or the SNI.
- **Plain-HTTP forward path.** The key is the URL hostname as parsed by the
  WHATWG URL parser, which is the host that is actually dialled.
  - Plaintext requests only match entries written `http://`. Loopback and
    private destinations therefore never match unless they are listed
    explicitly, which closes the "agent runs its own listener" hole.
  - The forward path strips `proxy-authorization` and hop-by-hop headers.
- **On a mismatch** the request is not forwarded.
  - The response is `403` with `X-Coatcheck-Denied: host-mismatch` and a JSON
    body that names the secret and the host.
  - The log line is `[swap] result=denied`.
  - If one ticket in a request is denied, the whole request is denied.
- **OAuth refresh.** The `token_url` host must be in the secret's allowed
  hosts, because `client_secret` is sent there. The refreshed access-token
  ticket inherits the binding.
- Mint responses include `allowed_hosts`; they aren't secret.
- **CDP origin binding:**
  - Session-bound tickets carry the login secret's hosts.
  - The proxy tracks each flattened CDP `sessionId`'s committed main-frame URL,
    using inbound `Page.frameNavigated` events with no `parentId`.
  - `Input.insertText` substitutes only when that host matches. On a mismatch,
    or when the origin is unknown (for example, `Page` was never enabled), the
    proxy drops the frame and returns a CDP error, the same way the keystroke
    detector does.
  - `Runtime.evaluate` and `Runtime.callFunctionOn` are no longer substitution
    sites.
  - A Playwright + Chromium e2e test must prove that `page.fill` still works on
    text, email and password inputs. If it doesn't, the fallback is to
    substitute in `callFunctionOn.arguments` only, never in
    `functionDeclaration` or `expression`, and still gated on origin.
- **Residual risk on CDP, documented rather than fixed:**
  - Script that the agent runs on the allowed origin can read the filled value
    and send it anywhere.
  - Cross-origin iframe logins. Binding keys on the main frame because the
    focused frame can't be attributed:
    - A login form inside a cross-origin iframe, such as an embedded auth
      widget, is refused when the main frame's origin isn't allowed.
    - When the main frame is allowed, a fill whose focus is inside a
      cross-origin iframe (including one injected by the agent) types the real
      value into that iframe.

  > **Superseded (2026-10, roadmap item 20).** There is no `Input.insertText` substitution any more.
  coatcheck fills the form itself on a freshly reloaded document while the
  agent's frames are held, checking the committed main-frame origin before
  and after the reload. Selectors resolve in the main document only, so
  cross-origin iframe logins fail with `404 selector-not-found`. The current residual risks are in
  `cdp-broker-login.md`.

## 4. Configuration

Use environment variables for scalar settings, plus one optional JSON policy
file.

- Rejected: environment variables only (per-secret host lists in the
  environment are unreadable), and a full config file that mirrors the
  environment (two ways to set everything, which is awkward on ECS and
  Kubernetes). JSON is chosen over YAML to avoid a dependency.
- Old names are removed outright; there are no external users yet. If a legacy
  name (`AGENT_LABEL`, `PROXY_PORT`, `PROXY_BIND_HOST`, `CA_DIR`,
  `PROXY_ROLE_ARN`, `CDP_PROXY_*`) is set, startup fails with
  "renamed to X".
- `packages/core/src/config.ts` exports a pure `loadConfig(env, readFile)` that
  returns a typed `Config`.

| Core | Default | Notes |
|---|---|---|
| `COATCHECK_PROVIDER` | required | `aws` \| `env` \| `file` \| module specifier |
| `COATCHECK_AGENT_ID` | unset | logs, `{agentId}` in templates, STS session name |
| `COATCHECK_BIND_HOST` | `127.0.0.1` | both listeners |
| `COATCHECK_PORT` | `3128` | |
| `COATCHECK_API_TOKEN` | unset | required when the bind host isn't loopback; vault API `Authorization: Bearer`, proxy `Proxy-Authorization` |
| `COATCHECK_POLICY_FILE` | unset | allowed hosts and the shared-secret allowlist |
| `COATCHECK_ALLOW_UNBOUND_SECRETS` | `0` | opt out of deny-by-default |
| `COATCHECK_TICKET_TTL_SECONDS` | `900` | HTTP tickets |
| `COATCHECK_SECRET_CACHE_TTL_SECONDS` | `300` | `withCache` |
| `COATCHECK_MITM` | `bound` | `bound`: MITM only hosts in the policy file, on live tickets, or on adapters. `always`: MITM every CONNECT (opt-in) |
| `COATCHECK_PASSTHROUGH_HOSTS` | empty | never MITM (cert-pinned clients); exact or wildcard |
| `COATCHECK_MAX_SWAP_BODY_BYTES` | `1048576` | largest body buffered for `swap_body`; larger ones stream unscanned (item 19) |
| `COATCHECK_CA_DIR` | unset | unset: ephemeral in-memory CA. Set: persist the CA key and cert only |
| `COATCHECK_CA_SUBJECT` | `CN=coatcheck CA, O=coatcheck` | |
| `COATCHECK_MISSING_SECRET_URL` | unset | `vault_url` hint in 404s; omitted when unset |
| `COATCHECK_CDP_ENABLED` | `0` | |
| `COATCHECK_CDP_PORT` | `8444` | |
| `COATCHECK_CDP_ADVERTISE_HOST` | `127.0.0.1` | |
| `COATCHECK_BROWSER_ADAPTERS` | `browserbase` | comma-separated built-ins; custom adapters through the library API |

| provider-aws | Default | Notes |
|---|---|---|
| `AWS_REGION`, `AWS_ENDPOINT_URL`, credentials | SDK chain | no hard-coded region |
| `COATCHECK_AWS_SSM_PREFIX` | `/coatcheck/secrets/` | `{agentId}` is interpolated |
| `COATCHECK_AWS_SHARED_PREFIX` | `coatcheck/` | Secrets Manager |
| `COATCHECK_AWS_ROLE_ARN` | unset | broker role to assume |
| `COATCHECK_AWS_EXTERNAL_ID` | unset | warns at startup if `ROLE_ARN` is set without it |
| `COATCHECK_AWS_ROLE_SESSION_NAME` | `coatcheck-{agentId}`, or `coatcheck` | |

| provider-env | Default | Notes |
|---|---|---|
| `COATCHECK_ENV_PREFIX` | `COATCHECK_SECRET_` | shared secrets use `COATCHECK_SHARED_SECRET_` |
| `COATCHECK_SECRETS_FILE` | required for `file` | `{"secrets":{…},"shared":{…}}`; `put` writes to a temp file, then renames |

**`COATCHECK_AWS_EXTERNAL_ID` details (recorded while implementing roadmap item 18):**

- Sent as `ExternalId` on every `AssumeRole` call for the broker role.
- Set without `COATCHECK_AWS_ROLE_ARN`, startup fails: there is no role to
  send it to, so it would protect nothing while looking configured.
- Validated against STS's format (2–1224 characters of `[\w+=,.@:/-]`). The
  error never echoes the value, because it is the credential that keeps the
  agent out of the broker role.
- The warning for `ROLE_ARN` without it is logged by the provider's default
  export (`awsConfigWarnings`), not by core, which knows nothing about AWS.
  It is a warning, not an error: a separate-task deployment can assume a role
  safely without one.
- Rejected: reading the value from a file or Secrets Manager inside the
  provider. ECS container-level `secrets` already inject it into one
  container from Secrets Manager, fetched by the execution role.

**The env provider accepts only `[a-z0-9-]+` names.** That keeps the mapping
reversible: `github-token` ↔ `COATCHECK_SECRET_GITHUB_TOKEN` (uppercase, `-` →
`_`). If a name is outside that set, the provider rejects it as a bad request.
When listing secrets, it ignores variables whose names don't map back. The
provider's README and the core README both document this. The `file` provider
uses core's name rules, because JSON keys need no mapping.

### API token details (recorded while implementing roadmap item 11)

- **Proxy credentials use Basic as well as Bearer.** `Proxy-Authorization:
  Basic base64(user:TOKEN)` is accepted with any user name, and so is
  `Bearer TOKEN`. Rationale: unmodified tools only send proxy credentials
  taken from the proxy URL (`HTTPS_PROXY=http://coatcheck:$TOKEN@host:3128`),
  and they send them as Basic. Bearer covers clients that set the header
  themselves.
- **The vault API takes `Authorization: Bearer TOKEN` only.** It is called
  directly, not through a proxy, so the client always controls the header.
- **`/_health` and `/_ca` stay open.** Orchestrator health checks (the
  Dockerfile `HEALTHCHECK`, ECS, Kubernetes probes) can't easily carry a
  secret, and the CA certificate is public by nature. Neither reveals a
  secret; `/_health` reveals only the ticket count.
- **Rejections:** `401` with `WWW-Authenticate: Bearer realm="coatcheck"` on
  the vault API; `407` with `Proxy-Authenticate: Basic realm="coatcheck"` on
  forward requests and `CONNECT`, which are refused before any upstream dial.
  Comparison is constant-time over SHA-256 digests. The token is never
  logged.
- **When a token is set it is enforced on every bind host**, loopback
  included. Without one, the listeners are open, which `loadConfig` allows
  only on loopback (`127.0.0.0/8`, `::1`, `localhost`). Any other bind host,
  including `0.0.0.0`, `::` and hostnames, needs a token.
- **The token must be at least 32 characters with no whitespace.** A short
  token on a network listener is guessable, and whitespace can't survive the
  header and URL forms. Suggested: `openssl rand -hex 32`.
- **The CDP listener stays authenticated by its sid.** The sid is a 96-bit
  capability that only reaches the agent inside an intercepted, authenticated
  browser-service response, and Playwright's `connectOverCDP` URL is the only
  thing every client can carry. Revisit if a CDP adapter without that flow
  appears.
- The demo compose files (`examples/docker-compose.localstack.yml` and
  `examples/docker-compose.env.yml`; `docker-compose.example.yml` before item
  12) bind `0.0.0.0`, so they require
  `COATCHECK_API_TOKEN` from the environment instead of hard-coding one: a
  published demo token would be no authentication at all.

Policy file:

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

## 5. MITM policy

- **The default is `COATCHECK_MITM=bound`.** coatcheck MITMs a CONNECT when the
  target matches any of:
  - hosts in the policy file;
  - the allowed hosts of a live ticket;
  - an adapter host.

  Every other CONNECT is a raw tunnel. A ticket can only ever substitute for
  those hosts, so decrypting anything else gains nothing and risks breaking
  clients.
  - Residual: a keep-alive tunnel opened to a host that is bound only in-band,
    before the first ticket for that host was minted, stays passthrough. The
    request then fails closed: the upstream sees the literal ticket.
  - `always` is opt-in, for when the host list isn't known in advance or for a
    future egress allowlist.
  - `COATCHECK_PASSTHROUGH_HOSTS` overrides both modes.
- **Details recorded while implementing roadmap item 10:**
  - *Unbound tickets match every host.* With `COATCHECK_ALLOW_UNBOUND_SECRETS=1`
    a live unbound ticket can be swapped anywhere, so while one is live every
    CONNECT is MITM'd. Otherwise the opt-out would silently stop working on
    hosts outside the policy.
  - *Session-bound (CDP) tickets don't count.* They never swap on HTTP(S).
    (Item 20 removed session-bound tickets.)
  - *An adapter host counts only when CDP is enabled*, because that is the
    only time its responses are rewritten. Its API key ticket is normally
    covered by the policy's `shared` hosts anyway.
  - *`COATCHECK_PASSTHROUGH_HOSTS` uses the allowed-host syntax* (exact, `*.`
    wildcard, IP) without `http://`, which means nothing for a CONNECT.
    Invalid entries fail startup.
  - *Upgrade handling.* After forwarding a request that carries an `Upgrade`
    header, coatcheck stops parsing the client stream and holds further
    bytes until the upstream's next response head. `101` turns both
    directions into a raw pipe (no swapping in frames); anything else resumes
    request parsing. An upgrade request pipelined behind other unanswered
    requests isn't supported (clients open a fresh connection for upgrades).
  - Each CONNECT logs `mode=mitm|passthrough` with a `reason`
    (`policy`, `ticket`, `adapter`, `always`, `passthrough-list`, `not-bound`).
- **The MITM TLS server advertises ALPN `http/1.1` only.** The request parser is
  HTTP/1.1, so h2-capable clients have to negotiate HTTP/1.1, not fail or
  stall. A test asserts the negotiated protocol.
- After a `101 Switching Protocols` response, the connection switches to a raw
  pipe, so WebSockets work through the MITM.

### Request framing details (recorded while implementing roadmap item 16)

- **The MITM parser frames requests per RFC 9112 §6** (`http1-framing.ts`):
  `Transfer-Encoding: chunked` is parsed chunk by chunk (size line, data,
  last chunk, trailer section), otherwise `Content-Length`, otherwise no body.
  The header section is swapped as before; the body, chunk framing included,
  is forwarded byte for byte. Before this, a chunked request was read as
  having no body, so chunk data containing a blank line was parsed as a new
  "request" and tickets in it were swapped into what the upstream reads as
  the body (body swapping is opt-in per secret, item 17).
- **Ambiguous framing is refused, not normalised.** coatcheck can't know how
  the upstream will read a request it doesn't understand, and the agent
  controls both sides of a desync. Each of these gets `400`
  (`X-Coatcheck-Denied: bad-framing`) and the tunnel is closed, without
  forwarding anything from that request on:
  - both `Transfer-Encoding` and `Content-Length`;
  - a `Transfer-Encoding` other than exactly `chunked` (other codings, lists,
    repeated headers);
  - a `Content-Length` that isn't all digits, or repeated with any value;
  - a header line that isn't `token ":"` (whitespace before the colon) or is
    an obs-fold continuation line;
  - a malformed chunk: a non-hex size, more than 16 hex digits, a size line
    longer than 4 KiB, or data not followed by CRLF.
  Header names are matched at the start of a line (the old unanchored regex
  read `X-Content-Length` as `Content-Length`).
- **Trailers are forwarded as received and never swapped.** Request trailers
  are rare, and swapping them would need the header binding rules for a
  second header section.
- **Bodies are buffered whole**, as `Content-Length` bodies already were.
  Superseded by item 19 (§3, "Bodies stream unless a swap is possible"):
  only a body a `swap_body` ticket could apply to is buffered, up to
  `COATCHECK_MAX_SWAP_BODY_BYTES`.

## 6. Browser adapters

```ts
export interface BrowserAdapter {
  name: string;
  hosts: string[];  // REST hosts whose responses are rewritten (exact or wildcard)
  /** Mutate parsed JSON in place; register(realWsUrl) returns the local ws URL. Return true if changed. */
  rewriteJson(body: unknown, register: (realUrl: string) => string): boolean;
}
```

Item 20 added an optional `rewriteRequestJson(body): boolean`, which the
Browserbase adapter uses to strip `extensionId` from JSON request bodies.

- The HTTP/1.1 framing in `browserbase-rewrite.ts` is vendor-neutral and
  becomes `createJsonResponseRewriter(transform)` in core. Adapters supply only
  the JSON transform.
  - Rejected: the earlier draft in which each adapter supplied a streaming
    response rewriter, because every adapter would have to reimplement HTTP
    framing.
- The Browserbase adapter rewrites every string value that matches
  `^wss?://[^/]*browserbase\.com/`, whatever its key. That covers `connectUrl`
  and the debug endpoint's `debuggerUrl`, `debuggerFullscreenUrl`, `wsUrl` and
  `pages[].debuggerUrl`. It also deletes `signingKey`. Rewriting only
  `connectUrl` left a bypass: with a valid API-key ticket, the agent could call
  `/v1/sessions/{id}/debug` and get raw CDP URLs. Check the field names against
  the current API when implementing.
- `CdpSessionStore.register(url, adapterName)` records the adapter name for
  logging.

### CDP origin binding details (recorded while implementing roadmap item 15)

> **Superseded (2026-10, roadmap item 20).** The `Input.insertText` gate, the CDP errors and the
`Runtime.*` handling below no longer exist. The origin-tracking rules (per
flattened session, unknown while navigating, http(s) only) still hold: the
login driver uses them for its origin check and page selection. The e2e
setup is unchanged and now covers broker-performed login.

- **Origin state is per flattened CDP `sessionId`** (the top-level
  `sessionId` field of a frame; frames without one share a root entry). It
  holds the main frame's id and committed URL from `Page.frameNavigated`
  with no `parentId`, and is dropped on `Target.detachedFromTarget`.
- **A navigation in progress makes the origin unknown.** Otherwise a fill
  sent right after a navigation to another site is checked against the old
  origin and can land on the new page (time of check vs. time of use). The
  origin is unknown:
  - from an outbound `Page.navigate`, `Page.reload` or
    `Page.navigateToHistoryEntry` on that session until the next main-frame
    `Page.frameNavigated`, a main-frame `Page.frameStoppedLoading`, or a
    `Page.navigate` response with no `loaderId` (same-document) or an
    `errorText`;
  - from an inbound main-frame `Page.frameStartedLoading` until the next
    main-frame `Page.frameNavigated` or `Page.frameStoppedLoading`.

  A navigation started by page script, or by a click whose start event hasn't
  reached coatcheck yet, can still race a fill; that is documented with the
  script-on-allowed-origin risk.
- **Only `http:` and `https:` origins can match.** `about:blank`, `data:`,
  `chrome-error:` and the like are unknown origins. The page URL's scheme is
  passed to `matchesHost`, so an `http://` page needs an `http://` entry, as
  on the HTTP path.
- **Unbound session tickets** (`COATCHECK_ALLOW_UNBOUND_SECRETS=1`) substitute
  on any known origin, never on an unknown one.
- **A denial drops the whole frame.** coatcheck answers with a CDP error
  carrying the request's `id` and `sessionId` (so Playwright routes it to the
  waiting call), code `-32000`, message `credential-origin violation: …`
  naming the secret and the page host, never a value. The keystroke
  detector's error gains the `sessionId` too. Playwright retries an action
  on any CDP error that isn't a JavaScript or session-closed error, so a
  refused `page.fill` is refused on every retry and surfaces as a
  `TimeoutError` after the action timeout; the reason is in coatcheck's log
  (`FAIL-CLOSED: origin binding refused …`). Accepted: no CDP error shape
  makes Playwright stop retrying, and the refusal is what matters.
- **No substitution in `Runtime.evaluate` or `Runtime.callFunctionOn`.**
  Playwright's `fill` passes the value to its injected script through
  `callFunctionOn.arguments`, but for text, email and password inputs the
  script only selects the field and returns `needsinput`; the value itself
  goes out as `Input.insertText`. So the injected script sees the ticket, and
  no `callFunctionOn` substitution is needed. Tickets seen in `Runtime.*`
  frames are logged (names only) and forwarded unchanged. The e2e test
  proves this on text, email and password inputs.
- **E2E test:** `playwright` (exact pin, core devDependency) launches local
  Chromium with `--remote-debugging-port` and
  `--host-resolver-rules` mapping two test hostnames to a local HTTP server;
  the test registers the browser's CDP URL as a sid, connects through the CDP
  proxy with `connectOverCDP`, and checks the submitted form. CI installs
  Chromium with `npx playwright install --with-deps chromium`. The test runs
  in the normal `npm test`.

### `mint-tokens` session details (recorded while implementing roadmap item 14)

> **Superseded (2026-10, roadmap item 20).** `mint-tokens` was removed. The sid lifetime rule
still holds. `POST /_vault/{name}/login` needs a *connected* sid (a
controller attached by the CDP proxy), checked before the provider is
called, and answers `404` otherwise.

- **A sid is live from `register` until its 10-minute TTL if no client
  connects; once a client connects, it stays live until that connection
  closes** (teardown revokes it). `mint-tokens` accepts only live sids.
  Rationale: the TTL exists to bound unused rewrites; expiring a connected
  session would make a login that starts more than 10 minutes into a session
  fail with `404`, and a closed session must not take new tickets.
- **The check runs before the provider is called**, right after body
  validation, and answers `404 {"error":"Unknown or expired CDP session"}`
  without echoing the sid. No ticket is issued.
- `VaultDeps.cdpSessionStore` is required (only `has` is used), so a caller
  can't forget it and silently skip the check.

### Adapter details (recorded while implementing roadmap item 13)

- **Field names checked against the Browserbase API reference
  (2026-10).** Session create returns `connectUrl` (WebSocket),
  `seleniumRemoteUrl` (HTTP) and `signingKey` ("used to authenticate HTTP
  connections to the session"). `GET /v1/sessions/{id}/debug` returns
  `debuggerUrl`, `debuggerFullscreenUrl`, `wsUrl` and `pages[]` with
  `debuggerUrl` and `debuggerFullscreenUrl`. The reference gives types
  (`uri`) but no example values, so the adapter can't assume the debugger
  URLs are WebSocket URLs.
- **Rewritten:** every string value that parses as a `ws:`/`wss:` URL whose
  host is `browserbase.com` or a subdomain of it, whatever its key; plus the
  value of any `connectUrl` key that is a `ws:`/`wss:` URL on any host. The
  host check uses the parsed hostname, not a regex over the raw string, so
  `evilbrowserbase.com` doesn't match. `connectUrl` stays key-based as well
  because it is the CDP endpoint by definition; a vendor domain change must
  not turn into a bypass.
- **Removed:** `signingKey`, and any string value that can't be rewritten
  but would hand the agent a direct route to the browser: an `http(s)` URL
  whose query embeds a Browserbase WebSocket target (the hosted DevTools
  viewer shape, `…inspector.html?wss=connect.browserbase.com/…`), and any
  non-WebSocket `debuggerUrl` / `debuggerFullscreenUrl`. Rationale: a live
  view in the agent's hands is raw CDP, which is the bypass this item closes.
  Cost: Browserbase live view is unavailable through coatcheck while CDP is
  enabled. `seleniumRemoteUrl` is left: without `signingKey` it can't
  authenticate. (Superseded by item 20: `seleniumRemoteUrl` is removed too,
  as a route to the browser that bypasses the CDP proxy.)
- **Library adapters replace the env list.** `startCoatcheck({ adapters })`
  uses exactly the adapters given; when omitted, `COATCHECK_BROWSER_ADAPTERS`
  (comma-separated built-in names, default `browserbase`; unknown names fail
  startup) picks built-ins. Rationale: one source of truth per process,
  and a library user can include `browserbaseAdapter` explicitly.
- Adapter `hosts` use the `allowed_hosts` syntax (exact or `*.suffix`) and
  are parsed when the server is built, so a bad pattern fails startup.
- Existing CDP tests keep passing. `cdp/proxy.test.ts` registers sids directly,
  and `browserbase-rewrite.test.ts` keeps working through a retained
  `createConnectUrlRewriter` wrapper. The tests that intentionally change
  belong to the origin-binding item.
- Out of v1: a local `--remote-debugging-port` adapter, because it needs a
  rewrite hook on the plain-HTTP forward path.

## 7. Certificates

- Use **`@peculiar/x509` on Node WebCrypto with ECDSA P-256** for the CA and
  leaf certificates.
  - Key generation takes about a millisecond.
  - The library is pure TypeScript and supports SAN, BasicConstraints, KeyUsage
    and EKU.
  - It needs a `reflect-metadata` import.
- **No RSA CA compatibility.** If `COATCHECK_CA_DIR` holds a CA whose key isn't
  ECDSA P-256, startup fails with a message to delete it. coatcheck never
  overwrites a trust anchor silently.
- **Leaf certificates:**
  - Generated asynchronously; the CONNECT handler awaits the certificate before
    it writes `200 Connection Established`.
  - Kept in an in-memory LRU capped at 1000, so many distinct hostnames can't
    exhaust memory.
  - Never written to disk. Only the CA is, and only when `COATCHECK_CA_DIR` is
    set.
  - IP-literal targets get an IP SAN.
- Rejected:
  - `node-forge`: slow pure-JS RSA key generation and a CVE history.
  - `pkijs`: verbose.
  - Node core: it can't issue certificates.
- **Drop `openssl` and `ca-certificates` from both images.** Node uses its
  bundled root CAs, and corporate CAs go through `NODE_EXTRA_CA_CERTS`.
  `Dockerfile.dev` also drops `curl`, which nothing uses.

## 8. Ticket prefix

- The ticket prefix becomes **`cct_`** ("coatcheck ticket"). It is the same
  length as `tok_`.
  - Rejected: `ck_`, because WooCommerce consumer keys are `ck_` plus 40 hex
    characters, so secret scanners would confuse the two formats in both
    directions.
- There is no dual-prefix window. Tickets live only in memory and never
  survive a restart, so there is nothing to stay compatible with. The only
  consumers that break are clients that pattern-match `tok_`, and they are
  updated in the same change.
- Export one `TICKET_PREFIX` / `TICKET_PATTERN` and use it everywhere,
  including the CDP outbound pre-filter (removed with outbound substitution
  in item 20).
- Deferred: a checksum suffix for registering the pattern with secret
  scanners.

## 9. Threat-model gaps: disposition

| Gap | Disposition |
|---|---|
| MITM only when the token store is non-empty | Fixed by §5 (`bound` default, `always` opt-in) |
| Vault API and proxy unauthenticated | Fixed: `COATCHECK_API_TOKEN`, required off loopback |
| STS-assume pitfall | Fixed in provider-aws (`ExternalId` plus a warning) and the AWS deploy guide |
| `mint-tokens` doesn't validate `sessionId` | Fixed: unknown sid returns `404`. `mint-tokens` later removed by item 20; `/login` keeps the check |
| No CDP origin binding; `Runtime.evaluate` exfiltration | Fixed by §3; replaced by broker-performed login (item 20) |
| OAuth refresh logs the provider's body | Fixed: status and parsed `error` code only |
| OAuth `token_url` unchecked | Fixed by §3 |
| Secret names unvalidated | Fixed by §2 |
| Unbounded leaf-certificate cache | Fixed by §7 |
| Tickets reusable until TTL | Deferred past 1.0; host binding removes most of the risk. TTL becomes configurable |
| Egress domain allowlist in the broker | Deferred past 1.0 (builds on `COATCHECK_MITM=always`) |
| `Host` / SNI not compared with the CONNECT target | Documented: policy keys on the CONNECT target |
| Transform-blind redaction, binary and screenshot frames, other routes to the browser, script-level exfiltration on an allowed origin, cross-origin iframe logins | Documented as accepted residual risk; README CDP claims corrected. Item 20 later closed script-level exfiltration (no agent script runs while the value is in the page) and cross-origin iframe logins fail (selectors resolve in the main document only); the rest stays documented |
| CA key readable on shared-filesystem deployments | Documented in the deploy guide |
