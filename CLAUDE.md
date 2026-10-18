# coatcheck

Credential broker sidecar for AI agents. The agent never holds real secrets: it asks coatcheck for a secret by name and gets a short-lived ticket (`cct_…`). Real values are substituted on the wire — in HTTPS requests (MITM `CONNECT` proxy) and in browser automation (CDP WebSocket proxy). Like a coat check: hand over the coat, get a ticket, the ticket is worthless outside the cloakroom.

## Origin

Extracted (with history, via `git filter-repo`) from a private monorepo, where it ran as an ECS Fargate sidecar next to each user's agent in a product that has since shut down. The deployment-specific values it carried (store path prefixes, `AGENT_LABEL`, CA subject, dashboard URL) are now configuration with neutral `coatcheck` defaults (`packages/core/src/config.ts`, `packages/provider-aws/src/index.ts`). Never reintroduce names, hostnames, or user data from that deployment.

Public repo, Apache-2.0. Published to npm as `@coatcheck/*` (see "Positioning").

## Positioning (decided)

- Closest prior art is [superfly/tokenizer](https://github.com/superfly/tokenizer) (stateless Go proxy, sealed secrets, per-secret `allowed_hosts`, HMAC/SigV4/JWT/OAuth processors, requires clients to send plain HTTP + `Proxy-Tokenizer` header). Don't compete on HTTP processors.
- coatcheck's differentiators: **browser/CDP credential injection** (headline), transparent `HTTPS_PROXY` MITM that works with unmodified tools, and by-name lookup from a secret backend.
- v1 ships with CDP injection.
- npm: unscoped `coatcheck` is taken → publish under `@coatcheck/*` (`core`, `provider-aws`, `provider-env`, later `provider-vault`, `provider-vercel`).

## Code map

npm workspaces (`packages/*`), TypeScript project references (`tsc -b`). Core never depends on a provider package; providers peer-depend on `@coatcheck/core`. Paths below are relative to `packages/core/src/` unless a package is named.

| File | Role |
|---|---|
| `cli.ts` | The `coatcheck` bin: reads `process.env`, `loadConfig` + `loadProvider`, calls `startCoatcheck`, startup log lines, SIGTERM |
| `start.ts` | `startCoatcheck({config, provider, adapters?})` (library API; `adapters` replaces the `COATCHECK_BROWSER_ADAPTERS` built-ins): builds `TokenStore`, CA, `CdpSessionStore`, `withCache`, listens on 3128, starts the CDP proxy; `close()` |
| `index.ts` | Public exports of `@coatcheck/core` |
| `load-provider.ts` | `loadProvider(name, ctx, importModule?)`: `aws`/`env`/`file` → `@coatcheck/provider-aws`, `@coatcheck/provider-env`, `@coatcheck/provider-env/file`; anything else is a module specifier; default export must be a `CreateProvider`; missing package → `ConfigError` naming it |
| `config.ts` | Pure `loadConfig(env)` → typed `Config`; every `COATCHECK_*` core setting (incl. `COATCHECK_MITM`, `COATCHECK_PASSTHROUGH_HOSTS`, `COATCHECK_ALLOW_UNBOUND_SECRETS`, `COATCHECK_MAX_SWAP_BODY_BYTES`); legacy names fail with "renamed to X"; non-loopback bind without `COATCHECK_API_TOKEN` fails; `ConfigError` lists all problems; `EnvReader` / `interpolateAgentId` are reused by providers |
| `policy.ts` | `COATCHECK_POLICY_FILE` parser (strict schema): per-secret `allowed_hosts` rules (exact or `prefix*`, exact > longest prefix) with optional `swap_body` / `swap_url` / `swap_headers`, and the `shared` allowlist for `/_secret/*` (`SharedRule {allowedHosts} & SwapSettings`); `policyRuleFor`, `policyHostsFor` |
| `host-matcher.ts` | Allowed-host patterns: exact, `*.suffix` (not apex, ≥2 labels), `http://` opt-in for plaintext, IP exact; normalised (lowercase, punycode); `matchesHost(patterns, {host, scheme})`, `intersectHostPatterns`, `formatHostPattern` |
| `secret-binding.ts` | Mint-time binding: `parseSecretValue` (simple / multi, `{value,_allowed_hosts}` is simple, `_`-keys are metadata; `_allowed_hosts`, `_swap_body`, `_swap_url`, `_swap_headers`), `parseSwapHeaders`, `DEFAULT_SWAP_HEADERS`, `resolveBinding` (policy ∩ in-band; unbound → 403 unless `COATCHECK_ALLOW_UNBOUND_SECRETS`; `swapBody`/`swapUrl` = either source true, neither false; `swapHeaders` = intersection when both set) |
| `server.ts` | `createCoatcheck(deps)`: side-effect-free factory for the proxy + vault API server (tests start it on port 0); routes absolute-form → forward, else vault API; applies the API token |
| `auth.ts` | `COATCHECK_API_TOKEN` checks: vault `Authorization: Bearer`, proxy `Proxy-Authorization` (Basic password or Bearer), constant-time; `/_health` + `/_ca` open; 401/407 responses |
| `mitm.ts` | `CONNECT` → MITM or passthrough per `COATCHECK_MITM` (`bound`: policy hosts, live-ticket hosts, adapter hosts; `always`) with `COATCHECK_PASSTHROUGH_HOSTS` overriding; ALPN `http/1.1` only; raw pipe after `101`; requests framed by `http1-framing.ts` (head cap 64 KiB → 431); backpressure (client paused while the upstream is full, pre-connect bytes > 1 MiB, or an upgrade is pending); header/URL token swap per placement (each field line's value with its header name; request line percent-encoded, header values with control chars → 403 `invalid-value`) on keep-alive requests; bodies stream unless `hasLiveBodyTicketFor`, then buffered up to `COATCHECK_MAX_SWAP_BODY_BYTES` (past it: streamed unscanned) for the opt-in body swap (`Content-Length` rewritten, chunked re-sent as one chunk); keyed on the CONNECT target; host mismatch → 403 + close tunnel; adapter response-rewrite wiring; on an adapter host (CDP on) every request body is buffered and refused with `403 uninspectable-body` unless it is plain JSON under the cap (`multipart/form-data` uploads excepted) |
| `forward.ts` | Plain-HTTP forward proxy: path/query/header swap per placement (+ body for `swap_body` tickets: streamed unless one is live for the host, else buffered up to the cap and re-sent with `Content-Length`) keyed on the URL host (plaintext needs `http://` entries); strips `proxy-authorization` + hop-by-hop; mismatch → 403 |
| `basic-auth.ts` | `swapBasicCredentials(store, value, target)` / `swapBasicFieldLine`: decode a canonical `Authorization: Basic` (never `Proxy-Authorization`), swap user-id and password via `replaceAll` at the `Authorization` location (same host binding / deny), re-encode (user-pass as latin1 so bytes round-trip, values inserted as UTF-8); `:` in a user-id value or control chars → `invalid`; non-canonical base64 left alone (still reported for the `miss` log); `userPass` (decoded, post-swap) feeds the `miss` log. Run before the header swap in `mitm.ts` and `forward.ts` |
| `body-swap.ts` | `swapRequestBody(store, body, {contentType, contentEncoding}, target)`: opt-in body swap (skips encoded bodies; JSON-escape / percent-encode / raw by content type; latin1 so bytes round-trip) |
| `swap-log.ts` | Structured swap-outcome lines per request (`hit`/`unbound`/`denied`/`invalid-value`/`body-skipped`/`placement-skipped`/`body-unscanned`/`miss`, and for signing `signed`/`signature-mismatch`/`unsignable`/`signing-skipped`; names, counts, ages; never values); `hostMismatchBody`, `signatureMismatchBody`, `unsignableBody` |
| `signing/processor.ts` | Signing processors (design `docs/design/signing-processors.md`): `planSigning(store, req, target)` finds a signing ticket used as a key in `Authorization` → `null` / `denied` (host-mismatch) / `unsignable` / a plan (`needsBody`, `ownedHeaders` the literal swap skips, `finalize(received, outgoing)`: verify the agent's signature, sign what goes out). Called by `mitm.ts` (before `swapHead`; body buffered when `needsBody`, past the cap → `403 unsignable`, signed last over the final head incl. `Content-Length`) and `forward.ts` |
| `signing/sigv4.ts` | Pure SigV4 (`node:crypto`): `parseSigV4Authorization` (SigV4a / malformed flagged), canonical URI (`s3` as sent, else normalised + encoded again), query, headers (SDK whitespace rules), `payloadMode` (`x-amz-content-sha256` → stream; absent → hash body; `STREAMING-AWS4-*` → unsignable), `finalizeSigV4` (verify with `AWS4`+ticket, re-sign with the real key, set/remove `x-amz-security-token`) |
| `signing/request.ts`, `signing/spec.ts`, `signing/types.ts` | `SignableRequest` (method, origin-form target, wire-order headers) from MITM field lines; `signing` / `_signing` parsing (`"aws-sigv4"`), the key fields `?field=` refuses, `signingCredentialFrom` (both AWS casings); `SigningCredential` |
| `ca.ts` | In-process ECDSA P-256 root CA + per-host leaf certs (`@peculiar/x509` on WebCrypto); leafs in an in-memory LRU; only the CA persists, and only when `COATCHECK_CA_DIR` is set |
| `http1-framing.ts` | MITM request framing (RFC 9112 §6): `parseRequestHead(head)` (request line, field lines, `header(name)`, framing: chunked / Content-Length / none; ambiguous → `invalid`, which `mitm.ts` answers `400 bad-framing` + close), incremental `ChunkedDecoder` (state across TLS records, linear time, trailer cap), `scanChunked` wrapper |
| `value-encoding.ts` | Where a real value lands: `percentEncodeUnsafe` (request line / path), `headerFieldValue` (refuses control chars → `invalid-value`) |
| `connect-target.ts` | Strict `CONNECT` target parser (RFC 1123 DNS name or IP literal, port 1–65535); invalid → 400 |
| `token-store.ts` | In-memory tickets (HTTP/S only), TTL 900s default; `issue(name, value, {ttlSeconds, allowedHosts, swapBody, swapUrl, swapHeaders, signing})` (a signing ticket is never substituted: `skipped` with `where: 'signing'`; `signingTicket(id)` looks one up); `replaceAll(input, {host, scheme}, location)` denies the whole request if any ticket is bound elsewhere, then swaps only where each ticket's placement allows (`Authorization`/`Proxy-Authorization` by default; else `skipped` with `where`); `replaceAllInBody` (only `swapBody` tickets, others → `skipped`); an encoder returning null → `invalid`; tickets found with one `TICKET_PATTERN` scan; `hasLiveBodyTicketFor`; `registerSessionValues(sid, values)`/`sessionValues(sid)`/`revokeSession(sid)` hold a CDP session's login values for inbound redaction (not tickets) |
| `vault-handler.ts` | `/_health`, `/_ca`, `/_vault*`, `/_secret/*` (a signing secret mints one credential ticket + `signing` in the response; `?field=` on its key field → 400; missing key → 500, no ticket), `POST /_vault/{name}/login` (broker login: live controller required via `VaultDeps.cdpSessionStore.controller`, else 404; maps `LoginResult`→status table; registers field values for redaction), OAuth `refresh`; multi-field JSON secrets + `_cleartext`; `InvalidSecretNameError` from a provider → 400 |
| `secret-provider.ts` | `SecretProvider` / `SecretStore` / `Secret` / `CreateProvider` interfaces, `withCache`, `InvalidSecretNameError`, secret-name validation (`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`, enforced in `vault-handler.ts` before any provider call) |
| `memory-provider.ts` | In-memory provider for tests and embedding (not selectable via `COATCHECK_PROVIDER`) |
| `json-response-rewriter.ts` | `createJsonResponseRewriter(transform)`: vendor-neutral HTTP/1.1 response framing (Content-Length, chunked → Content-Length) around a JSON transform |
| `browser-adapters.ts` | `BrowserAdapter {name, hosts, rewriteJson(body, register)}`; Browserbase adapter: rewrites every `ws(s)://…browserbase.com` value (parsed hostname) + any `ws(s)` `connectUrl`, deletes `signingKey` and live-view URLs; `COATCHECK_BROWSER_ADAPTERS` built-ins |
| `browserbase-rewrite.ts` | Retained `createConnectUrlRewriter` wrapper (key-based `connectUrl` rewrite) over `createJsonResponseRewriter` |
| `cdp-session-store.ts` | sid → real CDP URL + adapter name (`register(url, adapterName)`), 10 min TTL until connected; `markConnected` keeps it live until `revoke` (teardown); `has(sid)` |
| `cdp/proxy.ts` | WS proxy on 8444, `MAX_CONCURRENT=1`; `CdpConnection` per connection holds login-window state (attached page targets, agent new-document script ids, interception state, high-range (≥2³⁰) id multiplexer with pending map, agent frame queue, `waitForEvent`), attached to `CdpSessionStore` as the sid's `CdpController`; no outbound substitution (relays agent frames unchanged); teardown drops session redaction values |
| `cdp/login-driver.ts` | `runLogin(conn, req)`: broker-performed login — resolve page target, precheck origin/interception/busy, remove agent new-document scripts, reload to a fresh doc, re-check origin, fill each field (`DOM.focus`+clear+`Input.insertText`), submit (box-model click or Enter), wait for `until` (navigation/selector/urlPrefix), clear fields on timeout and success; returns `LoginResult` |
| `cdp/origin-tracker.ts` | Per flattened CDP `sessionId`: committed main-frame URL + `loaderId` from `Page.frameNavigated` (no `parentId`); `snapshot(sid)` for the driver; unknown while navigating (outbound `Page.navigate`/`reload`/`navigateToHistoryEntry`, inbound main-frame `frameStartedLoading`) or non-http(s) |
| `cdp/substitution.ts` | Inbound echo-back redaction/drop only (no outbound swap since item 20): matches each session value and its percent-, HTML-entity- and JSON-escaped forms |
| `cdp/e2e.test.ts` | Playwright + Chromium through the CDP proxy: full-page and SPA login via the controller succeed on the allowed origin, refused elsewhere (403); fields empty after timeout; pre-installed listener and new-document script see nothing; interception → 409; the four transform reads yield no password (CI installs Chromium) |
| `packages/provider-aws/src/index.ts` | **The only AWS-coupled package**; `loadAwsConfig` parses `COATCHECK_AWS_*` (prefixes with `{agentId}`, role ARN, `EXTERNAL_ID` (sent on AssumeRole; requires a role ARN; never echoed), session name); `awsConfigWarnings` (role without ExternalId → startup warning from the default export): SSM (per-agent secrets: get/exists/put/list), Secrets Manager (shared secrets), STS AssumeRole; `awsErrorCode` checks `err.name` and `err.Code` |
| `packages/provider-env/src/index.ts` | `env` provider: `[a-z0-9-]+` names only (`github-token` ↔ `COATCHECK_SECRET_GITHUB_TOKEN`; others → `InvalidSecretNameError`), shared via `COATCHECK_SHARED_SECRET_`, read-only, env snapshotted at startup |
| `packages/provider-env/src/file.ts` | `file` provider (`./file` export): `COATCHECK_SECRETS_FILE` JSON `{secrets, shared}`, re-read per call, `put` = temp file + rename (0600), writes serialised |

## Known security gaps (fix before going public)

1. ~~**Tickets are not bound to destination hosts**~~ — fixed on HTTP(S) (roadmap item 9): tickets snapshot allowed hosts (policy ∩ in-band `_allowed_hosts`), unbound secrets are refused at mint, and the MITM/forward paths deny mismatches with `403`. On CDP there are no credential tickets at all: coatcheck performs the login itself (roadmap item 20, `docs/design/cdp-broker-login.md`), checking the page's committed origin against the login secret's allowed hosts.
2. ~~**Shell injection / path traversal in `ca.ts`**~~ — fixed: strict `CONNECT` target validation (`connect-target.ts`) and in-process cert generation (`ca.ts`, no `openssl`).
3. ~~**Plain-HTTP forward path also swaps**~~ — fixed with gap 1: plaintext only matches `http://` entries, so an agent-run loopback listener never receives a value (test in `server.test.ts`).
4. **The AWS "sidecar assumes a separate role" pattern the original deployment used was bypassable** — both containers in an ECS task share one task role, and that role was allowed `sts:AssumeRole` on the proxy role, so the agent could assume it directly. `docs/THREAT_MODEL.md` documents correct patterns (separate task, ExternalId only injected into the sidecar, blocking 169.254.170.2); `docs/deploy/aws-ecs.md` is the reference deployment and provider-aws supports `COATCHECK_AWS_EXTERNAL_ID` (warns without it). Any AWS deployment guide/provider must not repeat this.

Full list with severities: `docs/THREAT_MODEL.md`. Proxy integration tests (MITM, passthrough, forward, `connectUrl` rewrite): `packages/core/src/server.test.ts`; signing: `packages/core/src/signing.server.test.ts` (helpers in `test-helpers.ts`, excluded from the package; SigV4 suite vectors in `signing/__fixtures__/`).

## Commands

```bash
npm install
npm run lint && npm run type-check && npm test && npm run build
COATCHECK_PROVIDER=env COATCHECK_SECRET_DEMO=x npm run dev   # tsx on packages/core/src/cli.ts (source export condition, no build)
docker compose -f examples/docker-compose.env.yml up --build          # zero-AWS quickstart
docker compose -f examples/docker-compose.localstack.yml up --build   # LocalStack-backed demo
```

## Conventions

- TypeScript strict, ESM, Node16 resolution, Node ≥ 24 (CI: 24 LTS + 26). vitest for tests (one project per package, root `vitest.config.ts`), colocated `*.test.ts`. Move files with `git mv`.
- Never log secret values, ticket IDs, or request bodies — only secret names, counts, ages.
- Signing processors never log canonical requests, strings-to-sign, signatures or key material.
- Only `packages/core/src/config.ts` and `cli.ts` read `process.env` (eslint `no-restricted-properties`); providers get env via `ProviderContext`.
- When catching AWS SDK errors, check `err.name` **and** `err.Code` (newer `@aws-sdk/core` puts the code on `Code`; varies by service).
- Security-relevant changes need tests that demonstrate the attack is blocked.
