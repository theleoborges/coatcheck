# coatcheck

Credential broker sidecar for AI agents. The agent never holds real secrets: it asks coatcheck for a secret by name and gets a short-lived ticket (`cct_…`). Real values are substituted on the wire — in HTTPS requests (MITM `CONNECT` proxy) and in browser automation (CDP WebSocket proxy). Like a coat check: hand over the coat, get a ticket, the ticket is worthless outside the cloakroom.

## Origin

Extracted (with history, via `git filter-repo`) from `packages/secret-proxy` in a private monorepo for Liv, an AI chief-of-staff product that has since shut down. In Liv it ran as an ECS Fargate sidecar next to each user's agent. The deployment-specific values it carried (store path prefixes, `AGENT_LABEL`, CA subject, dashboard URL) are now configuration with neutral `coatcheck` defaults (`packages/core/src/config.ts`, `packages/provider-aws/src/index.ts`). Never reintroduce Liv-specific names, hostnames, or user data.

Repo is **private** until we're ready to publish. Target license Apache-2.0.

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
| `config.ts` | Pure `loadConfig(env)` → typed `Config`; every `COATCHECK_*` core setting (incl. `COATCHECK_MITM`, `COATCHECK_PASSTHROUGH_HOSTS`, `COATCHECK_ALLOW_UNBOUND_SECRETS`); legacy names fail with "renamed to X"; non-loopback bind without `COATCHECK_API_TOKEN` fails; `ConfigError` lists all problems; `EnvReader` / `interpolateAgentId` are reused by providers |
| `policy.ts` | `COATCHECK_POLICY_FILE` parser (strict schema): per-secret `allowed_hosts` rules (exact or `prefix*`, exact > longest prefix) and the `shared` allowlist for `/_secret/*`; `policyHostsFor` |
| `host-matcher.ts` | Allowed-host patterns: exact, `*.suffix` (not apex, ≥2 labels), `http://` opt-in for plaintext, IP exact; normalised (lowercase, punycode); `matchesHost(patterns, {host, scheme})`, `intersectHostPatterns`, `formatHostPattern` |
| `secret-binding.ts` | Mint-time binding: `parseSecretValue` (simple / multi, `{value,_allowed_hosts}` is simple, `_`-keys are metadata), `resolveBinding` (policy ∩ in-band; unbound → 403 unless `COATCHECK_ALLOW_UNBOUND_SECRETS`) |
| `server.ts` | `createCoatcheck(deps)`: side-effect-free factory for the proxy + vault API server (tests start it on port 0); routes absolute-form → forward, else vault API; applies the API token |
| `auth.ts` | `COATCHECK_API_TOKEN` checks: vault `Authorization: Bearer`, proxy `Proxy-Authorization` (Basic password or Bearer), constant-time; `/_health` + `/_ca` open; 401/407 responses |
| `mitm.ts` | `CONNECT` → MITM or passthrough per `COATCHECK_MITM` (`bound`: policy hosts, live-ticket hosts, adapter hosts; `always`) with `COATCHECK_PASSTHROUGH_HOSTS` overriding; ALPN `http/1.1` only; raw pipe after `101`; requests framed by `http1-framing.ts`; header/URL token swap on keep-alive requests, keyed on the CONNECT target; host mismatch → 403 + close tunnel; adapter response-rewrite wiring |
| `forward.ts` | Plain-HTTP forward proxy: path/query/header swap keyed on the URL host (plaintext needs `http://` entries); strips `proxy-authorization` + hop-by-hop; mismatch → 403 |
| `swap-log.ts` | Structured swap-outcome lines per request (`hit`/`unbound`/`denied`/`miss`; names, counts, ages; never values); `hostMismatchBody` |
| `ca.ts` | In-process ECDSA P-256 root CA + per-host leaf certs (`@peculiar/x509` on WebCrypto); leafs in an in-memory LRU; only the CA persists, and only when `COATCHECK_CA_DIR` is set |
| `http1-framing.ts` | MITM request framing (RFC 9112 §6): `requestFraming(head)` (chunked / Content-Length / none; ambiguous → `invalid`, which `mitm.ts` answers `400 bad-framing` + close), `scanChunked(buf, start)` (decoded data, raw trailers, end offset) |
| `connect-target.ts` | Strict `CONNECT` target parser (RFC 1123 DNS name or IP literal, port 1–65535); invalid → 400 |
| `token-store.ts` | In-memory tickets, TTL 900s default; `issue(name, value, {ttlSeconds, allowedHosts, sessionId})`; `replaceAll(input, {host, scheme})` denies the whole request if any ticket is bound elsewhere; `replaceAllForSession(input, sid, origin)` (CDP; denies on mismatch or unknown origin) |
| `vault-handler.ts` | `/_health`, `/_ca`, `/_vault*`, `/_secret/*`, `mint-tokens` (live sid required via `VaultDeps.cdpSessionStore`, else 404), OAuth `refresh`; multi-field JSON secrets + `_cleartext`; `InvalidSecretNameError` from a provider → 400 |
| `secret-provider.ts` | `SecretProvider` / `SecretStore` / `Secret` / `CreateProvider` interfaces, `withCache`, `InvalidSecretNameError`, secret-name validation (`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`, enforced in `vault-handler.ts` before any provider call) |
| `memory-provider.ts` | In-memory provider for tests and embedding (not selectable via `COATCHECK_PROVIDER`) |
| `json-response-rewriter.ts` | `createJsonResponseRewriter(transform)`: vendor-neutral HTTP/1.1 response framing (Content-Length, chunked → Content-Length) around a JSON transform |
| `browser-adapters.ts` | `BrowserAdapter {name, hosts, rewriteJson(body, register)}`; Browserbase adapter: rewrites every `ws(s)://…browserbase.com` value (parsed hostname) + any `ws(s)` `connectUrl`, deletes `signingKey` and live-view URLs; `COATCHECK_BROWSER_ADAPTERS` built-ins |
| `browserbase-rewrite.ts` | Retained `createConnectUrlRewriter` wrapper (key-based `connectUrl` rewrite) over `createJsonResponseRewriter` |
| `cdp-session-store.ts` | sid → real CDP URL + adapter name (`register(url, adapterName)`), 10 min TTL until connected; `markConnected` keeps it live until `revoke` (teardown); `has(sid)` |
| `cdp/proxy.ts` | WS proxy on 8444, `MAX_CONCURRENT=1`, teardown revokes session tickets |
| `cdp/origin-tracker.ts` | Per flattened CDP `sessionId`: committed main-frame URL from `Page.frameNavigated` (no `parentId`); unknown while navigating (outbound `Page.navigate`/`reload`/`navigateToHistoryEntry`, inbound main-frame `frameStartedLoading`) or non-http(s) |
| `cdp/substitution.ts` | Outbound swap **only** in `Input.insertText`, gated on the tracked origin (deny → drop frame + CDP error with `id`/`sessionId`); never `Runtime.*`; inbound echo-back redaction/drop |
| `cdp/e2e.test.ts` | Playwright + Chromium through the CDP proxy: `fill` works on text/email/password on the allowed origin, refused elsewhere (CI installs Chromium) |
| `cdp/keystroke-detector.ts` | Fails closed on `page.type()` (keystroke-by-keystroke ticket entry) |
| `packages/provider-aws/src/index.ts` | **The only AWS-coupled package**; `loadAwsConfig` parses `COATCHECK_AWS_*` (prefixes with `{agentId}`, role ARN, session name): SSM (per-agent secrets: get/exists/put/list), Secrets Manager (shared secrets), STS AssumeRole; `awsErrorCode` checks `err.name` and `err.Code` |
| `packages/provider-env/src/index.ts` | `env` provider: `[a-z0-9-]+` names only (`github-token` ↔ `COATCHECK_SECRET_GITHUB_TOKEN`; others → `InvalidSecretNameError`), shared via `COATCHECK_SHARED_SECRET_`, read-only, env snapshotted at startup |
| `packages/provider-env/src/file.ts` | `file` provider (`./file` export): `COATCHECK_SECRETS_FILE` JSON `{secrets, shared}`, re-read per call, `put` = temp file + rename (0600), writes serialised |

## Known security gaps (fix before going public)

1. ~~**Tickets are not bound to destination hosts**~~ — fixed on HTTP(S) (roadmap item 9): tickets snapshot allowed hosts (policy ∩ in-band `_allowed_hosts`), unbound secrets are refused at mint, and the MITM/forward paths deny mismatches with `403`. CDP tickets are bound to the page's main-frame origin (roadmap item 15).
2. ~~**Shell injection / path traversal in `ca.ts`**~~ — fixed: strict `CONNECT` target validation (`connect-target.ts`) and in-process cert generation (`ca.ts`, no `openssl`).
3. ~~**Plain-HTTP forward path also swaps**~~ — fixed with gap 1: plaintext only matches `http://` entries, so an agent-run loopback listener never receives a value (test in `server.test.ts`).
4. **The AWS "sidecar assumes a separate role" pattern Liv used was bypassable** — both containers in an ECS task share one task role, and that role was allowed `sts:AssumeRole` on the proxy role, so the agent could assume it directly. `docs/THREAT_MODEL.md` documents correct patterns (separate task, ExternalId only injected into the sidecar, blocking 169.254.170.2). Any AWS deployment guide/provider must not repeat this.

Full list with severities: `docs/THREAT_MODEL.md`. Proxy integration tests (MITM, passthrough, forward, `connectUrl` rewrite): `packages/core/src/server.test.ts`.

## Commands

```bash
npm install
npm run lint && npm run type-check && npm test && npm run build
COATCHECK_PROVIDER=env COATCHECK_SECRET_DEMO=x npm run dev   # tsx on packages/core/src/cli.ts (source export condition, no build)
docker compose -f examples/docker-compose.env.yml up --build          # zero-AWS quickstart
docker compose -f examples/docker-compose.localstack.yml up --build   # LocalStack-backed demo
```

## Conventions

- TypeScript strict, ESM, Node16 resolution, Node ≥ 20. vitest for tests (one project per package, root `vitest.config.ts`), colocated `*.test.ts`. Move files with `git mv`.
- Never log secret values, ticket IDs, or request bodies — only secret names, counts, ages.
- Only `packages/core/src/config.ts` and `cli.ts` read `process.env` (eslint `no-restricted-properties`); providers get env via `ProviderContext`.
- When catching AWS SDK errors, check `err.name` **and** `err.Code` (newer `@aws-sdk/core` puts the code on `Code`; varies by service).
- Security-relevant changes need tests that demonstrate the attack is blocked.
