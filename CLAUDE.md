# coatcheck

Credential broker sidecar for AI agents. The agent never holds real secrets: it asks coatcheck for a secret by name and gets a short-lived ticket (`cct_…`). Real values are substituted on the wire — in HTTPS requests (MITM `CONNECT` proxy) and in browser automation (CDP WebSocket proxy). Like a coat check: hand over the coat, get a ticket, the ticket is worthless outside the cloakroom.

## Origin

Extracted (with history, via `git filter-repo`) from `packages/secret-proxy` in a private monorepo for Liv, an AI chief-of-staff product that has since shut down. In Liv it ran as an ECS Fargate sidecar next to each user's agent. The deployment-specific values it carried (store path prefixes, `AGENT_LABEL`, CA subject, dashboard URL) are now configuration with neutral `coatcheck` defaults (`src/config.ts`, `src/providers/aws.ts`). Never reintroduce Liv-specific names, hostnames, or user data.

Repo is **private** until we're ready to publish. Target license Apache-2.0.

## Positioning (decided)

- Closest prior art is [superfly/tokenizer](https://github.com/superfly/tokenizer) (stateless Go proxy, sealed secrets, per-secret `allowed_hosts`, HMAC/SigV4/JWT/OAuth processors, requires clients to send plain HTTP + `Proxy-Tokenizer` header). Don't compete on HTTP processors.
- coatcheck's differentiators: **browser/CDP credential injection** (headline), transparent `HTTPS_PROXY` MITM that works with unmodified tools, and by-name lookup from a secret backend.
- v1 ships with CDP injection.
- npm: unscoped `coatcheck` is taken → publish under `@coatcheck/*` (`core`, `provider-aws`, `provider-env`, later `provider-vault`, `provider-vercel`).

## Code map

| File | Role |
|---|---|
| `src/index.ts` | Entrypoint: loads config + provider, builds deps, listens on 3128, starts the CDP proxy, SIGTERM |
| `src/config.ts` | Pure `loadConfig(env)` → typed `Config`; every `COATCHECK_*` core setting (incl. `COATCHECK_MITM`, `COATCHECK_PASSTHROUGH_HOSTS`, `COATCHECK_ALLOW_UNBOUND_SECRETS`); legacy names fail with "renamed to X"; `ConfigError` lists all problems |
| `src/policy.ts` | `COATCHECK_POLICY_FILE` parser (strict schema): per-secret `allowed_hosts` rules (exact or `prefix*`, exact > longest prefix) and the `shared` allowlist for `/_secret/*`; `policyHostsFor` |
| `src/host-matcher.ts` | Allowed-host patterns: exact, `*.suffix` (not apex, ≥2 labels), `http://` opt-in for plaintext, IP exact; normalised (lowercase, punycode); `matchesHost(patterns, {host, scheme})`, `intersectHostPatterns`, `formatHostPattern` |
| `src/secret-binding.ts` | Mint-time binding: `parseSecretValue` (simple / multi, `{value,_allowed_hosts}` is simple, `_`-keys are metadata), `resolveBinding` (policy ∩ in-band; unbound → 403 unless `COATCHECK_ALLOW_UNBOUND_SECRETS`) |
| `src/providers/index.ts` | `loadProvider(name, ctx)`: `COATCHECK_PROVIDER` → provider factory |
| `src/server.ts` | `createCoatcheck(deps)`: side-effect-free factory for the proxy + vault API server (tests start it on port 0) |
| `src/mitm.ts` | `CONNECT` → MITM or passthrough per `COATCHECK_MITM` (`bound`: policy hosts, live-ticket hosts, adapter host; `always`) with `COATCHECK_PASSTHROUGH_HOSTS` overriding; ALPN `http/1.1` only; raw pipe after `101`; header/URL token swap on keep-alive requests, keyed on the CONNECT target; host mismatch → 403 + close tunnel; `connectUrl` rewrite wiring |
| `src/forward.ts` | Plain-HTTP forward proxy: path/query/header swap keyed on the URL host (plaintext needs `http://` entries); strips `proxy-authorization` + hop-by-hop; mismatch → 403 |
| `src/swap-log.ts` | Structured swap-outcome lines per request (`hit`/`unbound`/`denied`/`miss`; names, counts, ages; never values); `hostMismatchBody` |
| `src/ca.ts` | In-process ECDSA P-256 root CA + per-host leaf certs (`@peculiar/x509` on WebCrypto); leafs in an in-memory LRU; only the CA persists, and only when `CA_DIR` is set |
| `src/connect-target.ts` | Strict `CONNECT` target parser (RFC 1123 DNS name or IP literal, port 1–65535); invalid → 400 |
| `src/token-store.ts` | In-memory tickets, TTL 900s default; `issue(name, value, {ttlSeconds, allowedHosts, sessionId})`; `replaceAll(input, {host, scheme})` denies the whole request if any ticket is bound elsewhere; `replaceAllForSession` (CDP; origin check is roadmap item 15) |
| `src/vault-handler.ts` | `/_health`, `/_ca`, `/_vault*`, `/_secret/*`, `mint-tokens`, OAuth `refresh`; multi-field JSON secrets + `_cleartext` |
| `src/secret-provider.ts` | `SecretProvider` / `SecretStore` / `Secret` interfaces, `withCache`, secret-name validation (`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`, enforced in `vault-handler.ts` before any provider call) |
| `src/providers/aws.ts` | **The only AWS-coupled file**; `loadAwsConfig` parses `COATCHECK_AWS_*` (prefixes with `{agentId}`, role ARN, session name): SSM (per-agent secrets: get/exists/put/list), Secrets Manager (shared secrets), STS AssumeRole; `awsErrorCode` checks `err.name` and `err.Code` |
| `src/providers/memory.ts` | In-memory provider for tests and embedding |
| `src/browserbase-rewrite.ts` | Rewrites `connectUrl` in `api.browserbase.com` responses to the local CDP proxy (first "browser adapter") |
| `src/cdp-session-store.ts` | sid → real connect URL, 10 min TTL |
| `src/cdp/proxy.ts` | WS proxy on 8444, `MAX_CONCURRENT=1`, teardown revokes session tickets |
| `src/cdp/substitution.ts` | Outbound swap in `Input.insertText`, `Runtime.evaluate`, `Runtime.callFunctionOn`; inbound echo-back redaction/drop |
| `src/cdp/keystroke-detector.ts` | Fails closed on `page.type()` (keystroke-by-keystroke ticket entry) |

## Known security gaps (fix before going public)

1. ~~**Tickets are not bound to destination hosts**~~ — fixed on HTTP(S) (roadmap item 9): tickets snapshot allowed hosts (policy ∩ in-band `_allowed_hosts`), unbound secrets are refused at mint, and the MITM/forward paths deny mismatches with `403`. CDP origin binding is still open (roadmap item 15).
2. ~~**Shell injection / path traversal in `src/ca.ts`**~~ — fixed: strict `CONNECT` target validation (`src/connect-target.ts`) and in-process cert generation (`src/ca.ts`, no `openssl`).
3. ~~**Plain-HTTP forward path also swaps**~~ — fixed with gap 1: plaintext only matches `http://` entries, so an agent-run loopback listener never receives a value (test in `src/server.test.ts`).
4. **The AWS "sidecar assumes a separate role" pattern Liv used was bypassable** — both containers in an ECS task share one task role, and that role was allowed `sts:AssumeRole` on the proxy role, so the agent could assume it directly. `docs/THREAT_MODEL.md` documents correct patterns (separate task, ExternalId only injected into the sidecar, blocking 169.254.170.2). Any AWS deployment guide/provider must not repeat this.

Full list with severities: `docs/THREAT_MODEL.md`. Proxy integration tests (MITM, passthrough, forward, `connectUrl` rewrite): `src/server.test.ts`.

## Commands

```bash
npm install
npm run lint && npm run type-check && npm test && npm run build
COATCHECK_PROVIDER=aws npm run dev                    # tsx src/index.ts (needs AWS creds/region or LocalStack via AWS_ENDPOINT_URL)
docker compose -f docker-compose.example.yml up --build   # LocalStack-backed demo
```

## Conventions

- TypeScript strict, ESM, Node16 resolution, Node ≥ 20. vitest for tests, colocated `*.test.ts`.
- Never log secret values, ticket IDs, or request bodies — only secret names, counts, ages.
- Only `src/config.ts` and the entrypoint read `process.env` (eslint `no-restricted-properties`); providers get env via `ProviderContext`.
- When catching AWS SDK errors, check `err.name` **and** `err.Code` (newer `@aws-sdk/core` puts the code on `Code`; varies by service).
- Security-relevant changes need tests that demonstrate the attack is blocked.
