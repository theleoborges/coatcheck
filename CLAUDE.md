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
| `src/config.ts` | Pure `loadConfig(env)` → typed `Config`; every `COATCHECK_*` core setting; legacy names fail with "renamed to X"; `ConfigError` lists all problems |
| `src/providers/index.ts` | `loadProvider(name, ctx)`: `COATCHECK_PROVIDER` → provider factory |
| `src/server.ts` | `createCoatcheck(deps)`: side-effect-free factory for the proxy + vault API server (tests start it on port 0) |
| `src/mitm.ts` | `CONNECT` → MITM (only when token store non-empty) or passthrough; header/URL token swap on keep-alive requests; `connectUrl` rewrite wiring |
| `src/forward.ts` | Plain-HTTP forward proxy with URL/header token swap |
| `src/swap-log.ts` | One structured swap-outcome line per request (names, counts, ages; never values) |
| `src/ca.ts` | In-process ECDSA P-256 root CA + per-host leaf certs (`@peculiar/x509` on WebCrypto); leafs in an in-memory LRU; only the CA persists, and only when `CA_DIR` is set |
| `src/connect-target.ts` | Strict `CONNECT` target parser (RFC 1123 DNS name or IP literal, port 1–65535); invalid → 400 |
| `src/token-store.ts` | In-memory tickets, TTL 900s default, optional CDP session binding, `replaceAll` / `replaceAllForSession` |
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

1. **Tickets are not bound to destination hosts** — the MITM path (`src/mitm.ts`) knows the hostname but only logs it. A ticket sent to any host gets the real value. Fix: per-secret allowed hosts/pattern, enforced at swap time (HTTP and CDP).
2. ~~**Shell injection / path traversal in `src/ca.ts`**~~ — fixed: strict `CONNECT` target validation (`src/connect-target.ts`) and in-process cert generation (`src/ca.ts`, no `openssl`).
3. **Plain-HTTP forward path also swaps** — `curl -x proxy http://127.0.0.1:<agent-listener>/?k=cct_…` hands the agent the plaintext without leaving the box, so egress enforcement alone doesn't close gap 1. Host binding must cover the HTTP path too.
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
