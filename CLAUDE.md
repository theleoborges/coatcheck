# coatcheck

Credential broker sidecar for AI agents. The agent never holds real secrets: it asks coatcheck for a secret by name and gets a short-lived ticket (`tok_…`). Real values are substituted on the wire — in HTTPS requests (MITM `CONNECT` proxy) and in browser automation (CDP WebSocket proxy). Like a coat check: hand over the coat, get a ticket, the ticket is worthless outside the cloakroom.

## Origin

Extracted (with history, via `git filter-repo`) from `packages/secret-proxy` in a private monorepo for Liv, an AI chief-of-staff product that has since shut down. In Liv it ran as an ECS Fargate sidecar next to each user's agent. Some code still carries Liv-isms (secret path `/liv/agents/{label}/user-secrets/`, Secrets Manager prefix `liv/`, `AGENT_LABEL`, CA subject) — these are scheduled to become configuration (see `docs/ROADMAP.md`). Never reintroduce Liv-specific names, hostnames, or user data.

Repo is **private** until we're ready to publish. Target license Apache-2.0.

## Positioning (decided)

- Closest prior art is [superfly/tokenizer](https://github.com/superfly/tokenizer) (stateless Go proxy, sealed secrets, per-secret `allowed_hosts`, HMAC/SigV4/JWT/OAuth processors, requires clients to send plain HTTP + `Proxy-Tokenizer` header). Don't compete on HTTP processors.
- coatcheck's differentiators: **browser/CDP credential injection** (headline), transparent `HTTPS_PROXY` MITM that works with unmodified tools, and by-name lookup from a secret backend.
- v1 ships with CDP injection.
- npm: unscoped `coatcheck` is taken → publish under `@coatcheck/*` (`core`, `provider-aws`, `provider-env`, later `provider-vault`, `provider-vercel`).

## Code map

| File | Role |
|---|---|
| `src/index.ts` | HTTP server on 3128: vault API routing, plain-HTTP forwarding, `CONNECT` → MITM (only when token store non-empty) or passthrough; header/URL token swap; swap-outcome logging |
| `src/ca.ts` | Self-signed root CA + per-host leaf certs via `openssl` `execSync` (**unsafe**: hostname unvalidated) |
| `src/token-store.ts` | In-memory tickets, TTL 900s default, optional CDP session binding, `replaceAll` / `replaceAllForSession` |
| `src/vault-handler.ts` | `/_health`, `/_ca`, `/_vault*`, `/_secret/*`, `mint-tokens`, OAuth `refresh`; multi-field JSON secrets + `_cleartext` |
| `src/secret-fetcher.ts` | **The only AWS-coupled file**: SSM (user vault get/exists/put/list), Secrets Manager (shared secrets), STS AssumeRole. Will move behind a `SecretProvider` interface |
| `src/browserbase-rewrite.ts` | Rewrites `connectUrl` in `api.browserbase.com` responses to the local CDP proxy (first "browser adapter") |
| `src/cdp-session-store.ts` | sid → real connect URL, 10 min TTL |
| `src/cdp/proxy.ts` | WS proxy on 8444, `MAX_CONCURRENT=1`, teardown revokes session tickets |
| `src/cdp/substitution.ts` | Outbound swap in `Input.insertText`, `Runtime.evaluate`, `Runtime.callFunctionOn`; inbound echo-back redaction/drop |
| `src/cdp/keystroke-detector.ts` | Fails closed on `page.type()` (keystroke-by-keystroke ticket entry) |

## Known security gaps (fix before going public)

1. **Tickets are not bound to destination hosts** — `swapTokensInRawHeaders` (`src/index.ts`) gets the hostname but only logs it. A ticket sent to any host gets the real value. Fix: per-secret allowed hosts/pattern, enforced at swap time (HTTP and CDP).
2. **Shell injection / path traversal in `src/ca.ts`** — `CONNECT` hostname interpolated into `execSync` openssl commands and file paths. Fix: in-process cert generation (`@peculiar/x509` or `node-forge`) + hostname validation.
3. **Plain-HTTP forward path also swaps** — `curl -x proxy http://127.0.0.1:<agent-listener>/?k=tok_…` hands the agent the plaintext without leaving the box, so egress enforcement alone doesn't close gap 1. Host binding must cover the HTTP path too.
4. **The AWS "sidecar assumes a separate role" pattern Liv used was bypassable** — both containers in an ECS task share one task role, and that role was allowed `sts:AssumeRole` on the proxy role, so the agent could assume it directly. `docs/THREAT_MODEL.md` documents correct patterns (separate task, ExternalId only injected into the sidecar, blocking 169.254.170.2). Any AWS deployment guide/provider must not repeat this.

Full list with severities: `docs/THREAT_MODEL.md`. Untested: `src/index.ts` MITM path and `src/ca.ts`.

## Commands

```bash
npm install
npm run lint && npm run type-check && npm test && npm run build
npm run dev                                           # tsx src/index.ts (needs AGENT_LABEL + AWS/LocalStack)
docker compose -f docker-compose.example.yml up --build   # LocalStack-backed demo
```

## Conventions

- TypeScript strict, ESM, Node16 resolution, Node ≥ 20. vitest for tests, colocated `*.test.ts`.
- Never log secret values, ticket IDs, or request bodies — only secret names, counts, ages.
- When catching AWS SDK errors, check `err.name` **and** `err.Code` (newer `@aws-sdk/core` puts the code on `Code`; varies by service).
- Security-relevant changes need tests that demonstrate the attack is blocked.
