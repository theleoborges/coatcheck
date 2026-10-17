# Roadmap

Ordered by priority. Security fixes come first; see `docs/THREAT_MODEL.md`
for the gaps they close.

1. **Host-bound tickets.** Each secret declares where its value may go:
   `allowed_hosts` (exact hosts and/or a suffix pattern such as
   `*.example.com`). A ticket substitutes only when the CONNECT target (or
   forward-proxy URL host) matches; otherwise it is left as a literal and the
   miss is logged. Match on the actual upstream, never the `Host` header.
   Secrets without a policy keep today's behaviour behind an explicit
   opt-out flag. The model is inspired by
   [superfly/tokenizer](https://github.com/superfly/tokenizer). Extending it
   to CDP means origin binding on `Page.frameNavigated`.

2. **In-process certificate generation.** Replace the `openssl` shell-outs in
   `src/ca.ts` with an in-process implementation (e.g. `node-forge` or
   `@peculiar/x509`), validate CONNECT hostnames as DNS names or IP literals
   in `src/index.ts`, and stop writing per-host key files to disk.

3. **Ticket prefix `tok_` → `ck_`.** A distinctive prefix makes tickets easy
   to grep for and to register with secret scanners. Accept both prefixes for
   one release.

4. **Pluggable secret providers.** Replace the AWS-specific `SecretFetcher`
   with:

   ```ts
   interface SecretStore {
     get(name: string): Promise<string | null>;
     exists(name: string): Promise<boolean>;
     list(): Promise<string[]>;
     put?(name: string, value: string): Promise<void>; // needed for OAuth refresh
   }

   interface SecretProvider {
     user: SecretStore;                    // per-agent secrets
     fleet: Pick<SecretStore, 'get'>;      // shared, allowlisted secrets
   }
   ```

   plus a `withCache(store, ttlMs)` decorator (today's 5-minute cache).
   Providers:
   - `aws`: SSM Parameter Store for the user store, Secrets Manager for shared
     secrets, optional STS AssumeRole for the broker identity;
   - `env` / `file`: local development and tests;
   - later: HashiCorp Vault, Vercel.

   Published as `@coatcheck/core`, `@coatcheck/provider-aws`,
   `@coatcheck/provider-env`.

5. **Make deployment-specific choices configurable.**
   - Browser adapter as a plugin (host + response rewriter; see
     `docs/design/cdp-injection.md`), Browserbase as the first adapter.
   - Shared-secret allowlist (today hard-coded in `src/vault-handler.ts`).
   - Secret store paths/prefixes (today hard-coded in
     `src/secret-fetcher.ts`).
   - CA certificate subject (today hard-coded in `src/ca.ts`).
   - Dashboard URL returned in 404 hints (`vault_url`).
   - `AGENT_LABEL`: today required at startup; make it optional, used only
     when a provider needs it.

6. **Coverage of the swap path.**
   - Request body substitution, opt-in per secret, with correct
     `Content-Length` rewriting.
   - Chunked request bodies in the MITM parser (`src/index.ts` TODO).
   - Tests for the `src/index.ts` MITM path (keep-alive, passthrough vs MITM,
     `connectUrl` rewrite wiring) and for `src/ca.ts`.

7. ~~**Remove the unused `http-proxy` dependency.**~~ Done during extraction
   (dependency, `@types/http-proxy` and lockfile).

8. **`docs/deploy/aws-ecs.md`.** Reference deployment: sidecar task
   definition, health-gated startup, CA trust in the agent entrypoint,
   explicit deny on the agent task role, broker role and how to keep the agent
   from assuming it, egress rules.
