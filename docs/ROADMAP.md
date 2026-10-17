# Roadmap

Ordered by dependency. Security fixes come as early as their dependencies
allow.

Every item is one PR. Each PR:
- leaves CI green (lint, type-check, test, build, Docker build);
- updates README.md and docs/THREAT_MODEL.md wherever it changes behaviour.

Security fixes include a test that performs the attack and shows it is
blocked. The decisions behind this list, and the alternatives that were
rejected, are in `docs/design/v1-decisions.md`.

## Phase 1: shell injection (HIGH)

1. **[Done]** **Validate CONNECT targets.** Parse `host:port` strictly:
   - the host must be a DNS name (RFC 1123 labels, at most 253 chars) or an
     IP literal (`net.isIP`, with IPv6 in brackets);
   - the port must be 1–65535.

   Anything else gets `400`. Tests cover `$(…)`, backticks, `;`, `|`, `/`,
   `..`, and empty or over-long labels.

2. **[Done]** **In-process certificate generation.** Replace the `openssl` shell-outs in
   `src/ca.ts` with `@peculiar/x509` on Node WebCrypto, ECDSA P-256.
   - Leaf certs stay in memory (LRU, cap 1000), and IP targets get an IP SAN.
   - Only the CA key and cert are ever written to disk, and only when a CA
     directory is configured.
   - No RSA compatibility: a persisted CA that isn't ECDSA P-256 fails startup
     with a message to delete it.
   - Remove `openssl` and `ca-certificates` from both Dockerfiles.
   - Add `src/ca.test.ts`:
     - the chain verifies with `crypto.X509Certificate`;
     - SAN and EKU are correct;
     - no leaf files are written.

## Phase 2: foundations

3. **[Done]** **Make the proxy testable.** Split `src/index.ts` into a side-effect-free
   `createCoatcheck(deps)` factory and modules for the MITM handler, the
   plain-HTTP forwarder, and swap logging. Add tests for keep-alive,
   passthrough vs MITM, `connectUrl` rewrite wiring, and the forward path.
   No behaviour change.

4. **[Done]** **Ticket prefix `tok_` → `cct_`.** Export one `TICKET_PREFIX` /
   `TICKET_PATTERN`, and use it in the token store, swap logging, and the CDP
   outbound pre-filter (which hard-codes `'tok_'` today). There is no
   dual-prefix window: tickets live only in memory and never survive a
   restart. (`ck_` was rejected because it collides with WooCommerce consumer
   keys.)

5. **[Done]** **Stop logging OAuth error bodies.** On a non-2xx refresh,
   `handleOAuthRefresh` logs the status and a parsed, truncated `error` code,
   and nothing else.

6. **[Done]** **`SecretProvider` interface (in-tree).** Introduce:

   ```ts
   interface Secret { value: string; allowedHosts?: string[] }
   interface SecretStore {
     get(name: string): Promise<Secret | null>;
     exists(name: string): Promise<boolean>;
     list(): Promise<string[]>;
     put?(name: string, value: string): Promise<void>; // absent => refresh returns 501
   }
   interface SecretProvider {
     readonly name: string;
     secrets: SecretStore;                // per-agent secrets
     shared?: Pick<SecretStore, 'get'>;   // shared, allowlisted secrets (was "fleet")
     close?(): Promise<void>;
   }
   ```

   Then:
   - add `withCache(store, ttlMs)`;
   - port `SecretFetcher` to an AWS implementation;
   - validate secret names in core (`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`);
   - replace the test mocks with an in-memory provider;
   - rename "fleet" to "shared" throughout.

   No other behaviour change.

7. **[Done]** **Configuration.** Add a pure `loadConfig(env)`. It is the only reader of
   `process.env`, which an eslint rule enforces.
   - All settings move to the `COATCHECK_*` names in
     `docs/design/v1-decisions.md`. A legacy name fails startup with
     "renamed to X".
   - The deployment-specific hard-coded values become configuration:
     - `AGENT_LABEL` becomes an optional `COATCHECK_AGENT_ID`;
     - the SSM and Secrets Manager prefixes become templates with `{agentId}`;
     - the CA subject becomes configurable;
     - the `vault_url` hint is omitted when unset;
     - the hard-coded region default goes;
     - `AWS_ENDPOINT_URL` is left to the SDK.
   - Add `COATCHECK_TICKET_TTL_SECONDS`.

8. **[Done]** **Policy file and host matcher.** `COATCHECK_POLICY_FILE` (JSON) maps secret
   names (trailing `*` allowed) to `allowed_hosts`. It also lists the shared
   secrets, replacing the hard-coded allowlist in `src/vault-handler.ts`.

   Add a pure matcher:
   - exact hostnames, plus `*.example.com`, which matches one or more labels
     but not the apex;
   - entries are lowercased, stripped of the trailing dot, and converted to
     punycode;
   - IP literals match exactly;
   - plaintext is allowed only by an `http://host` entry;
   - bare `*` and too-broad wildcards are rejected.

   An invalid policy file fails startup.

## Phase 3: host binding and listener hardening (HIGH, MEDIUM)

9. **[Done]** **Host-bound tickets on HTTP(S).** A secret's effective hosts are the
   intersection of the policy file and an in-band `_allowed_hosts` in its JSON
   value. A JSON secret whose only non-underscore key is `value` counts as a
   simple secret.
   - **Unbound secrets.** They are refused at mint time with `403`, unless
     `COATCHECK_ALLOW_UNBOUND_SECRETS=1`.
   - **Token store.** Tickets snapshot their allowed hosts. `TokenStore.issue`
     takes options (`ttlSeconds`, `allowedHosts`, `sessionId`) and replaces
     `issueForSession`. `replaceAll` requires the target.
   - **Enforcement.** On the HTTPS path the check is against the CONNECT
     target, never `Host` or SNI. On the forward path it is against the URL
     host.
   - **On a mismatch.** The request is not forwarded. The client gets `403`
     with `X-Coatcheck-Denied: host-mismatch`, and coatcheck logs
     `[swap] result=denied`.
   - **Forward path.** It strips `proxy-authorization` and hop-by-hop headers.
   - **OAuth refresh.** It checks the `token_url` host, and the refreshed
     ticket inherits the binding.
   - **Mint responses.** They include `allowed_hosts`.
   - **Tests.** The THREAT_MODEL `attacker.example` exfiltration fails, and so
     does a variant using a loopback listener.
   - Fix a duplicate type check in `policy.ts`.

10. **MITM policy.** Add `COATCHECK_MITM`:
    - `bound` (the default) MITMs a CONNECT only when the target is a host in
      the policy file, on a live ticket, or on an adapter. Everything else is
      a raw tunnel.
    - `always` (opt-in) MITMs every CONNECT.

    `COATCHECK_PASSTHROUGH_HOSTS` overrides both modes, for cert-pinned
    clients. This replaces "MITM only when the token store is non-empty".
    Also:
    - the MITM TLS server advertises ALPN `http/1.1` only, and a test asserts
      that an h2-capable client negotiates `http/1.1`;
    - after `101 Switching Protocols` the connection becomes a raw pipe, so
      WebSockets work through the MITM.

11. **Authenticate the listeners.** `COATCHECK_API_TOKEN` is checked as a
    bearer token on the vault API and as `Proxy-Authorization` on the proxy.
    Startup is refused on a non-loopback bind without it.

## Phase 4: packaging

12. **npm workspaces.** Move code with `git mv` into three packages:
    - `packages/core` (`@coatcheck/core`, with the `coatcheck` bin);
    - `packages/provider-aws`;
    - `packages/provider-env`.

    `provider-env` provides two providers:
    - an `env` provider, which accepts only `[a-z0-9-]+` secret names, so that
      `github-token` ↔ `COATCHECK_SECRET_GITHUB_TOKEN` is reversible
      (document this in its README and in the main README);
    - a `./file` JSON-file provider, whose `put` writes atomically.

    `COATCHECK_PROVIDER=aws|env|file|<module>` picks the provider through
    `import()`. The root Dockerfile builds all workspaces and ships core plus
    both providers. The demos move to `examples/`. A new zero-AWS
    `docker-compose.env.yml` becomes the README quickstart. Use TypeScript
    project references.

## Phase 5: browser injection

13. **Browser adapters.**
    - Extract the HTTP framing from `src/browserbase-rewrite.ts` into a generic
      `createJsonResponseRewriter`.
    - Add the adapter interface `{ name, hosts, rewriteJson(body, register) }`
      and `COATCHECK_BROWSER_ADAPTERS`.
    - The Browserbase adapter rewrites every `ws(s)://…browserbase.com` URL by
      value, not by key. That covers `connectUrl` and the `/debug` endpoint's
      debugger URLs.
    - It also strips `signingKey`. Verify the field names against the current
      API.
    - Existing CDP tests keep passing.

14. **Validate `mint-tokens` sessions.** Give `VaultDeps` the
    `CdpSessionStore`. An unknown or expired sid gets `404`.

15. **CDP origin binding.**
    - Track each CDP session's committed main-frame URL from
      `Page.frameNavigated`.
    - `Input.insertText` substitutes a session-bound ticket only when that host
      matches the login secret's allowed hosts. On a mismatch or an unknown
      origin, it drops the frame and returns a CDP error.
    - Remove substitution from `Runtime.evaluate` and `Runtime.callFunctionOn`.
      This closes direct exfiltration through expressions.
    - Add a Playwright + Chromium e2e test:
      - `page.fill` works on text, email, and password inputs;
      - a fill on a different origin is refused.

      If `fill` needs `callFunctionOn.arguments`, substitute there only, still
      gated on origin.
    - Document the residual risks:
      - Script the agent runs on the allowed origin can read the filled value.
      - Logins in cross-origin iframes aren't handled correctly, because the
        binding keys on the main frame:
        - a login form inside an iframe from another origin is refused unless
          the main frame's origin is allowed;
        - on an allowed main frame, a fill focused inside a cross-origin
          iframe (including one the agent injected) types the real value into
          that iframe.

## Phase 6: swap coverage and deployment

16. **Chunked request bodies.** Parse `Transfer-Encoding: chunked` in the MITM
    request parser so that keep-alive framing stays correct.

17. **Request body substitution.** Opt in per secret, with `swap_body` in the
    policy file or `_swap_body` in-band. Host binding applies, and
    `Content-Length` is rewritten.

18. **`docs/deploy/aws-ecs.md` and `ExternalId` in provider-aws.** The
    reference deployment covers:
    - the sidecar task definition;
    - health-gated startup;
    - CA trust in the agent entrypoint;
    - an explicit deny on the agent task role;
    - the broker role, and two ways to keep the agent from assuming it: a
      separate task, or an `ExternalId` injected only into the sidecar;
    - blocking `169.254.170.2`;
    - egress rules;
    - CA key handling.

    provider-aws supports `COATCHECK_AWS_EXTERNAL_ID` and warns at startup when
    `COATCHECK_AWS_ROLE_ARN` is set without it.

Done: the unused `http-proxy` dependency was removed during extraction.

## After 1.0

- Single-use tickets, opt-in per secret.
- An egress domain allowlist in the broker (builds on `COATCHECK_MITM=always`).
- Mint-time host narrowing (`?host=`), which may only narrow the allowed hosts.
- Provider-native host metadata (for example, AWS tags) through
  `Secret.allowedHosts`.
- Buffer-and-replay for `page.type()`, instead of failing closed.
- More than one concurrent CDP connection.
- A local `--remote-debugging-port` browser adapter. It needs a rewrite hook
  on the forward path.
- Providers for HashiCorp Vault and Vercel.
- A ticket checksum suffix, so tickets can be registered with secret scanners.

## Documented, not planned

These are recorded as residual risk in `docs/THREAT_MODEL.md`:

- The `Host` header and SNI are not compared with the CONNECT target, and the
  policy never uses them.
- Inbound redaction doesn't catch transformed values.
- Binary and screenshot frames are not inspected.
- Second routes to the same remote browser exist beyond what adapters rewrite.
- Script on an allowed origin can exfiltrate the filled value.
- Cross-origin iframe logins (item 15).
- Under `COATCHECK_MITM=bound`, a keep-alive tunnel opened before a host's
  first ticket existed stays passthrough. This fails closed.
- The CA key is readable on deployments that share a filesystem.
