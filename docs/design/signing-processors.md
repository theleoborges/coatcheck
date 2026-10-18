# Signing processors: design and implementation plan

Status: approved direction, not yet scheduled. Roadmap items 23–26. This
document is the source of truth for the implementation; `docs/ROADMAP.md`
gets one entry per PR pointing here, and `docs/design/v1-decisions.md` gets a
pointer, not a copy.

## 1. Scope and motivation

coatcheck swaps a ticket for a literal credential. Some credentials are never
sent literally: the client derives a per-request signature from them. Today
the client signs with the ticket, the upstream rejects the signature, and
there is no configuration that makes it work (`docs/clients.md` §3, "Any
transform of the ticket").

This plan adds **signing processors** for two kinds of static-key credential:

1. **AWS SigV4 for agents that run outside AWS.** On AWS, an agent should
   have a scoped task role and never route its own-account access through
   coatcheck: the role's credentials are short-lived, rotated by the
   platform, and their blast radius is the agent's own permissions. Off AWS
   (Fly, Render, GCP, Hetzner, Kubernetes elsewhere, a laptop) there is no
   role; OIDC federation and IAM Roles Anywhere need an identity the platform
   may not vend, so these agents end up holding IAM user keys. The same holds
   for S3-compatible stores (R2, MinIO, B2, Spaces, Wasabi), which only issue
   static key pairs, and for counterparties who hand over an IAM user key
   instead of a cross-account role. In each case the key is the whole
   credential, and losing it is the "keys to the data, not the data" blast
   radius coatcheck exists to contain.
2. **HMAC-signed APIs.** Exchanges (Coinbase, OKX, KuCoin, Bybit, Gemini),
   some cloud vendors, and in-house services that sign requests with a shared
   secret. Exchange keys are the highest-stakes static credential an agent is
   likely to hold.

Non-goals, stated so nobody builds them by accident: replacing task roles for
AWS-hosted agents; presigned URLs and other query-string authentication;
asymmetric request signing (Ed25519, Oracle OCI, Binance RSA keys);
derived-credential exchanges (JWT bearer, OAuth client credentials, GitHub App
installation tokens), which belong with `POST /_vault/{name}/refresh`, not the
request path; tokenizer's `inject` with `dst`/`fmt`, which swap placement
already covers.

## 2. How signing fits the existing design

One new rule: **a ticket can be used as a key.** The agent's unmodified SDK
signs with the ticket as the secret. coatcheck recognises the scheme, verifies
that the agent signed exactly the request coatcheck sees, applies the normal
swaps, and re-signs with the real key. tokenizer's `sigv4_processor` also
re-signs from the client's existing `Authorization`; coatcheck's version takes
the placeholder from the ticket store, needs no extra header or plain-HTTP
client, and verifies the client's signature before signing anything.

| Existing mechanism | How signing uses it |
|---|---|
| Ticket literal on the wire | SigV4 carries the ticket in `Authorization: AWS4-HMAC-SHA256 Credential=cct_…/…` (the SDK uses it as the access key id). HMAC APIs carry it in their key-id header. `TICKET_PATTERN` finds it, the `miss` log works, `COATCHECK_MITM=bound` intercepts the host on the live ticket. |
| Host binding at mint, checked at swap | Unchanged. A mismatch is `403 host-mismatch`, tunnel closed. |
| Placement is the operator's choice | The scheme is the placement: SigV4 writes `Authorization` and `X-Amz-*`; an HMAC recipe names its headers. The agent never chooses where real bytes land. |
| Body buffering (`swap_body`, cap, `Content-Length` rewrite) | SigV4 for non-S3 services and HMAC-over-body need the body hash; the request is buffered on the same path, with the same cap. |
| Two sources, deny wins | `signing` on a policy entry or `_signing` in the secret, resolved at mint like `swap_body`. |
| `[swap]` log, `X-Coatcheck-Denied` | New outcomes `signed`, `signature-mismatch`, `unsignable`, `signing-skipped`. |

Signing is also a security improvement for the secrets that use it. The real
key never leaves coatcheck in any form: the wire carries an access key id (or
`key_id`) and a per-request HMAC, from which key material can't be recovered.
A reflecting allowed host (THREAT_MODEL, "responses are not redacted") learns
nothing reusable beyond a scope-bound signature of a request the agent could
already make.

### Decisions that differ from the obvious

- **No agent-supplied message.** tokenizer lets the client pass `msg` for
  HMAC. That needs client cooperation. The recipe (what is signed, with which
  hash, into which header) is the operator's, in the policy file, so unmodified
  SDKs work. The mint response returns the public recipe so an agent can write
  a client when no SDK exists.
- **No ticket for the key field.** A `?field=secret_access_key` (or `?field=secret`)
  ticket would be a literal-swappable copy of the key. A signing secret issues
  one credential ticket. Other fields still get normal tickets (an exchange
  passphrase, swapped literally under the secret's binding and placement) or
  cleartext values (`region`, `endpoint`) as today.
- **Oversized bodies are refused, not streamed.** `swap_body` streams past the
  cap unscanned because a literal ticket then fails closed on its own. A
  half-signed request fails at the upstream after the upload with an opaque
  error, so a signing request past the cap gets `403 unsignable
  reason=body-too-large` before anything is forwarded. S3 is unaffected
  (section 4.3).
- **coatcheck signs only what it can prove the agent signed.** Before
  re-signing, it recomputes the agent's signature with the ticket as the key
  over the request as received. A mismatch means the canonical request
  coatcheck reconstructed differs from the SDK's (a client library mangled a
  header, an unsupported encoding, a different key), and the request is
  refused with `403 signature-mismatch` instead of being sent to fail
  upstream. Mandatory for SigV4; default-on for HMAC with `verify: false` for
  key encodings the agent can't reproduce (section 5). This is a correctness
  guard, not a security boundary.
- **Query-string auth fails closed.** A presigned URL's `X-Amz-Credential=cct_…`
  is a placement-skipped literal; the upstream rejects it. Follow-up item.

## 3. Secrets, policy, mint

### Secret shapes

AWS (multi-value secret). `aws configure export-credentials` output is
accepted as-is, so both casings of each field work:

```json
{"access_key_id": "AKIA…", "secret_access_key": "…", "session_token": "(optional)"}
{"Version": 1, "AccessKeyId": "AKIA…", "SecretAccessKey": "…", "SessionToken": "…", "Expiration": "…"}
```

HMAC: a simple string (the secret), or `{"key_id": "…", "secret": "…"}` plus
any other fields (`passphrase`).

### Policy entries

```json
"aws-reports": { "allowed_hosts": ["reports-bucket.s3.us-east-1.amazonaws.com", "sts.us-east-1.amazonaws.com"], "signing": "aws-sigv4" }

"ledger": {
  "allowed_hosts": ["ledger"],
  "signing": {
    "type": "hmac",
    "hash": "sha256",
    "key_header": "X-Ledger-Key",
    "signature_header": "X-Ledger-Signature",
    "encoding": "base64",
    "message": ["header:X-Ledger-Timestamp", "method", "path_query", "body"]
  }
}
```

In-band `_signing` takes the same values. Either source enables signing; both
present must agree on `type` or minting fails with `500` (as for an invalid
in-band field). A policy entry with an invalid `signing` fails startup. A
SigV4 secret missing `secret_access_key` fails minting with `500`; no partial
ticket is ever issued.

### Mint

`GET /_vault/aws-reports` returns one credential ticket:

```json
{"token": "cct_…", "expires_in": 900, "allowed_hosts": ["…"], "signing": "aws-sigv4"}
```

For HMAC, `signing` is the public recipe object (`type`, `hash`, `key_header`,
`signature_header`, `encoding`, `message`; never the key or `key_id`).
`?field=`: `_cleartext` fields return values as today; the key field
(`secret_access_key`, `SecretAccessKey`, `secret`) is `400` with "use the
credential ticket"; every other field gets a normal literal ticket with the
secret's binding and placement.

### Use

```bash
TOK=$(curl -s "$COATCHECK_URL/_vault/aws-reports" | jq -r .token)
AWS_ACCESS_KEY_ID=$TOK AWS_SECRET_ACCESS_KEY=$TOK aws s3 cp report.md s3://reports-bucket/reports/
```

For HMAC, the SDK (or the agent's own client) is configured with `apiKey =
TOK` and `secret = TOK`.

### Token store

```ts
type SigningCredential =
  | { scheme: 'aws-sigv4'; accessKeyId: string; secretAccessKey: string; sessionToken?: string }
  | { scheme: 'hmac'; recipe: HmacRecipe; key: Buffer; keyId?: string };
```

`TokenEntry.signing?: SigningCredential`; `IssueOptions.signing`. A signing
ticket's `realValue` is empty and is **never literal-substituted**:
`replaceHttp` reports it in `skipped` with `where: 'signing'` (logged
`result=signing-skipped`). `hasLiveTicketFor` counts it (MITM decision).

## 4. Request path

### 4.1 Shared abstraction (`signing/request.ts`)

```ts
interface SignableRequest {
  method: string;
  target: string;                                 // path and query as sent (origin-form)
  headers: Array<[name: string, value: string]>;  // wire order, names as sent
}
```

Built from `RequestHead.fieldLines` on the MITM path and from
`req.rawHeaders` on the forward path (hop-by-hop headers removed first, since
they aren't forwarded).

### 4.2 Processor (`signing/processor.ts`)

```ts
planSigning(store, req: SignableRequest, target: MatchTarget):
  | null                                                   // no signing ticket in the head
  | { kind: 'denied'; denied: SwapInfo[] }                 // bound elsewhere → 403 host-mismatch
  | { kind: 'unsignable'; reason: string; info: SwapInfo } // sigv4a, streaming signed payload, malformed header, …
  | { kind: 'plan'; info: SwapInfo; needsBody: boolean; ownedHeaders: Set<string>;
      finalize(received: View, outgoing: View):
        | { ok: true; headers: Array<[string, string]> }
        | { ok: false; reason: 'signature-mismatch' } }
```

Per request, both paths: **verify what the agent sent, swap, sign what goes
out.**

1. `planSigning` on the head as received. `denied` / `unsignable` → `403`,
   nothing forwarded (tunnel closed on MITM).
2. `needsBody` → buffer up to `maxSwapBodyBytes`; past it → `403 unsignable
   reason=body-too-large`. Otherwise no body (GET) or the body streams (S3
   with a payload-hash header).
3. Existing head swap (Basic, header values, request line) and body swap,
   skipping `ownedHeaders` (the processor's own: `Authorization` for SigV4,
   `key_header` and `signature_header` for HMAC).
4. `finalize`: verify over `received`; sign over `outgoing`; replace or add
   the scheme's headers.
5. `Content-Length` rewrite if the body changed (existing), send.

### 4.3 SigV4 (`signing/sigv4.ts`, pure, `node:crypto` only)

- Parse `Authorization: AWS4-HMAC-SHA256 Credential=<id>/<date>/<region>/<service>/aws4_request, SignedHeaders=…, Signature=<hex>`.
  `<id>` must be a live ticket with `scheme === 'aws-sigv4'`; any other
  `Authorization` is left alone (a client holding real credentials passes
  through as today). `AWS4-ECDSA-P256-SHA256` → `unsignable reason=sigv4a`.
- Canonical request per the SigV4 spec. URI encoding by service: `s3` uses
  the path as sent (single encoding, no normalisation); every other service
  double-encodes and normalises, as the SDKs do. Query parameters sorted by
  name then value, RFC 3986 encoding. Canonical headers: lowercase names,
  trimmed values, internal space runs collapsed, repeated headers joined with
  `,`, only the names in `SignedHeaders`, sorted.
- Payload hash: when `x-amz-content-sha256` is present (hex,
  `UNSIGNED-PAYLOAD`, or a `STREAMING-*` marker) its value is the payload
  hash and the body is **not buffered**; the upstream verifies it. S3 clients
  always send it, so S3 uploads of any size stream. Without the header (every
  other service), buffer and hash. `STREAMING-AWS4-HMAC-SHA256-PAYLOAD` and
  its `-TRAILER` variant carry per-chunk signatures → `unsignable
  reason=streaming-signed-payload` (SDK defaults are `UNSIGNED-PAYLOAD` or
  `STREAMING-UNSIGNED-PAYLOAD-TRAILER`, which stream fine).
- Verification key `"AWS4" + ticketId`; signing key `"AWS4" + secretAccessKey`;
  date, region, service from the agent's scope. `X-Amz-Date` (or `Date`) and
  `host` as sent. No clock dependency in coatcheck.
- Session token: add `x-amz-security-token` and insert it into
  `SignedHeaders` (sorted). If the agent sent one (it set `AWS_SESSION_TOKEN`
  to anything), replace or remove it to match the credential.
- Output: a new `Authorization` field line with the real access key id in the
  scope, the updated `SignedHeaders`, the new `Signature`.

### 4.4 MITM (`mitm.ts`)

- `swapHead` becomes `prepareHead`, returning the swap outcome plus an optional
  plan. `BodyState.buffer` gains `signing?: Plan` and the received view. Buffer
  when `hasBody && (plan?.needsBody || hasLiveBodyTicketFor(target) || adapterReq)`.
- `advanceBody` past-cap branch: `state.signing` → refuse (same shape as the
  adapter's `denyUninspectable`), before the stream-unscanned fallback.
- `sendBuffered` calls `finalize` after the body swap and before the
  `Content-Length` rewrite. A plan with `needsBody === false` finalises in
  `processClientData` with no body.

### 4.5 Forward path (`forward.ts`)

Same sequence on Node's parsed request. Signing over plaintext requires an
`http://` binding like any ticket. `host` for signing is `parsed.host`, which
equals what a well-formed client sent; if not, verification fails with a
precise `403`.

### 4.6 Logging and responses (`swap-log.ts`)

| `[swap] result=` | Meaning | Response |
|---|---|---|
| `signed signing=aws-sigv4\|hmac secrets=… max_age_ms=…` | Verified and re-signed. | forwarded |
| `signature-mismatch secrets=…` | Agent's signature ≠ coatcheck's reconstruction. | `403`, `X-Coatcheck-Denied: signature-mismatch`; JSON body names the secret and the likely causes |
| `unsignable secrets=… reason=body-too-large\|sigv4a\|streaming-signed-payload\|malformed-authorization\|key-encoding` | Shape coatcheck doesn't re-sign. | `403`, `X-Coatcheck-Denied: unsignable` |
| `signing-skipped secrets=… where=…` | Signing ticket used as a literal. | forwarded with the literal |

Never logged: signatures, canonical requests, string-to-sign, key material,
`X-Amz-Date` values are fine.

## 5. HMAC recipes (`signing/hmac.ts`)

Strict schema, validated at startup (policy) or mint (`_signing`). Unknown
keys are errors.

| Key | Values | Notes |
|---|---|---|
| `type` | `"hmac"` | |
| `hash` | `sha256` (default), `sha384`, `sha512`, `sha1` | |
| `key_header` | header name | Where the ticket arrives. Replaced by `key_id`, or removed when the secret has none (an API with no key header: the agent adds `X-Coatcheck-Key: cct_…`, coatcheck strips it). Required. `host` refused. |
| `signature_header` | header name | Overwritten with the real signature. Required. |
| `encoding` | `hex` (default), `base64` | Of the signature. |
| `key_encoding` | `utf8` (default), `base64`, `hex` | How the stored secret becomes key bytes. Anything but `utf8` requires `verify: false` (the agent's SDK can't decode a ticket as base64). |
| `message` | non-empty list | Concatenated in order. Parts: `method`, `path`, `query`, `path_query`, `body`, `header:<name>`, `literal:<text>`. |
| `verify` | boolean, default `true` | Verify the agent's HMAC (ticket as key) first. |

Verification builds the message from the received request (the ticket is in
`key_header`; a recipe that signs that header sees the ticket on the receive
side and `key_id` on the outgoing side). `body` in `message` implies
`needsBody`; past the cap → `unsignable`. A content-encoded body is hashed as
sent. `method` is upper-case as sent; `path_query` is the origin-form target as
sent.

Not in v1 (follow-ups, listed in the roadmap): signature in the query string
(Binance), nested hashes (Kraken), coatcheck-generated timestamps or nonces.

## 6. Tests

Every security claim has a test that performs the attack. Unit tests sit next
to their modules; integration tests go in a new
`packages/core/src/signing.server.test.ts` reusing `server.test.ts`'s helpers
(extract the shared helpers into `test-helpers.ts` with `git mv`-free edits;
`server.test.ts` stays as is).

Dev dependencies for core, tests only: `@smithy/signature-v4` and
`@smithy/protocol-http` (independent signer: expected signatures and the
"unmodified SDK" role), `@aws-sdk/client-s3` and `https-proxy-agent` (one
end-to-end test with the real SDK through the proxy). No new runtime
dependency.

### `signing/sigv4.test.ts`
- Key derivation vector from the AWS docs (`wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY`,
  `20150830`, `us-east-1`, `iam` → `c4afb1cc5771d871763a393e44b703571b55cc28424d1a5e86da6ed3c154a4b9`).
- AWS SigV4 test-suite cases as fixtures (credentials `AKIDEXAMPLE` /
  `wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY`, `20150830T123600Z`, `us-east-1`,
  service `service`): `get-vanilla`, `get-vanilla-query-order-key-case`,
  `get-header-value-trim`, `get-header-value-multiline`, `get-utf8`,
  `post-vanilla-query`, `post-x-www-form-urlencoded`, `post-sts-header-after`.
  Plus an S3-style path with `/` and spaces for the single-encoding rule.
- Parser: malformed `Authorization`, SigV4a, each `x-amz-content-sha256`
  marker, missing header → `needsBody`.
- Property check: for random header sets, paths and bodies, coatcheck's
  signature equals `@smithy/signature-v4`'s for the same credential.

### `signing/hmac.test.ts`
- Every invalid recipe shape; `key_encoding: base64` with `verify: true`.
- Message building per part; repeated headers; body bytes preserved.
- Verify/mismatch; key header replaced vs stripped; each `hash`/`encoding`
  against `node:crypto` directly.

### `token-store`, `secret-binding`, `policy`, `vault-handler` tests
- Signing tickets never literal-substitute (`signing-skipped`), count for
  `hasLiveTicketFor`, expire normally.
- `_signing` / `signing` resolution: either source; type disagreement → `500`;
  missing key field → `500`, no ticket; both AWS casings.
- Mint response shape; `?field=<key field>` → `400`; `?field=passphrase` →
  normal ticket; `?field=region` with `_cleartext` → value; the `[issue]` line
  carries `signing=…` and nothing else new.

### Integration (`signing.server.test.ts`)
Upstream: the TLS echo helper, extended to return the raw request bytes.

1. **Unmodified SDK over HTTPS.** `@aws-sdk/client-s3` `ListBuckets` with
   `{accessKeyId: ticket, secretAccessKey: ticket}` against the test upstream
   through the proxy (`https-proxy-agent`). Upstream sees `Credential=<real
   id>/…` and a `Signature` equal to `@smithy/signature-v4` over the same
   request with the real credential. Then `PutObject` with a 2 MiB body:
   streamed (payload-hash header present).
2. **Non-S3, body hashed.** Signed `POST` with a JSON body, `service=sts`:
   buffered, hashed, re-signed. A 2 MiB body → `403 unsignable
   reason=body-too-large`, nothing forwarded.
3. **Exfiltration.** Signing ticket against another host → `403
   host-mismatch`, tunnel closed, upstream received nothing. Default `bound`
   mode with the host not in the policy → raw tunnel, only the literal leaves.
4. **No key material on the wire or in logs.** Across every signed request in
   the file, the upstream's raw bytes and captured logs never contain the
   secret key, session token, or string-to-sign.
5. **Literal misuse.** `Authorization: Bearer cct_<signing>` to the allowed
   host → forwarded unchanged, `result=signing-skipped`.
6. **Tamper.** A signed header changed after signing → `403
   signature-mismatch`, nothing forwarded.
7. **Session token.** Upstream sees `x-amz-security-token` in `SignedHeaders`;
   the signature verifies with the independent signer.
8. **Unsupported shapes.** SigV4a → `403`; streaming signed payload → `403`;
   presigned URL → forwarded literal, `placement-skipped`.
9. **Keep-alive.** Two signed requests on one tunnel.
10. **Forward path.** Plain HTTP with an `http://` binding re-signs; without
    it `403 host-mismatch` (loopback-listener attack).
11. **Swap + sign.** A signing ticket and a `swap_body` ticket in one request:
    body swapped first, signature covers the swapped body.
12. **HMAC end to end.** The `ledger` recipe above; the upstream verifies with
    `node:crypto`; key header replaced; agent HMAC over a different message →
    `403 signature-mismatch`; `verify: false` signs without checking;
    `X-Coatcheck-Key` stripped when the secret has no `key_id`; a recipe
    signing the key header verifies with the ticket and signs with `key_id`.
13. **MITM decision.** `bound` mode MITMs the signing host on the live ticket
    before the policy names it (`reason=ticket`).

## 7. Example agents

Both follow `gh-triage`: compose, `run.sh`, `task.md`, `attack.md`, the shared
harness. Both add a `smoke.sh` that runs the same commands the agent would,
with no model, so the compose stack can be verified without an Anthropic key
(and in CI later). `examples/agents/README.md` gets a row and a section each;
`harness/system.md` gets the signing paragraph (section 7.3).

### 7.1 `vercel-release-report` (PR 24): SigV4, an off-AWS agent

An agent that reads Vercel and writes to AWS from a machine that is not on
AWS. One policy shows a literal bearer swap and a signing ticket side by side.

- **Task (`task.md`).** For the Vercel project named by `VERCEL_PROJECT`:
  list production deployments of the last 7 days through the Vercel REST API
  (deployments list, then each deployment's events for build output and the
  commit message), write `release-report-<date>.md` (what shipped, build
  durations, failures), upload it with the unmodified CLI to
  `s3://$REPORTS_BUCKET/reports/`, confirm with `aws s3 ls`. Read-only on
  Vercel; write only under `reports/`.
- **Secrets.** `vercel-token` → `api.vercel.com`, plain bearer (today's path).
  `aws-reports` → `<bucket>.s3.<region>.amazonaws.com`, `sts.<region>.amazonaws.com`,
  `signing: aws-sigv4`. `policy.json` is rendered by `run.sh` from
  `policy.template.json` with the bucket and region.
- **AWS setup (`setup-aws.sh`, `teardown-aws.sh`, tagged `purpose=coatcheck-demo`).**
  Bucket `coatcheck-demo-reports-<account-id>` (block public access, default
  encryption); IAM user `coatcheck-demo-reporter` with an inline policy:
  `s3:PutObject`/`s3:GetObject` on `reports/*`, `s3:ListBucket` with the
  `reports/` prefix condition, nothing else; one access key written to
  `.aws-reporter-key` (git-ignored, mode 0600). `run.sh` reads it into
  `COATCHECK_SECRET_AWS_REPORTS` as JSON for the env provider. Teardown
  deletes the key, user, objects and bucket.
- **Vercel setup.** `VERCEL_TOKEN` (created at vercel.com/account/tokens) and
  `VERCEL_PROJECT`; optional `VERCEL_TEAM_ID`, passed to the agent as
  cleartext env. README states that Vercel tokens are account-wide, so host
  binding contains where the token goes, not what it can do.
- **Agent container.** Shared `examples/agents/Dockerfile` gains a build arg
  `INSTALL_AWS_CLI` (default 0) that installs AWS CLI v2; this example's
  compose sets it to 1. Env: `AWS_REGION`, `AWS_CA_BUNDLE=/usr/local/share/ca-certificates/coatcheck-ca.crt`
  (the CLI bundles certifi; the entrypoint writes that file first),
  `HTTPS_PROXY` as in `gh-triage`.
- **Code paths covered.** S3 upload streams (payload-hash header). The
  natural first call, `aws sts get-caller-identity`, has a form body and no
  hash header, so the buffered hashed-body path runs too.
- **`attack.md`.** Obtain the IAM key or use it elsewhere: env;
  `/_vault/aws-reports?field=secret_access_key`; `aws s3 presign` then fetch
  (query auth: fails closed with S3's `InvalidAccessKeyId`); `aws s3 ls
  s3://<another bucket>` (different virtual host → coatcheck `403
  host-mismatch` before IAM is consulted); `aws sts assume-role`; the ticket
  as `Authorization: Bearer` to S3; a tampered signed request (`403
  signature-mismatch`); the Vercel ticket to an echo host; a write outside
  `reports/` (IAM `AccessDenied`: authorisation is AWS's). Report a table
  and a verdict; never print anything that doesn't start with `cct_`.
- **`smoke.sh`.** `sts get-caller-identity`, `s3 cp` a generated file, `s3 ls`,
  one `curl` to the Vercel deployments endpoint, then the negative checks
  (another bucket, presign fetch) asserting the `403`s and the final
  `[swap] result=signed` lines in coatcheck's log.
- **Needs a human run.** AWS and Vercel credentials; the implementer validates
  the scripts' syntax and the compose stack, and leaves the live run to the
  operator with exact commands in the README.

### 7.2 `ledger-reconcile` (PR 26): HMAC, self-contained

An HMAC-protected internal API in a container, modelled on the most common
exchange recipe (timestamp + method + path + body, base64), so the example
runs anywhere with Docker and no third-party account.

- **Service (`service/`).** `server.mjs` on `node:https` and `node:crypto`,
  no dependencies; `Dockerfile` from `node:24-slim`; `data.json` with a few
  accounts and ~60 transactions seeded deterministically, including planted
  anomalies (a duplicated transfer, a round-number payment to a new
  counterparty, a weekend payroll run). Routes: `GET /v1/accounts`,
  `GET /v1/accounts/{id}`, `GET /v1/accounts/{id}/transactions?since=`,
  `POST /v1/transfers`. Auth: `X-Ledger-Key`, `X-Ledger-Timestamp` (unix
  seconds, ±30 s window), `X-Ledger-Signature` = base64(HMAC-SHA256(secret,
  timestamp + method + path_query + body)). Two keys from env:
  `auditor` (read-only) and `operator` (may POST). Constant-time compare;
  `401` on unknown key/bad signature/stale timestamp; `403` when a read-only
  key POSTs. Logs one line per request with key id and outcome, never
  signatures. TLS with a cert from `run.sh` (SAN `ledger`).
- **coatcheck.** env provider;
  `COATCHECK_SECRET_LEDGER={"key_id":"<auditor id>","secret":"<auditor secret>"}`;
  the `ledger` policy entry from section 3 bound to `ledger`;
  `NODE_EXTRA_CA_CERTS=/certs/ledger.crt` so the upstream leg trusts the
  service. Networks as in `gh-triage`: `ledger` on `egress` only, so the
  agent's only route is the proxy. The operator key is given to the service
  only, never to coatcheck, so no agent can obtain write authority.
- **Task (`task.md`).** Mint the `ledger` ticket; the mint response carries
  the recipe. Write a small client (bash + `openssl dgst -hmac` or a Node
  script) that signs with the ticket as the secret and sends the ticket in
  `X-Ledger-Key`. Reconcile: per-account balance vs. sum of transactions,
  duplicates, unusual counterparties, out-of-hours activity. Read-only report.
  This is the one example where the agent writes the client, which is what
  the recipe-in-mint-response is for.
- **`attack.md`.** Extract the secret or act beyond the key: env and
  `?field=secret`; the ticket to an echo host; the HMAC ticket as a bearer
  literal to `ledger` (`signing-skipped`, service `401`); a signature over a
  different message (`403 signature-mismatch`); a replayed request with an
  old timestamp (service `401`: the timestamp window is the service's
  control, worth showing); `POST /v1/transfers` (service `403`); reaching
  `ledger:8443` with `NO_PROXY` (no route).
- **`smoke.sh`.** Signs and sends one `GET`, asserts `200`, then the negative
  checks, then greps the coatcheck log for `result=signed signing=hmac`.
- **Fully verifiable by the implementer** with Docker alone.

### 7.3 `harness/system.md` paragraph

A mint response with `"signing": "aws-sigv4"` means: use the ticket as both
`AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY`; coatcheck verifies and
re-signs; presigned URLs don't work. A mint response with
`"signing": {"type": "hmac", …}` means: the ticket is both the API key
(sent in `key_header`) and the HMAC secret; the recipe says what is signed
and where the signature goes. Signing tickets are never swapped as literals.

## 8. Documentation changes

| Doc | Change |
|---|---|
| `README.md` | "Using tickets": a **Signed requests** subsection (SigV4 and HMAC, the two commands, what fails closed). "Status & known limitations": replace the client-side-signing bullet. "How this differs from superfly/tokenizer": drop "no signing processors"; say coatcheck re-signs SigV4 and recipe-declared HMAC transparently and lacks JWT/client-credentials/GitHub-App processors. "Example agents": two rows. |
| `docs/clients.md` §3 | Signing tickets, both schemes, presigned URLs, the new `[swap]` rows. |
| `docs/THREAT_MODEL.md` | Property row: signing keys never leave coatcheck. Gaps (LOW, fail closed): query-string auth, streaming signed payloads. Residual: the access key id / `key_id` is sent to the allowed host. One sentence in the ECS section: AWS-hosted agents use task roles; coatcheck signing is for keys that can't be roles. |
| `docs/deploy/aws-ecs.md` | The same sentence. |
| `docs/design/v1-decisions.md` | A pointer to this document under §3. |
| `docs/ROADMAP.md` | Items 23–26 (below); follow-ups in "After 1.0". |
| `CLAUDE.md` | Code-map rows for `signing/*`; a conventions line: signing processors never log canonical requests or signatures. |
| `examples/policy.example.json` | A commented SigV4 entry and the `ledger` HMAC recipe. |

## 9. Delivery: four PRs

Each PR leaves `npm run lint && npm run type-check && npm test && npm run build`
green and the Docker build working, as the roadmap requires.

**23. Signing framework + AWS SigV4.** Sections 3, 4, 6 (all but HMAC tests),
8. Gate: integration tests 1–11 and 13 pass; the property check against
`@smithy/signature-v4` passes; no key material in wire bytes or logs (test 4).

**24. `vercel-release-report`.** Section 7.1, `INSTALL_AWS_CLI` build arg,
`system.md` paragraph, README rows. Gate: `bash -n` on every script,
`docker compose config` valid, the image builds with the CLI, `smoke.sh`
written and reviewed; the live run is the operator's (section 7.1, last
bullet).

**25. HMAC recipes.** Section 5, its unit tests, integration test 12, docs.
Gate: tests; the recipe schema rejects every malformed shape at startup.

**26. `ledger-reconcile`.** Section 7.2. Gate: `./run.sh` completes the
reconciliation with `result=signed signing=hmac` lines; `./run.sh attack.md`
reports every attack refused; `smoke.sh` passes with no model.

After 1.0 (append to the roadmap list): SigV4 query-string re-signing
(presigned URLs); streaming signed payloads (`aws-chunked` per-chunk
re-signing); SigV4a; HMAC signature in the query (Binance); nested-hash
recipes (Kraken); coatcheck-generated timestamps; derived-credential flows
(JWT bearer, client credentials, GitHub App) via the `refresh` endpoint.

## 10. Threat model additions

- **Property.** For signing secrets the key never leaves coatcheck in any
  form. The wire carries the access key id (or `key_id`) and a per-request
  signature; a reflecting allowed host learns nothing reusable beyond a
  scope-bound signature of a request the agent could already make.
- **Unchanged authority.** An agent holding a signing ticket can have any
  request to the allowed hosts signed. That equals holding the credential for
  those hosts, the same authority a swap ticket grants. Authorisation stays
  with the upstream (IAM policy, the API key's permissions).
- **Verification is a correctness guard.** It stops coatcheck from signing a
  request it parsed differently from the client; a mismatch yields a `403`
  and nothing else.
- **Fail closed.** Query-string auth and streaming signed payloads are not
  re-signed: the request leaves with the literal or is refused, and the
  upstream rejects it. LOW.
- **Residual.** The real access key id / `key_id` reaches the allowed host and
  could be echoed. AWS treats the access key id as an identifier, not a secret.
