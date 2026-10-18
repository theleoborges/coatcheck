# Browser credential injection via CDP substitution

Status: **superseded in part by broker-performed login** (roadmap item 20,
implemented; `docs/design/cdp-broker-login.md`), behind
`COATCHECK_CDP_ENABLED=1`.

> **Superseded sections.** The v1 flow handed the agent session-bound tickets
> to fill with `page.fill()` and swapped them inside `Input.insertText`. Item 20
> removed that: coatcheck now performs the fill and submit itself (see
> `cdp-broker-login.md`, which also has the login endpoint, its status codes
> and the current residual risks). Sections marked **(history)** describe code
> that no longer exists, or reasoning item 20 overturned, and are kept only to
> explain what was removed and why:
> **Problem** (the v1 approach), **Why substitution**,
> **Step 2: session-bound tickets**, **Outbound substitution**,
> **Keystroke detector** and **Known gaps (v1)**.
>
> **In force** (updated to match the code): **Architecture**, **Step 1:
> connectUrl rewrite** (now also stripping request extension params and
> `seleniumRemoteUrl`), **Step 3: CDP proxy connection**, **Origin tracking**
> (reused for the login origin check and page selection), **Inbound
> redaction** (extended to browser-applied encodings), **Teardown**,
> **Failure modes**, **Browser adapters**, **Configuration** and **Logging**.

Code: `packages/core/src/cdp/proxy.ts`, `packages/core/src/cdp/login-driver.ts`, `packages/core/src/cdp/substitution.ts`,
`packages/core/src/cdp-session-store.ts`, `packages/core/src/browser-adapters.ts`, `packages/core/src/json-response-rewriter.ts`, wiring in `packages/core/src/mitm.ts` and `packages/core/src/start.ts`,
login endpoint in `packages/core/src/vault-handler.ts`.

## Problem (history)

> The first paragraph still describes the problem. The rest describes the v1
> answer, replaced by broker-performed login.

coatcheck's HTTPS path swaps tickets (`cct_*`) for real values in request
headers and URLs. Logging into a website from a remote browser is different:
the agent drives the browser with Playwright over a Chrome DevTools Protocol
(CDP) WebSocket, and the password travels inside a CDP frame such as
`Input.insertText`. The HTTPS MITM never sees that frame. Without help, the
agent process has to hold the cleartext password, which puts it in reach of
prompt injection.

CDP injection adds a second listener to coatcheck: a WebSocket proxy that sits
between the agent's Playwright client and the remote browser. It substitutes
tickets for real values on outbound CDP frames and redacts real values out of
inbound frames. The agent fills a login form with `page.fill(sel, "cct_…")`
and never sees the password.

Scope: ordinary HTML login forms. Sites that require 2FA/OTP at login are out
of scope.

## Why substitution, not session handover or per-site adapters (history)

> **Overturned by roadmap item 20.** The red-team run showed substitution
> leaves the real value in a page the agent can script. coatcheck now drives
> the login itself, but generically: the agent supplies the selectors per call,
> so there are still no per-site adapters to maintain.

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
agent ── HTTPS POST /v1/sessions (x-api-key: cct_…) ──▶ coatcheck :3128 (MITM)
                                                         │ swap ticket → real API key
                                                         │ rewrite response connectUrl
                                                         ▼
                                                    browser vendor REST API

agent ── ws://127.0.0.1:8444/cdp/{sid} ──▶ coatcheck :8444 (CDP proxy)
                                            │ outbound: relayed unchanged (queued during a login)
                                            │ login:    coatcheck's own fill + submit
                                            │ inbound:  real value → [REDACTED:…] or drop
                                            ▼
                                        vendor CDP endpoint (real connectUrl)

agent ── POST /_vault/{name}/login {sessionId, fields, submit, …} ──▶ coatcheck :3128 (vault API)
```

Both listeners run in one process and share the `TokenStore` and the
`CdpSessionStore`; the login endpoint drives the connection through the
controller the CDP proxy attaches to its sid. The CDP
listener binds to the same host as the HTTP listener (`COATCHECK_BIND_HOST`,
default `127.0.0.1`), port `COATCHECK_CDP_PORT` (default 8444)
(`packages/core/src/start.ts`). If the CDP listener fails to bind,
`startCoatcheck` rejects and the `coatcheck` bin exits (`packages/core/src/start.ts`, `cli.ts`), so a deployment that gates the agent
on broker health also gates it on the CDP listener.

### Step 1: connectUrl rewrite (browser adapters)

A remote-browser session is created over the vendor's REST API. The response
carries a `connectUrl` (a `wss://` URL with a signing key embedded), and other
endpoints (Browserbase's `GET /v1/sessions/{id}/debug`) return more CDP and
live-view URLs. If the agent received any of them it could connect directly
and bypass the proxy, and with it the login window and redaction.

When the CDP proxy is enabled and the CONNECT target is one of a browser
adapter's REST hosts, coatcheck replaces the plain response pipe with a
streaming rewriter (`packages/core/src/mitm.ts`).
`createJsonResponseRewriter` (`packages/core/src/json-response-rewriter.ts`) is
a small, vendor-neutral HTTP/1.1 response parser:

- Frames each response by `Content-Length`, or decodes `Transfer-Encoding:
  chunked` and re-emits it with a `Content-Length`.
- If the body parses as JSON, hands it to the adapter's `rewriteJson` and, if
  that changed anything, re-serialises it and recomputes `Content-Length`.
- Non-JSON bodies pass through unchanged. A response with neither framing
  header switches the connection to raw passthrough for the rest of its life.

The Browserbase adapter (`packages/core/src/browser-adapters.ts`):

- rewrites every string that parses as a `ws:`/`wss:` URL on `browserbase.com`
  or a subdomain (parsed hostname, so `evilbrowserbase.com` doesn't match),
  whatever its key: `connectUrl`, `wsUrl`, and WebSocket `debuggerUrl`s,
  including `pages[]`; plus any `ws(s)` `connectUrl` on any host;
- deletes `signingKey` and `seleniumRemoteUrl` (an HTTP route to the same
  browser; removed since item 20);
- deletes values it can't point at the local proxy but that would be a direct
  route to the browser: http(s) viewer URLs whose query embeds a Browserbase
  WebSocket target (`…inspector.html?wss=connect.browserbase.com/…`) and any
  non-WebSocket `debuggerUrl`/`debuggerFullscreenUrl`. Browserbase live view
  is therefore unavailable through coatcheck while CDP is enabled;
- on requests (item 20): deletes `extensionId`, top-level and in
  `browserSettings`, from request bodies to the API host, refusing any body it
  can't read as JSON (`multipart/form-data` uploads excepted), so the agent
  can't load its own extension into the browser (details in
  `cdp-broker-login.md`, "Browser adapter addition").

Each replacement is produced by `CdpSessionStore.register(realUrl, adapterName)`
(`packages/core/src/cdp-session-store.ts`), which stores the real URL under a random
24-hex-char `sid` (12 random bytes) with a 10-minute TTL, and returns
`ws://{COATCHECK_CDP_ADVERTISE_HOST}:{COATCHECK_CDP_PORT}/cdp/{sid}`. The signing key
in the real URL never reaches the agent.

The rewrite only happens on a MITM'd connection. With CDP enabled, the
browser service's API host is always intercepted in the default
`COATCHECK_MITM=bound` mode, as an adapter host (`packages/core/src/mitm.ts`); unless it is
listed in `COATCHECK_PASSTHROUGH_HOSTS`, which disables the rewrite.

### Step 2: session-bound tickets (`POST /_vault/mint-tokens`) (history)

> **Superseded by roadmap item 20.** `mint-tokens` and session-bound tickets were removed; coatcheck fills the form itself. Kept for historical context.

Body: `{ "secretName": "<name>", "sessionId": "<sid>", "expires_in"?: <seconds> }`.

`handleMintTokens` (`packages/core/src/vault-handler.ts`) first checks that the
sid is live in `CdpSessionStore` (registered by an adapter rewrite and not
expired; once a client connects it stays live until that connection closes).
An unknown, expired or closed sid gets `404 {"error":"Unknown or expired CDP
session"}` before the provider is called. It then reads the named secret,
requires it to be a JSON object with non-empty string `username` and
`password` fields, and issues two tickets with
`TokenStore.issueForSession(...)` (`packages/core/src/token-store.ts:81`). TTL defaults to
600 s and is capped at 1800 s (`packages/core/src/vault-handler.ts:222-223`, `:249-252`).
Response: `{ "username_token", "password_token", "expires_in" }`.

Session-bound tickets differ from ordinary tickets in two ways:

- `replaceAll` (the HTTP/HTTPS path) skips any entry with a `sessionId`
  (`packages/core/src/token-store.ts:133`). A session-bound ticket never substitutes on the
  HTTPS path.
- `replaceAllForSession(input, sid)` (`:148`) substitutes only tickets bound to
  that sid. Ordinary (unscoped) tickets do not substitute inside CDP frames.

The lookup key is the secret name, not a domain. There is no association
between a credential and the site it belongs to (see Known gaps).

### Step 3: CDP proxy connection

`startCdpProxy` (`packages/core/src/cdp/proxy.ts`) accepts `ws://…/cdp/{sid}`:

1. Parse the sid from the path (`/^\/cdp\/([a-f0-9]+)\/?$/`) and resolve it
   in `CdpSessionStore`. Unknown or expired sid: close 1008.
2. Enforce `MAX_CONCURRENT = 1`. A second concurrent connection is closed with
   1013 "CDP proxy busy". v1 assumes one agent drives one browser at a time.
3. Mark the sid connected (it stays live until teardown), create a
   `CdpConnection` and attach it to the sid as its login controller.
4. Dial the real `connectUrl`. Frames that arrive before the upstream opens are
   queued, capped at 256 (`pendingFrameCap`). Overflow sends a CDP error and
   tears down. The upstream must open within 10 s or the connection is torn
   down.
5. Relay agent frames upstream unchanged, tracking the state a login needs
   (page targets, new-document scripts, interception). Agent frames with an
   id ≥ 2³⁰ are refused (coatcheck's own range). During a login window agent
   frames are queued and released afterwards. Inbound frames go through
   inbound redaction; responses to coatcheck's own commands are swallowed.

There is no authentication on the WebSocket upgrade beyond knowledge of the
sid. The sid is unguessable and only delivered to the agent in the rewritten
response, and the listener binds to loopback by default.

### Origin tracking

`OriginTracker` (`packages/core/src/cdp/origin-tracker.ts`), one per
connection, keeps each flattened CDP session's committed main-frame URL from
inbound `Page.frameNavigated` events with no `parentId`. The origin is
**unknown** before the first such event, for non-http(s) URLs (`about:blank`,
`data:`, `chrome-error:`), and while a main-frame navigation is in progress:
from an outbound `Page.navigate` / `Page.reload` / `Page.navigateToHistoryEntry`
or an inbound main-frame `Page.frameStartedLoading`, until the next main-frame
`Page.frameNavigated` or `Page.frameStoppedLoading` (or a `Page.navigate`
response that commits nothing). Sessions are forgotten on
`Target.detachedFromTarget`.

### Outbound substitution (agent → browser) (history)

> **Superseded by roadmap item 20.** There is no outbound credential substitution any more; coatcheck never swaps a ticket into a CDP frame. Kept for historical context.

`substituteOutbound` (`packages/core/src/cdp/substitution.ts`):

- Pre-filter: if the raw frame contains no `cct_` substring, forward it
  untouched without parsing. Most CDP traffic skips JSON parsing.
- Only `Input.insertText.params.text` (what `page.fill()` sends) is a
  substitution site. `TokenStore.replaceAllForSession(text, sid, origin)`
  swaps a session ticket only when the frame's CDP session has a known origin
  that matches the ticket's allowed hosts (an `http:` page needs an `http://`
  entry; unbound tickets match any known origin). If any ticket in the frame
  is denied, the whole frame is dropped and the client gets a CDP error with
  the request's `id` and `sessionId`: `credential-origin violation: <secret>
  not allowed on <scheme>://<host>`, or `… page origin unknown (<reason>) …`.
  Playwright retries the action on such errors until its timeout.
- `Runtime.evaluate` and `Runtime.callFunctionOn` are not substitution sites:
  an expression that received the real value could send it anywhere.
  Playwright's `fill` passes the ticket to its injected script through
  `callFunctionOn.arguments`, but for text, email and password inputs that
  script only focuses and selects the field; the value is typed with
  `Input.insertText` (verified by `packages/core/src/cdp/e2e.test.ts`).
- A frame of any other method that contains `cct_` is forwarded unmodified and
  logged ("token observed in …"; at info level for `Runtime.*`, which is
  expected). Not substituted: `Network.setExtraHTTPHeaders`,
  `Page.addScriptToEvaluateOnNewDocument`, `Fetch.continueRequest`.
- Binary frames are forwarded without inspection (`packages/core/src/cdp/proxy.ts:96-99`).

### Inbound redaction (browser → agent)

If the browser reports a real value back, for example a field read, a form
POST body in a `Network` event, or site console output, it would arrive in an
inbound frame. Since item 20 this is a backstop for browser-produced data:
no agent script runs while the value is in the page. `substituteInbound`
(`packages/core/src/cdp/substitution.ts`) defends it:

1. Collect the session's real values (`TokenStore.sessionValues`). A login
   registers its non-`_cleartext` field values under the sid; they stay until
   teardown. None: forward as-is.
2. Match each value and the encodings the browser applies: percent-encoding
   (`encodeURIComponent`), HTML entities and JSON string escaping.
3. Byte-level floor: if no form occurs as a substring of the raw frame,
   forward as-is.
4. Otherwise parse. Unparseable: **drop the frame**.
5. Walk the JSON tree and replace each occurrence in string values with
   `[REDACTED:<secretName>:<field>]`, for example
   `[REDACTED:example-login:password]`.
6. Re-serialize. If any form still occurs in the output, drop the frame.

A dropped frame is never forwarded, so the Playwright call that was waiting
for it hangs or times out rather than returning the secret
(`packages/core/src/cdp/proxy.ts`). Binary inbound frames are forwarded
without inspection.

The redaction marker carries the secret name, not the ticket id, and is not
re-substitutable: filling `[REDACTED:…]` into another field sends the marker
text literally.

### Keystroke detector: fail closed for `page.type()` (history)

> **Superseded by roadmap item 20.** The keystroke detector was removed: with no credential tickets in the browser, `page.type()` needs no special handling. Kept for historical context.

`page.fill()` sends the value in one `Input.insertText` frame, which the
outbound substitutor handles. `page.type()` sends one `Input.dispatchKeyEvent`
per character, so the ticket never appears whole in a single frame and cannot
be substituted without stateful buffering and replay, which v1 does not do.

Instead, `KeystrokeDetector` (`packages/core/src/cdp/keystroke-detector.ts`) keeps an 80-char
sliding window of `params.text` from `Input.dispatchKeyEvent` frames, one
detector per connection. When the window ends with an active session-bound
ticket id (`TokenStore.sessionTokenIds`), the proxy drops that frame and
replies to the agent's request id with a CDP error:
`{"error":{"code":-32000,"message":"credential-flow violation: page.type() detected on a vault token; use page.fill() instead"}}`
(`packages/core/src/cdp/proxy.ts:102-120`, `:227-233`). The session stays up.

What this guarantees: the real password is never sent (it was never going to
be, since keystrokes are not substituted) and the automation fails loudly
rather than appearing to succeed. What it does not guarantee: the first 67 of
the ticket's 68 characters have already been typed into the page by the time
the last keystroke matches. A ticket is useless outside its own CDP session,
so this leaks no secret, but the page has seen most of a ticket string.

`Input.dispatchKeyEvent` frames are never run through `substituteOutbound`
(`packages/core/src/cdp/proxy.ts:118`).

### Teardown and revocation

`teardown()` (`packages/core/src/cdp/proxy.ts`) runs once on client close,
client error, upstream close, upstream error, upstream connect timeout,
pending buffer overflow, or agent-queue overflow during a login. It:

- fails any coatcheck command or event wait in flight (a login in progress
  answers `502 upstream-closed`),
- decrements the concurrency counter,
- drops the sid's redaction values (`TokenStore.revokeSession`),
- revokes the sid in `CdpSessionStore` and detaches its controller, so a sid
  is single-use: reconnecting to the same `connectUrl` after close fails with
  1008, and `/login` on it answers `404`,
- closes both sockets.

It does not end the remote browser session at the vendor. Releasing that
session remains the client's job.

## Failure modes

| Condition | Behaviour |
|---|---|
| `COATCHECK_CDP_ENABLED` unset | No CDP listener; `connectUrl` not rewritten; agent receives the real vendor URL (`packages/core/src/mitm.ts`, `packages/core/src/start.ts`). Browser login unavailable. |
| Adapter host in `COATCHECK_PASSTHROUGH_HOSTS` | Tunnel is passthrough; `connectUrl` not rewritten. Otherwise an adapter host is always MITM'd while CDP is enabled (`packages/core/src/mitm.ts`). |
| sid unknown or expired (10 min, unconnected) | WebSocket closed 1008. |
| `/login` for an unknown or not-connected sid | `404 unknown-sid-or-secret`, provider not called. |
| Second concurrent CDP connection | Closed 1013. |
| Upstream does not open within 10 s | Torn down. |
| >256 frames queued before upstream opens | CDP error to client, torn down. |
| Agent frame with an id ≥ 2³⁰ | Refused with a CDP error, never forwarded. |
| >4096 agent frames queued during a login | Torn down; the login answers `502`. |
| Login refused or failed | See the status table in `cdp-broker-login.md`. |
| Real value echoed in an inbound frame that cannot be cleaned | Frame dropped; the awaiting client call stalls. |
| CDP listener bind failure | Process exits. |

## Known gaps (v1) (history)

> These are the gaps of the v1 ticket flow. The first and fourth were
> confirmed against a real Browserbase session
> (`examples/agents/browser-login/attack-transform.md`) and are what
> `cdp-broker-login.md` (roadmap item 20) closed. Current residual risks are
> in `cdp-broker-login.md` ("Residual risk after this change") and
> `docs/THREAT_MODEL.md`. Binary frames, other routes to the browser,
> authenticated-action abuse and vendor trust still apply as written.

- **Script on an allowed origin can read the filled value.** Origin binding
  (roadmap item 15) stops a fill on another site and closes direct
  exfiltration through `Runtime.*` expressions, but once the real value is in
  a field on an allowed origin, script the agent runs there
  (`page.evaluate`) can read it and send it anywhere, transformed so the
  redactor doesn't match. A navigation that page script starts can also race
  a fill (the start event may not have reached coatcheck yet).
- **Cross-origin iframe logins.** The binding keys on the main frame, because
  the focused frame can't be attributed from `Input.insertText`:
  - a login form inside an iframe from another origin (for example an
    embedded auth widget) is refused unless the main frame's origin is
    allowed;
  - on an allowed main frame, a fill whose focus is inside a cross-origin
    iframe (including one the agent injected) types the real value into that
    iframe.
- **SSO and auth subdomains** need their hosts in the login secret's allowed
  hosts (`*.example.com` or explicit entries); the page origin at fill time is
  what is checked.
- **The redactor only matches the literal value.** Any transform defeats
  inbound redaction: `btoa(el.value)`, `el.value.split('').reverse().join('')`,
  `encodeURIComponent`, char codes, slicing into pieces across frames. An agent
  that can run script in the page can read the password back in transformed
  form.
- **Binary frames are not inspected** in either direction. Screenshots
  (`Page.captureScreenshot` returns base64 inside a text frame, which the
  literal-match redactor will not match) and any rendered password (for
  example after a "show password" toggle) reach the agent.
- **Other routes to the same browser bypass the proxy.** Inbound redaction
  only covers traffic that flows through this listener. Since roadmap item 13
  the Browserbase adapter rewrites every Browserbase WebSocket URL in API
  responses and removes `signingKey` and live-view URLs, but a route it can't
  see still works: a URL the vendor encodes in a shape the adapter doesn't
  recognise, a vendor endpoint on a host that isn't an adapter host, or a
  browser reached through `COATCHECK_PASSTHROUGH_HOSTS` or with CDP disabled.
- **Authenticated-action abuse.** Once logged in, the agent can do anything the
  user can do on that site. Out of scope for a credential broker.
- **Vendor trust.** The remote browser vendor sees the real credential.

## Browser adapters

The vendor-specific pieces are a host list and a JSON transform
(`packages/core/src/browser-adapters.ts`):

```ts
interface BrowserAdapter {
  name: string;
  /** REST hosts whose responses are rewritten (exact or `*.suffix`). */
  hosts: string[];
  /** Mutate parsed JSON in place; register(realWsUrl) returns the local ws URL. Return true if changed. */
  rewriteJson(body: unknown, register: (realUrl: string) => string): boolean;
  /** Optional (item 20): strip agent-controlled parameters from a JSON request body in place. Return true if changed. */
  rewriteRequestJson?(body: unknown): boolean;
}
```

Everything else (HTTP framing, the CDP proxy, the login driver, redaction,
session store) is vendor-neutral. Built-ins are chosen
with `COATCHECK_BROWSER_ADAPTERS` (default `browserbase`); custom adapters go
through `startCoatcheck({ config, provider, adapters })`, which then uses
exactly the adapters given. A local `--remote-debugging-port` browser needs a
rewrite hook on the plain-HTTP forward path and is out of v1.

## Configuration

| Variable | Default | Meaning |
|---|---|---|
| `COATCHECK_CDP_ENABLED` | `0` | `1` enables the listener and the adapters' URL rewrite. |
| `COATCHECK_BROWSER_ADAPTERS` | `browserbase` | Comma-separated built-in adapters. |
| `COATCHECK_CDP_PORT` | `8444` | Listener port. |
| `COATCHECK_CDP_ADVERTISE_HOST` | `127.0.0.1` | Host written into rewritten URLs. Override when the client is in a different network namespace (e.g. separate containers in local dev). |
| `COATCHECK_BIND_HOST` | `127.0.0.1` | Bind address for both listeners. |

## Logging

The CDP proxy logs sids, adapter names, counts (redactions, dropped
redaction values), fail-closed events, and per login the secret name,
outcome, duration and number of queued agent frames. It does not log frame
bodies or real values.
