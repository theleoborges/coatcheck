# Broker-performed browser login

Status: **implemented** (roadmap item 20, merged in PR #8). Replaces step 2
of `cdp-injection.md` and its outbound substitution and keystroke detector
(`mint-tokens`, outbound `Input.insertText` substitution, the keystroke
detector). The connectUrl rewrite, the CDP proxy connection, origin tracking,
inbound redaction and teardown stay. The spec below matches the code; where
the build settled something the design left open, it is under
"Implementation decisions" and "Implementation notes".

Code: `packages/core/src/cdp/login-driver.ts` (the window),
`cdp/proxy.ts` (`CdpConnection`: state, id multiplexing, agent queue),
`vault-handler.ts` (`handleLogin`), `cdp-session-store.ts` (`LoginRequest`,
`LoginResult`, `CdpController`).

## Problem

In v1 the agent fills the login form with session-bound tickets and coatcheck
swaps them for the real values inside `Input.insertText`. From then on the
real password sits in a DOM field on a page where the agent can run script of
its own, and inbound redaction has to recognise the value in whatever that
script returns. A literal matcher can't do that: the agent chooses the
encoding. The red-team task `examples/agents/browser-login/attack-transform.md`
demonstrated this against the v1 build.

The lesson is that redaction is sound for data the **browser** produces on its
own (raw field reads, site console output, request bodies), and unsound for
data produced by code the **agent** wrote. So the fix is not better redaction.
It is to make sure no agent-controlled code runs while the real value exists
in the page.

Rejected: gating CDP methods while a credential is in the page (Playwright's
own actions use the same methods as agent script, so the agent's submit can't
be told apart from its read-back), and "document only" (browser injection is
coatcheck's headline feature; shipping it as protection against accidental
exposure while the README implies protection against an adversarial agent
would mislead users).

## Principle

coatcheck already sits on the CDP connection. It performs the fill and the
submit itself, on a document the agent has had no chance to instrument, while
the agent's frames are held. By the time the agent's next frame is forwarded,
the page has moved on or coatcheck has emptied the fields. Inbound literal
redaction remains as the backstop for browser-produced data.

## Agent API

`POST /_vault/{name}/login` replaces `POST /_vault/mint-tokens`. API-token
protected like every vault route.

```json
{
  "sessionId": "<coatcheck sid from the rewritten connectUrl>",
  "page": { "url": "https://www.example.com/login" },
  "fields": { "username": "#username", "password": "#password" },
  "submit": "button[type=submit]",
  "until": "navigation",
  "timeoutMs": 15000
}
```

| Field | Meaning |
|---|---|
| `sessionId` | Required. A live, **connected** sid (`CdpSessionStore`); `404` otherwise. |
| `page` | Optional. Which attached page target to drive. Without it there must be exactly one page target with a committed main-frame URL (any scheme, so an extra `about:blank` tab counts). With it, `url` is a prefix matched against the targets' committed main-frame URLs, which `OriginTracker` already records. No match or several: `409 {"status":"page-ambiguous"}`. |
| `fields` | Required, non-empty. Secret field → CSS selector, resolved in the main document. Only fields of the multi-value secret (`501` otherwise); `_cleartext` fields may be filled too. A non-string or empty selector is `400`. |
| `submit` | Required. A CSS selector to click, or `{"press":"Enter"}` on the last filled field. Anything else is `400`. |
| `until` | Success condition: `"navigation"` (default: a main-frame `Page.frameNavigated` whose `loaderId` differs from the one committed before the submit), `{"selector":"…"}` (element appears; polled every 250 ms) or `{"urlPrefix":"…"}` (the committed main-frame URL starts with it). Covers full-page and SPA logins. Anything else is `400`. |
| `timeoutMs` | Default 15 000, max 60 000 (larger values are clamped; a missing or non-positive value gets the default). One budget covers the reload, the fill and the wait. |

| Status | Body | When |
|---|---|---|
| `200` | `{"status":"ok","url":"https://…"}` | Success condition held. |
| `400` | `{"error":"…"}` | Invalid request body (see the field table). |
| `409` | `{"status":"no-success","cleared":true}` | Timeout (also when the reload doesn't finish, before anything is filled). The fields coatcheck filled were emptied before the agent resumed. |
| `409` | `{"status":"interception-active"}` | The agent has request interception enabled on that page (see preconditions). |
| `409` | `{"status":"busy"}` | A login is already in progress on this connection. |
| `409` | `{"status":"page-ambiguous"}` | No page target, or more than one, matches (see `page`). |
| `403` | `{"error":"credential-origin violation: …"}` | The page's committed origin isn't in the secret's allowed hosts, or is unknown / navigating / not http(s). Checked before the reload and again after it. Same rule as v1 origin binding. |
| `403` | `{"error":"…"}` | The secret is unbound (no policy rule and no `_allowed_hosts`) and `COATCHECK_ALLOW_UNBOUND_SECRETS` is off, or its host sources don't intersect. Same mint-time rule as `/_vault/{name}`. |
| `404` | `{"status":"selector-not-found","field":"…"}` | A field selector matched nothing. Every selector is checked before any value is typed, so nothing was filled (a field that vanishes mid-fill is emptied first; #11). |
| `404` | `{"status":"unknown-sid-or-secret","error":"…"}` | Unknown or not-connected sid, or no secret under that name. |
| `501` | `{"error":"…"}` | The secret isn't a multi-value secret, or lacks a requested field. |
| `502` | `{"status":"driver-error","cleared":true}` | One of coatcheck's own CDP commands failed (decision 8), including a `submit` selector that matches nothing. |
| `502` | `{"status":"upstream-closed"}` | The connection closed mid-window, including an agent-queue overflow (decision 4). |

Agent flow: create the session, connect with Playwright, `page.goto(login)`,
call `/login`, carry on with the logged-in page. Outside the login window
agents may use `page.type()`, `page.evaluate()` and screenshots freely: there
are no tickets in the browser to protect.

## The login window

Everything runs inside the per-connection handler in `cdp/proxy.ts`, which
already parses both directions.

**Command multiplexing.** CDP ids are client-chosen integers. coatcheck uses a
high id range (≥ 2³⁰) that Playwright's sequential counter never reaches,
keeps a map of its own pending ids, and swallows inbound frames whose `id` is
in that map. Everything else inbound is relayed as today.

**State tracked per connection**, all from frames the proxy already sees:

| State | Source | Used for |
|---|---|---|
| Attached page targets and their flattened `sessionId`s | inbound `Target.attachedToTarget` / `Target.detachedFromTarget` | `page` selection |
| Committed main-frame URL per target | `OriginTracker` (exists) | origin check, `page.url` match, `until` |
| New-document scripts the agent registered | outbound `Page.addScriptToEvaluateOnNewDocument` + its response's `identifier`, per target | fresh-document step |
| Request interception enabled | outbound `Fetch.enable` / `Fetch.disable`, `Network.setRequestInterception` | precondition |
| Login in progress | the driver | `busy`, agent queue |

**Preconditions** (checked before anything is sent upstream): sid connected;
page resolved; origin allowed; interception off (fail closed with `409` rather
than silently disabling the agent's interception); no other login in flight.

**Sequence:**

1. **Quiesce the agent.** From here until the end, agent → upstream frames are
   queued, not dropped, and released in order afterwards. Responses to
   commands the agent sent *before* the window, and all browser events, are
   relayed (with redaction) as usual. Playwright's default action timeout is
   30 s; the window is a few seconds.
2. **Fresh document.** Remove the new-document scripts the agent registered on
   this target (`Page.removeScriptToEvaluateOnNewDocument` for each tracked
   identifier), then `Page.reload` and wait for the main frame to commit and
   finish loading. Listeners the agent installed through earlier script die
   with the old document; only the site's own JS runs from here. Re-check the
   origin after the reload.
3. **Fill.** For each field: `DOM.getDocument` → `DOM.querySelector` →
   `DOM.focus`, clear the current value (coatcheck may call
   `Runtime.callFunctionOn` on the node; it's coatcheck's own command), then
   `Input.insertText` with the **real** value. Fill `_cleartext` fields the
   same way.
4. **Submit.** Click the `submit` selector via its box model and
   `Input.dispatchMouseEvent`, or `Input.dispatchKeyEvent` Enter on the last
   field.
5. **Wait for `until`** (events for `navigation`, polling `DOM.querySelector`
   for `selector`, `OriginTracker` for `urlPrefix`).
6. **On timeout**, empty every field coatcheck filled (same mechanism as the
   clear in step 3), then answer `409 no-success`. On success answer `200`.
7. **Release the queue.**

If the upstream connection closes mid-window, the login fails
(`502 upstream-closed`) and teardown runs as today. There are no session
tickets to revoke any more; teardown (`TokenStore.revokeSession`) drops the
sid's redaction values.

**Inbound redaction** stays and is extended to the small, fixed set of
encodings the *browser* applies to values it reports: percent-encoding (form
bodies), HTML entities and JSON string escaping. These are finite and
knowable, unlike agent transforms. The real values to match are the login
secret's field values for the duration of the connection (registered with the
`TokenStore`'s session value set before the window, dropped at teardown; see
decision 9).

## Browser adapter addition

The Browserbase session-create request can carry agent-controlled browser
code (an extension). With CDP enabled, the adapter strips such parameters
from **request** bodies (the MITM already buffers request bodies for
`swap_body`, so a request-side JSON transform hook on adapter hosts is a small
addition). The adapter also removes `seleniumRemoteUrl` from session
responses, which the v1 adapter left in place.

As built (`BrowserAdapter.rewriteRequestJson`, wired in `mitm.ts`): the
Browserbase adapter deletes `extensionId` at the top level and inside
`browserSettings` (field names checked against the Browserbase API,
2026-10). It runs on every request to an adapter host that carries a body, not
only `POST /v1/sessions`, and it fails closed (issue #13): the body is buffered
under the same `COATCHECK_MAX_SWAP_BODY_BYTES` cap as `swap_body`, and one the
adapter can't read as JSON — past the cap, with a `Content-Encoding`, or not
parseable whatever its `Content-Type` says — is refused with
`403 uninspectable-body` and the tunnel closed, never forwarded. The one
exception is `multipart/form-data` (file uploads to the browser service), which
no server reads as a session config and so passes through uninspected. An
earlier version only inspected bodies whose `Content-Type` was JSON and
forwarded everything else unchanged, which would have let a JSON config under
another content type carry the extension parameters through.

## What this removes

- `POST /_vault/mint-tokens`, session-bound `username_token` /
  `password_token`, and `TokenStore.replaceAllForSession`'s outbound use.
- Outbound substitution in `cdp/substitution.ts` and the origin gate on
  agent `Input.insertText` frames (`OriginTracker` stays for the login's
  origin check and `page` selection).
- `cdp/keystroke-detector.ts`.
- The client rules "use `page.fill()`, never `page.type()`/`page.evaluate()`
  for credentials" and "don't read the field back".

## Residual risk after this change

- **Site JS and the vendor see the password.** Already accepted as upstream
  trust; the site must receive the password to authenticate.
- **Cross-origin iframe logins** fail with `404 selector-not-found`: selectors resolve in the main
  document only. Embedded auth widgets need the login page itself to be the
  identity provider's page (navigate there first).
- **Client-side hashing / challenge logins** need the page's JS to see the
  raw password, which it does; they work. Logins that require typing into a
  non-`<input>` custom element may need `until`/`submit` tuning.
- **Authenticated-action abuse** is unchanged and out of scope.

## Tests

- `cdp/proxy.test.ts` (fake upstream): the id multiplexing swallows coatcheck's
  responses and relays the agent's; a reserved-range agent id is refused;
  agent frames sent during the window arrive upstream only after it, in order;
  target, new-document-script and interception tracking.
- `cdp/login-driver.test.ts` (fake browser): the full sequence, SPA
  `until.selector`, timeout clears the fields, `busy`, `interception-active`,
  origin `403`, `selector-not-found`.
- `cdp/e2e.test.ts` (real Chromium): the login succeeds via `/login` for a
  full-page form and for an SPA-style form (`until.selector`); after success
  the password field is gone or empty; on a wrong-selector timeout the fields
  are empty when the agent resumes; a listener the agent installed before the
  call sees nothing (reload) and a new-document script it registered is gone;
  **the four `attack-transform.md` reads return nothing derived from the
  password**; interception enabled → `409`.
- `vault-handler.test.ts`: request validation, the `LoginResult` → HTTP table
  (including `page-ambiguous`), host binding, `mint-tokens` removed (`404`).
- The example agents: `examples/agents/browser-login/task.md` rewritten for
  `/login`; `attack.md` and `attack-transform.md` re-run against the new build
  must report no password material.

## Implementation decisions

Choices the design above leaves open, settled before implementing.

1. **Vault → connection wiring.** `POST /_vault/{name}/login` is served by the
   vault server; the state lives in the CDP connection. The proxy attaches a
   per-connection controller to its sid in `CdpSessionStore`
   (`attach(sid, controller)`, cleared at teardown) and the vault handler looks
   it up. "Connected" in the status table means a controller is attached; a
   registered-but-unconnected or unknown sid answers `404`. This keeps
   `vault-handler.ts` free of WebSocket code and the store the single owner of
   sid lifetime.
2. **Empty new-document scripts are kept.** Playwright registers
   `Page.addScriptToEvaluateOnNewDocument {source: "", worldName}` on every page
   to create its utility world. It runs no code, and removing it breaks
   Playwright on the reloaded document. Only scripts whose `source` is
   non-empty after trimming are removed. Removed scripts are not restored
   after the window (re-adding would give them new identifiers the agent
   doesn't know); the agent re-adds init scripts or bindings it still needs.
3. **Id range.** coatcheck's ids start at 2³⁰ and increment. An agent frame
   whose `id` is ≥ 2³⁰ is refused with a CDP error and never forwarded, so a
   collision can't route a browser response to the wrong side.
4. **Agent queue cap.** Frames queued during the window are capped at 4096. On
   overflow the connection is torn down (fail closed; the login answers `502`)
   rather than dropping frames, which would desynchronise Playwright.
5. **Page targets.** Only flattened sessions from `Target.attachedToTarget` with
   `targetInfo.type === "page"` are candidates. With no candidate the answer is
   `409 page-ambiguous`.
6. **Reload wait.** After `Page.reload`, wait for a main-frame
   `Page.frameNavigated` and then `Page.loadEventFired` on that session. Both
   count against `timeoutMs`. If the reload doesn't finish, nothing was filled,
   and the answer is `409 no-success`.
7. **Clear on success too.** After the success condition holds, any filled field
   still attached to the document is emptied before the queue is released. For
   a full-page login the nodes are gone and this does nothing. It covers SPAs
   that keep the form mounted after logging in.
8. **Driver errors.** If one of coatcheck's own commands fails for a reason not
   in the table (for example, `DOM.focus` on an element that can't take focus),
   the filled fields are emptied and the answer is
   `502 {"status":"driver-error","cleared":true}`. The CDP error text isn't
   echoed back, and no value is ever echoed.
9. **Values for inbound redaction.** The login's field values
   (non-`_cleartext`) are registered in `TokenStore` under the sid
   (`registerSessionValues`). As built, `vault-handler.ts` registers them once
   the request and binding are valid, just before handing the login to the
   connection, so they are registered even if the driver then refuses
   (`busy`, `page-ambiguous`, …). They are not tickets and never substitute
   anywhere. `revokeSession` drops them at teardown.
10. **Logging.** The window logs `[cdp] sid=… login secret=… window open` and
    `[cdp] sid=… login secret=… window closed outcome=… ms=… queued=…`: names,
    outcome, counts and duration only.

## Implementation notes

Behaviour the spec above doesn't spell out, as built.

- **Order of checks.** The vault handler validates the body, then the sid
  (`404` before the provider is called), then the secret and its fields, then
  the host binding. The connection then checks `busy`; the driver resolves
  the page and checks interception before opening the window, and checks the
  origin inside the window before sending anything upstream.
- **Unbound secrets.** With `COATCHECK_ALLOW_UNBOUND_SECRETS=1` an unbound
  login secret is accepted and the origin check only requires a committed
  http(s) page, on any host.
- **`until: {"urlPrefix"}`** holds at once if the committed URL already starts
  with the prefix, and otherwise waits for a main-frame `Page.frameNavigated`
  to a matching URL. A client-side route change (`history.pushState`) doesn't
  fire that event; use `{"selector"}` for SPAs.
- **Submit by click** uses the centre of the element's content box
  (`DOM.getBoxModel`); `{"press":"Enter"}` sends `keyDown`/`keyUp` Enter to the
  focused (last filled) field.
- **Clearing** sets the node's `value` to `""` through coatcheck's own
  `Runtime.callFunctionOn`, before each fill and on the clear steps.

## Later: network mode

The strongest design routes the **browser's** egress through coatcheck too
(per-session external proxies on the browser service; trivially for a
self-hosted Chromium). Then the DOM only ever holds a ticket, the login POST is
swapped on the wire by the existing host-bound `swap_body` path, the browser's
egress becomes enforceable, and the CDP-side machinery above is unnecessary.
It needs coatcheck to be reachable from the browser and the browser to trust
coatcheck's CA. Tracked as roadmap item 21; broker-performed login ships
first because it works with Browserbase today and needs no ingress.
