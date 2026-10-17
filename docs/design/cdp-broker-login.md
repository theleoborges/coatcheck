# Broker-performed browser login

Status: **proposed** (roadmap item 20). Replaces steps 2–3 of
`cdp-injection.md` (`mint-tokens`, outbound `Input.insertText` substitution,
the keystroke detector). The connectUrl rewrite, the CDP proxy connection,
origin tracking, inbound redaction and teardown stay.

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
| `sessionId` | A live, **connected** sid (`CdpSessionStore`); `404` otherwise. |
| `page` | Which attached page target to drive. Optional when exactly one page target has a committed origin; otherwise `url` is a prefix matched against the targets' committed main-frame URLs, which `OriginTracker` already records. No match or several: `409 {"status":"page-ambiguous"}`. |
| `fields` | Secret field → CSS selector, resolved in the main document. Only fields of the multi-value secret (`400` otherwise); `_cleartext` fields may be filled too. |
| `submit` | A CSS selector to click, or `{"press":"Enter"}` on the last filled field. |
| `until` | Success condition: `"navigation"` (default: a main-frame `Page.frameNavigated` with a new `loaderId`), `{"selector":"…"}` (element appears) or `{"urlPrefix":"…"}`. Covers full-page and SPA logins. |
| `timeoutMs` | Default 15 000, max 60 000. |

| Status | Body | When |
|---|---|---|
| `200` | `{"status":"ok","url":"https://…"}` | Success condition held. |
| `409` | `{"status":"no-success","cleared":true}` | Timeout. The fields coatcheck filled were emptied before the agent resumed. |
| `409` | `{"status":"interception-active"}` | The agent has request interception enabled on that page (see preconditions). |
| `409` | `{"status":"busy"}` | A login is already in progress on this connection. |
| `403` | `{"error":"credential-origin violation: …"}` | The page's committed origin isn't in the secret's allowed hosts, or is unknown / navigating. Same rule as v1 origin binding. |
| `404` | `{"status":"selector-not-found","field":"…"}` | A selector matched nothing. Also for unknown secret or sid. |
| `501` | | The secret isn't a multi-value secret with the requested fields. |

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

If the upstream connection closes mid-window, the login fails (`502`) and
teardown runs as today. The `sid`'s tickets no longer exist, so there is
nothing to revoke; teardown keeps revoking any plain tickets bound to the sid
for backward compatibility of the store.

**Inbound redaction** stays and is extended to the small, fixed set of
encodings the *browser* applies to values it reports: percent-encoding (form
bodies), HTML entities and JSON string escaping. These are finite and
knowable, unlike agent transforms. The real values to match are the login
secret's field values for the duration of the connection (registered with the
`TokenStore`'s session value set at the start of the window, revoked at
teardown).

## Browser adapter addition

The Browserbase session-create request can carry agent-controlled browser
code (an extension). With CDP enabled, the adapter strips such parameters
from `POST /v1/sessions` **request** bodies (the MITM already buffers request
bodies for `swap_body`, so a request-side JSON transform hook on adapter hosts
is a small addition). Verify the exact field names against the current API in
that PR. The adapter also removes `seleniumRemoteUrl` from session responses,
which the v1 adapter leaves in place.

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
- **Cross-origin iframe logins** are refused: selectors resolve in the main
  document only. Embedded auth widgets need the login page itself to be the
  identity provider's page (navigate there first).
- **Client-side hashing / challenge logins** need the page's JS to see the
  raw password, which it does; they work. Logins that require typing into a
  non-`<input>` custom element may need `until`/`submit` tuning.
- **Authenticated-action abuse** is unchanged and out of scope.

## Tests

- `cdp/proxy.test.ts` (fake upstream): the id multiplexing swallows coatcheck's
  responses and relays the agent's; agent frames sent during the window arrive
  upstream only after it, in order; `busy`, `interception-active`,
  `page-ambiguous`, origin `403`, `selector-not-found`.
- `cdp/e2e.test.ts` (real Chromium): the login succeeds via `/login` for a
  full-page form and for an SPA-style form (`until.selector`); after success
  the password field is gone or empty; on a wrong-selector timeout the fields
  are empty when the agent resumes; a listener the agent installed before the
  call sees nothing (reload) and a new-document script it registered is gone;
  **the four `attack-transform.md` reads return nothing derived from the
  password**; interception enabled → `409`.
- `vault-handler.test.ts`: request validation, `mint-tokens` removed (`404`).
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
9. **Values for inbound redaction.** At the start of the window the login's
   field values (non-`_cleartext`) are registered in `TokenStore` under the sid
   (`registerSessionValues`). They are not tickets and never substitute
   anywhere. `revokeSession` drops them at teardown.
10. **Logging.** The window logs `[cdp] sid=… login secret=… window open` and
    `[cdp] sid=… login secret=… window closed outcome=… ms=… queued=…`: names,
    outcome, counts and duration only.

## Later: network mode

The strongest design routes the **browser's** egress through coatcheck too
(per-session external proxies on the browser service; trivially for a
self-hosted Chromium). Then the DOM only ever holds a ticket, the login POST is
swapped on the wire by the existing host-bound `swap_body` path, the browser's
egress becomes enforceable, and the CDP-side machinery above is unnecessary.
It needs coatcheck to be reachable from the browser and the browser to trust
coatcheck's CA. Tracked as roadmap item 21; broker-performed login ships
first because it works with Browserbase today and needs no ingress.
