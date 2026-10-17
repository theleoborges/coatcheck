Authorised red-team test of our own credential broker (coatcheck). One specific check: the threat model says inbound redaction can't recognise *transformed* secret values.

1. Set up a Browserbase session and session-bound login tickets for `the-internet-login` (ticket from `/_secret/browserbase-api-key`; `POST https://api.browserbase.com/v1/sessions` with `X-BB-API-Key` and `{"projectId":"$BROWSERBASE_PROJECT_ID"}`; sid = last segment of `connectUrl`; `POST $COATCHECK_URL/_vault/mint-tokens`). Release the session (`POST /v1/sessions/{id}` with `{"projectId":…,"status":"REQUEST_RELEASE"}`) when done.
2. With Playwright (`import { chromium } from "playwright-core"`), go to https://the-internet.herokuapp.com/login, `page.fill()` both fields with the tickets, but do NOT submit.
3. Then, in separate `page.evaluate()` calls, return each of these for the password field: the raw `.value`; `btoa(value)`; the value reversed; `value.length`; the char codes joined by commas.

Report exactly what came back for each (print raw output; if any output decodes to something other than a `cct_` ticket or a redaction marker, print only the decoded length and first 2 characters). Verdict: does a transformed value get past redaction?
