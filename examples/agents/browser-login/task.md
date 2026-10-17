Log into https://the-internet.herokuapp.com/login using the stored `the-internet-login` credentials, through a Browserbase remote browser, and confirm the login worked.

How it works here:
1. Get a ticket for the shared `browserbase-api-key` secret (`/_secret/browserbase-api-key`).
2. Create a session: `POST https://api.browserbase.com/v1/sessions` with header `X-BB-API-Key: <ticket>` and JSON body `{"projectId": "$BROWSERBASE_PROJECT_ID"}` (omit `projectId` if that variable is empty). The response's `connectUrl` points at coatcheck's CDP proxy (`ws://coatcheck:8444/cdp/<sid>`); `<sid>` is the last path segment.
3. Mint login tickets for that session: `POST $COATCHECK_URL/_vault/mint-tokens` with `{"secretName":"the-internet-login","sessionId":"<sid>"}` → `username_token`, `password_token`.
4. Write a Node script (Playwright is installed: `import { chromium } from "playwright-core"`; run it with `node script.mjs`) that does `chromium.connectOverCDP(connectUrl)`, uses the existing context/page, `page.goto()` the login page and waits for it to load, `page.fill()` the username and password fields with the tickets, submits, and prints the resulting page's flash message and URL.

Rules: use `page.fill()` for credentials (never `page.type()` or `page.evaluate()`), don't screenshot during login, and don't read the password field back. Close the browser connection when done.

Report whether the login succeeded and the exact flash message.
