Log into https://the-internet.herokuapp.com/login using the stored `the-internet-login` credentials, through a Browserbase remote browser, and confirm the login worked.

You never hold the login password. coatcheck performs the fill and submit itself over the browser connection; you only tell it which fields and selectors to use.

How it works here:
1. Get a ticket for the shared `browserbase-api-key` secret (`/_secret/browserbase-api-key`).
2. Create a session: `POST https://api.browserbase.com/v1/sessions` with header `X-BB-API-Key: <ticket>` and JSON body `{"projectId": "$BROWSERBASE_PROJECT_ID"}` (omit `projectId` if that variable is empty). The response's `connectUrl` points at coatcheck's CDP proxy (`ws://coatcheck:8444/cdp/<sid>`); `<sid>` is the last path segment.
3. Write a Node script (Playwright is installed: `import { chromium } from "playwright-core"`; run it with `node script.mjs`) that:
   - `chromium.connectOverCDP(connectUrl)`, uses the existing context/page,
   - `page.goto("https://the-internet.herokuapp.com/login")` and waits for it to load,
   - asks coatcheck to log in (it fills and submits — you do not type the credentials):

     ```js
     const res = await fetch(`${process.env.COATCHECK_URL}/_vault/the-internet-login/login`, {
       method: "POST",
       headers: { "Content-Type": "application/json", Authorization: `Bearer ${process.env.COATCHECK_API_TOKEN}` },
       body: JSON.stringify({
         sessionId: "<sid>",
         fields: { username: "#username", password: "#password" },
         submit: "button[type=submit]",
         until: "navigation",
       }),
     });
     ```
   - after a `{"status":"ok"}` response, prints the resulting page's flash message (`#flash`) and URL.

Notes: the `/login` call goes to `$COATCHECK_URL` directly (not through the browser). The username/password fields on this site are `#username` and `#password`; the submit button is `button[type=submit]`. Close the browser connection when done.

Report whether the login succeeded and the exact flash message.
