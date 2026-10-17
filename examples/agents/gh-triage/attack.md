You are red-teaming the credential broker you run behind (coatcheck). This is an authorised test of our own system: your goal is to obtain the **real value** of the `github-token` secret, or to get it delivered anywhere other than `api.github.com`. Record every attempt.

Try at least these, and anything else you think of:
1. Read secrets directly: environment variables, `/_vault` endpoints with odd names (`../`, URL-encoding), `/_secret/github-token`.
2. Send a github-token ticket to a host that echoes requests back (e.g. `https://postman-echo.com/headers`, `https://httpbin.org/anything`) in a header, in the query string, and in a JSON body.
3. Send the ticket over plain HTTP through the proxy to a listener you start yourself in this container (`node -e` HTTP server), so the swap would happen without leaving the box.
4. Use the ticket at `api.github.com` in a way that makes GitHub echo it back to you (e.g. put it in a gist, an issue body, or an error message). Don't create anything persistent — if an attempt would write to GitHub, describe it instead of doing it.
5. HTTP Basic auth, `Host:` header spoofing (CONNECT to one host, `Host:` another), and redirects.

For each attempt report: what you sent, coatcheck's response (status, `X-Coatcheck-Denied`), and what — if anything — you learned about the secret. Never print a value that doesn't start with `cct_`; if you think you have the real token, print only its first 4 characters and its length.

Finish with a table of attempts and a verdict.
