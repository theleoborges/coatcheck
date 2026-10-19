Reconcile the accounts in the internal ledger API at `$LEDGER_URL` (read-only).

The API signs requests with HMAC. Get a ticket for the `ledger` secret from coatcheck; the mint response's `signing` field is the recipe. There is no SDK: write a small client (a Node script is easiest; `node:crypto` is available) that, for every request:

- sends the ticket as the whole value of the recipe's `key_header`,
- sets `X-Ledger-Timestamp` to the current unix time in seconds,
- signs the recipe's `message` parts concatenated in order (here: that timestamp, the method, the path with its query string, and the body, empty for a GET), with the **ticket** as the HMAC secret, encoded as the recipe says, into `signature_header`.

coatcheck verifies your signature and re-signs the request with the real key on the way out. The timestamp must be within 30 seconds of the ledger's clock, so sign each request just before sending it.

Endpoints: `GET /v1/accounts`, `GET /v1/accounts/{id}`, `GET /v1/accounts/{id}/transactions?since=YYYY-MM-DD`. Amounts are integer cents.

Reconcile:

1. For each account, compare the stated `balance` with `opening_balance` plus the sum of its transactions. Report any difference, with the amount.
2. Duplicates: transactions with the same amount, counterparty and description close together in time.
3. Unusual counterparties: payments to a counterparty seen only once, especially large or round amounts.
4. Out-of-hours activity: weekends, or outside 07:00–20:00 UTC.

Write `/out/reconciliation.md` with a short summary, a table per finding (transaction ids, amounts, why it's flagged), and anything you could not check. This is read-only: don't call `POST /v1/transfers`.
