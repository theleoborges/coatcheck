#!/usr/bin/env bash
# Verify the compose stack with no model: inside the agent container, sign and
# send what the agent's client would (one GET, asserting 200), run the negative
# checks, then assert coatcheck's `result=signed signing=hmac` lines.
# Needs Docker and openssl only.
# Usage: ./smoke.sh
set -euo pipefail
cd "$(dirname "$0")"
export ANTHROPIC_API_KEY="${ANTHROPIC_API_KEY:-smoke-unused}"
. ./env.sh
trap 'docker compose down >/dev/null 2>&1 || true' EXIT
docker compose up --build -d ledger coatcheck
docker compose build agent

status=0
docker compose run --rm -T agent bash -s <<'INNER' || status=1
set -uo pipefail
fail=0
pass() { echo "ok   $1"; }
flunk() { echo "FAIL $1"; fail=1; }
H="Authorization: Bearer $COATCHECK_API_TOKEN"

# The agent's own client: HMAC-SHA256 over timestamp + method + path_query + body,
# base64, with the ticket as the secret; the ticket in X-Ledger-Key.
cat > /tmp/sign.mjs <<'JS'
import { createHmac } from 'node:crypto';
const [key, message] = process.argv.slice(2);
process.stdout.write(createHmac('sha256', key).update(message).digest('base64'));
JS
# ledger <ticket> <method> <path_query> [body] [timestamp] [signed-path-override]
ledger() {
  local tok="$1" method="$2" pq="$3" body="${4:-}" ts="${5:-$(date +%s)}" signed_pq="${6:-$3}"
  local sig; sig="$(node /tmp/sign.mjs "$tok" "${ts}${method}${signed_pq}${body}")"
  local extra=()
  [ -n "$body" ] && extra=(-H 'Content-Type: application/json' --data-binary "$body")
  curl -s -o /tmp/resp.json -w '%{http_code}' -X "$method" \
    -H "X-Ledger-Key: $tok" -H "X-Ledger-Timestamp: $ts" -H "X-Ledger-Signature: $sig" \
    "${extra[@]}" "$LEDGER_URL$pq"
}

mint="$(curl -sf -H "$H" "$COATCHECK_URL/_vault/ledger")"
TOK="$(echo "$mint" | jq -r .token)"
case "$TOK" in cct_*) pass "mint ledger (signing ticket)";; *) flunk "mint ledger: $mint"; exit 1;; esac
if echo "$mint" | jq -e '.signing.type == "hmac" and .signing.key_header == "X-Ledger-Key" and (.signing | has("key_id") | not)' >/dev/null; then
  pass "mint response carries the public recipe"; else flunk "recipe in mint response"; fi

code="$(ledger "$TOK" GET /v1/accounts)"
if [ "$code" = 200 ] && [ "$(jq '.accounts | length' /tmp/resp.json)" = 3 ]; then pass "GET /v1/accounts (200, 3 accounts)"; else flunk "GET /v1/accounts ($code)"; fi
code="$(ledger "$TOK" GET '/v1/accounts/acc_ops/transactions?since=2026-09-01')"
if [ "$code" = 200 ] && [ "$(jq '.transactions | length' /tmp/resp.json)" -gt 10 ]; then pass "GET transactions with a query (200)"; else flunk "GET transactions ($code)"; fi

# Negative checks.
code="$(curl -s -o /dev/null -w '%{http_code}' -H "$H" "$COATCHECK_URL/_vault/ledger?field=secret")"
[ "$code" = 400 ] && pass "?field=secret refused (400)" || flunk "?field=secret ($code)"
if env | grep -qi 'ledger_.*secret'; then flunk "a ledger secret is in the agent's env"; else pass "no ledger secret in the agent's env"; fi
code="$(curl -s -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $TOK" "$LEDGER_URL/v1/accounts")"
[ "$code" = 401 ] && pass "ticket as a bearer literal: service 401" || flunk "bearer literal ($code)"
code="$(ledger "$TOK" GET /v1/accounts/acc_ops '' "$(date +%s)" /v1/accounts)"
[ "$code" = 403 ] && pass "signature over a different message: 403 signature-mismatch" || flunk "different message ($code)"
code="$(ledger "$TOK" GET /v1/accounts '' "$(( $(date +%s) - 600 ))")"
[ "$code" = 401 ] && [ "$(jq -r .reason /tmp/resp.json)" = stale-timestamp ] && pass "replayed old timestamp: service 401 stale-timestamp" || flunk "old timestamp ($code)"
code="$(ledger "$TOK" POST /v1/transfers '{"from":"acc_reserve","to":"acc_ops","amount":100}')"
[ "$code" = 403 ] && pass "POST /v1/transfers with the auditor key: service 403" || flunk "POST transfers ($code)"
if curl -s --max-time 5 --noproxy '*' -o /dev/null "$LEDGER_URL/v1/accounts"; then flunk "reached the ledger without the proxy"; else pass "no route to the ledger without the proxy"; fi
exit "$fail"
INNER

echo; echo "--- coatcheck swap log"
logs="$(docker compose logs coatcheck)"
echo "$logs" | grep -E '\[swap\]|\[connect\]' || true
echo; echo "--- ledger log"
docker compose logs ledger | grep -E '\[ledger\]' || true
check() { if echo "$logs" | grep -q "$2"; then echo "ok   $1"; else echo "FAIL $1"; status=1; fi; }
signed="$(echo "$logs" | grep -c 'result=signed signing=hmac secrets=ledger' || true)"
if [ "$signed" -ge 4 ]; then echo "ok   $signed result=signed signing=hmac lines"; else echo "FAIL expected >= 4 result=signed signing=hmac lines, got $signed"; status=1; fi
check "signature-mismatch logged" 'result=signature-mismatch secrets=ledger'
check "bearer literal logged as signing-skipped" 'result=signing-skipped secrets=ledger'
if echo "$logs" | grep -q "$LEDGER_AUDITOR_SECRET"; then echo "FAIL the auditor secret appears in coatcheck's log"; status=1; else echo "ok   no secret in coatcheck's log"; fi
[ "$status" = 0 ] && echo "smoke: PASS" || echo "smoke: FAIL"
exit "$status"
