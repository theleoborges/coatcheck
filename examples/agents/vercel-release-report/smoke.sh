#!/usr/bin/env bash
# Verify the compose stack with no model: run, inside the agent container, the
# commands the agent would (sts get-caller-identity, s3 cp, s3 ls, one Vercel
# call), then the negative checks (another bucket, a presigned URL), then
# assert coatcheck's [swap] lines. Needs ./setup-aws.sh and Vercel credentials;
# no Anthropic key (the agent loop isn't run).
# Usage: VERCEL_TOKEN=… VERCEL_PROJECT=… [VERCEL_TEAM_ID=…] ./smoke.sh
set -euo pipefail
cd "$(dirname "$0")"
export ANTHROPIC_API_KEY="${ANTHROPIC_API_KEY:-smoke-unused}"
: "${VERCEL_TOKEN:?set VERCEL_TOKEN}" "${VERCEL_PROJECT:?set VERCEL_PROJECT}"
. ./env.sh
trap 'docker compose down >/dev/null 2>&1 || true' EXIT
docker compose up --build -d coatcheck
docker compose build agent

status=0
docker compose run --rm -T agent bash -s <<'INNER' || status=1
set -uo pipefail
fail=0
pass() { echo "ok   $1"; }
flunk() { echo "FAIL $1"; fail=1; }
H="Authorization: Bearer $COATCHECK_API_TOKEN"
AWS_TOK="$(curl -sf -H "$H" "$COATCHECK_URL/_vault/aws-reports" | jq -r .token)"
VERCEL_TOK="$(curl -sf -H "$H" "$COATCHECK_URL/_vault/vercel-token" | jq -r .token)"
case "$AWS_TOK" in cct_*) pass "mint aws-reports (signing ticket)";; *) flunk "mint aws-reports"; exit 1;; esac
case "$VERCEL_TOK" in cct_*) pass "mint vercel-token";; *) flunk "mint vercel-token"; exit 1;; esac
export AWS_ACCESS_KEY_ID="$AWS_TOK" AWS_SECRET_ACCESS_KEY="$AWS_TOK"

# Buffered, hashed-body path (form POST, no payload-hash header).
arn="$(aws sts get-caller-identity --query Arn --output text 2>&1)"
case "$arn" in *:user/coatcheck-demo-reporter) pass "sts get-caller-identity ($arn)";; *) flunk "sts get-caller-identity: $arn";; esac

# Streamed S3 upload (payload-hash header), then a list.
name="smoke-$(date -u +%Y%m%dT%H%M%SZ).md"
printf '# coatcheck smoke test\n\n%s\n' "$(date -u)" > "/tmp/$name"
if aws s3 cp "/tmp/$name" "s3://$REPORTS_BUCKET/reports/smoke/$name" --only-show-errors; then pass "s3 cp reports/smoke/$name"; else flunk "s3 cp"; fi
if aws s3 ls "s3://$REPORTS_BUCKET/reports/smoke/" | grep -q "$name"; then pass "s3 ls shows it"; else flunk "s3 ls"; fi

# The literal bearer path: GET /v7/deployments (https://vercel.com/docs/rest-api/deployments/list-deployments).
code="$(curl -s -o /tmp/deployments.json -w '%{http_code}' -H "Authorization: Bearer $VERCEL_TOK" \
  "https://api.vercel.com/v7/deployments?projectId=$VERCEL_PROJECT&target=production&limit=1${VERCEL_TEAM_ID:+&teamId=$VERCEL_TEAM_ID}")"
if [ "$code" = 200 ] && jq -e '.deployments | type == "array"' /tmp/deployments.json >/dev/null; then pass "vercel deployments list (200)"; else flunk "vercel deployments list ($code)"; fi

# Negative: another bucket is another virtual host, not an allowed host: coatcheck refuses before IAM sees it.
other="coatcheck-demo-not-allowed-$RANDOM$RANDOM"
out="$(aws s3 ls "s3://$other/" 2>&1)"
case "$out" in *403*|*Forbidden*) pass "other bucket refused (403)";; *) flunk "other bucket: $out";; esac

# Negative: a presigned URL carries the ticket in the query; it leaves as a literal and S3 rejects it.
url="$(aws s3 presign "s3://$REPORTS_BUCKET/reports/smoke/$name" --expires-in 60)"
code="$(curl -s -o /tmp/presign.xml -w '%{http_code}' "$url")"
if [ "$code" = 403 ] && grep -q InvalidAccessKeyId /tmp/presign.xml; then pass "presigned URL fails closed (403 InvalidAccessKeyId)"; else flunk "presigned URL ($code)"; fi
exit "$fail"
INNER

echo; echo "--- coatcheck swap log"
logs="$(docker compose logs coatcheck)"
echo "$logs" | grep -E '\[swap\]|\[connect\]' || true
signed="$(echo "$logs" | grep -c 'result=signed signing=aws-sigv4 secrets=aws-reports' || true)"
if [ "$signed" -ge 3 ]; then echo "ok   $signed result=signed lines"; else echo "FAIL expected >= 3 result=signed lines, got $signed"; status=1; fi
if echo "$logs" | grep -q "result=denied secrets=aws-reports"; then echo "ok   result=denied for the other bucket"; else echo "FAIL no result=denied line"; status=1; fi
if echo "$logs" | grep -q "result=placement-skipped secrets=aws-reports where=url"; then echo "ok   presigned URL: placement-skipped"; else echo "FAIL no placement-skipped line"; status=1; fi
if echo "$logs" | grep -q "result=hit secrets=vercel-token"; then echo "ok   vercel-token swapped"; else echo "FAIL no vercel-token hit"; status=1; fi
[ "$status" = 0 ] && echo "smoke: PASS" || echo "smoke: FAIL"
exit "$status"
