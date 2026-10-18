# Sourced by run.sh and smoke.sh: a fresh API token, fresh ledger keys, and a
# self-signed certificate for the ledger (SAN DNS:ledger) in certs/ (git-ignored).
export COATCHECK_API_TOKEN="$(openssl rand -hex 32)"
export LEDGER_AUDITOR_KEY_ID="auditor-$(openssl rand -hex 4)"
export LEDGER_AUDITOR_SECRET="$(openssl rand -hex 32)"
export LEDGER_OPERATOR_KEY_ID="operator-$(openssl rand -hex 4)"
export LEDGER_OPERATOR_SECRET="$(openssl rand -hex 32)"
# What coatcheck holds: the auditor key only.
export COATCHECK_SECRET_LEDGER="{\"key_id\":\"$LEDGER_AUDITOR_KEY_ID\",\"secret\":\"$LEDGER_AUDITOR_SECRET\"}"
# Regenerated when missing or expiring within a day (it is valid for 30 days).
if [ ! -s certs/ledger.crt ] || [ ! -s certs/ledger.key ] \
  || ! openssl x509 -checkend 86400 -noout -in certs/ledger.crt >/dev/null 2>&1; then
  mkdir -p certs
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 30 \
    -subj "/CN=ledger" -addext "subjectAltName=DNS:ledger" \
    -keyout certs/ledger.key -out certs/ledger.crt 2>certs/openssl.log \
    || { echo "generating the ledger certificate failed:" >&2; cat certs/openssl.log >&2; exit 1; }
  # Readable by the service's unprivileged user inside the container (a throwaway demo key).
  chmod 644 certs/ledger.key
fi
