#!/bin/sh
# Trust coatcheck's CA, then run the agent as the unprivileged `node` user.
set -e
for i in $(seq 1 30); do
  curl -sf "$COATCHECK_URL/_health" >/dev/null && break
  sleep 1
done
curl -sf "$COATCHECK_URL/_ca" -o /usr/local/share/ca-certificates/coatcheck-ca.crt
update-ca-certificates >/dev/null 2>&1
export NODE_EXTRA_CA_CERTS=/usr/local/share/ca-certificates/coatcheck-ca.crt
exec setpriv --reuid=node --regid=node --init-groups env HOME=/home/node "$@"
