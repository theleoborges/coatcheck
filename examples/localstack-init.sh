#!/bin/sh
# Seeds demo secrets into LocalStack. Runs from /etc/localstack/init/ready.d.
# Path scheme matches the current AWS provider (src/providers/aws.ts); it will
# become configurable once the SecretProvider interface lands (docs/ROADMAP.md).
set -e
LABEL="${AGENT_LABEL:-demo}"

awslocal ssm put-parameter --type SecureString --overwrite \
  --name "/liv/agents/${LABEL}/user-secrets/example-api-key" \
  --value "sk-demo-not-a-real-key"

awslocal ssm put-parameter --type SecureString --overwrite \
  --name "/liv/agents/${LABEL}/user-secrets/example-login" \
  --value '{"username":"demo@example.com","password":"hunter2","_cleartext":["username"]}'
