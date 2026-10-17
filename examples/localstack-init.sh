#!/bin/sh
# Seeds demo secrets into LocalStack. Runs from /etc/localstack/init/ready.d.
# Paths use the aws provider's default prefix (COATCHECK_AWS_SSM_PREFIX,
# default /coatcheck/secrets/).
set -e
PREFIX="${COATCHECK_AWS_SSM_PREFIX:-/coatcheck/secrets/}"

awslocal ssm put-parameter --type SecureString --overwrite \
  --name "${PREFIX}example-api-key" \
  --value "sk-demo-not-a-real-key"

awslocal ssm put-parameter --type SecureString --overwrite \
  --name "${PREFIX}example-echo-key" \
  --value "sk-demo-echo-not-a-real-key"

awslocal ssm put-parameter --type SecureString --overwrite \
  --name "${PREFIX}example-login" \
  --value '{"username":"demo@example.com","password":"hunter2","_cleartext":["username"]}'
