#!/usr/bin/env bash
# Delete everything setup-aws.sh created. Usage: AWS_PROFILE=… ./teardown-aws.sh
set -uo pipefail
cd "$(dirname "$0")"
: "${AWS_PROFILE:?set AWS_PROFILE}"
REGION="${AWS_REGION:-$(aws configure get region)}"
for p in anthropic-api-key the-internet-login; do
  aws ssm delete-parameter --region "$REGION" --name "/coatcheck/demo/secrets/$p" && echo "deleted ssm $p"
done
aws secretsmanager delete-secret --region "$REGION" --secret-id coatcheck-demo/browserbase-api-key \
  --force-delete-without-recovery >/dev/null && echo "deleted secret browserbase-api-key"
aws iam delete-role-policy --role-name coatcheck-demo-broker --policy-name read-demo-secrets
aws iam delete-role --role-name coatcheck-demo-broker && echo "deleted role coatcheck-demo-broker"
rm -f .external-id
