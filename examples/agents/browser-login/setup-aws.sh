#!/usr/bin/env bash
# Create the ephemeral AWS resources for the browser-login example.
#   - SSM SecureStrings under /coatcheck/demo/secrets/ (anthropic key, test-site login)
#   - Secrets Manager coatcheck-demo/browserbase-api-key (shared key)
#   - IAM role coatcheck-demo-broker: read-only on exactly those, assumable by the
#     calling identity only with an ExternalId (the pattern from docs/deploy/aws-ecs.md)
# Usage: AWS_PROFILE=liv ANTHROPIC_API_KEY=… BROWSERBASE_API_KEY=… ./setup-aws.sh
# Remove everything with ./teardown-aws.sh.
set -euo pipefail
cd "$(dirname "$0")"
: "${AWS_PROFILE:?set AWS_PROFILE}" "${ANTHROPIC_API_KEY:?set ANTHROPIC_API_KEY}"
REGION="${AWS_REGION:-$(aws configure get region)}"
ACCOUNT="$(aws sts get-caller-identity --query Account --output text)"
CALLER="$(aws sts get-caller-identity --query Arn --output text)"
ROLE=coatcheck-demo-broker
SSM_PREFIX=/coatcheck/demo/secrets/
SM_PREFIX=coatcheck-demo/
TAGS='Key=purpose,Value=coatcheck-demo'

put_ssm() {
  aws ssm put-parameter --region "$REGION" --type SecureString --overwrite \
    --name "${SSM_PREFIX}$1" --value "$2" >/dev/null
  aws ssm add-tags-to-resource --region "$REGION" --resource-type Parameter \
    --resource-id "${SSM_PREFIX}$1" --tags "$TAGS"
  echo "ssm: ${SSM_PREFIX}$1"
}
put_ssm anthropic-api-key "$ANTHROPIC_API_KEY"
# Public practice-site credentials (https://the-internet.herokuapp.com/login), not a real account.
put_ssm the-internet-login '{"username":"tomsmith","password":"SuperSecretPassword!","_allowed_hosts":["the-internet.herokuapp.com"]}'

if [ -n "${BROWSERBASE_API_KEY:-}" ]; then
  if aws secretsmanager describe-secret --region "$REGION" --secret-id "${SM_PREFIX}browserbase-api-key" >/dev/null 2>&1; then
    aws secretsmanager put-secret-value --region "$REGION" --secret-id "${SM_PREFIX}browserbase-api-key" \
      --secret-string "$BROWSERBASE_API_KEY" >/dev/null
  else
    aws secretsmanager create-secret --region "$REGION" --name "${SM_PREFIX}browserbase-api-key" \
      --secret-string "$BROWSERBASE_API_KEY" --tags "$TAGS" >/dev/null
  fi
  echo "secretsmanager: ${SM_PREFIX}browserbase-api-key"
else
  echo "secretsmanager: skipped (BROWSERBASE_API_KEY not set)"
fi

EXTERNAL_ID_FILE=.external-id
[ -s "$EXTERNAL_ID_FILE" ] || openssl rand -hex 16 > "$EXTERNAL_ID_FILE"
EXTERNAL_ID="$(cat "$EXTERNAL_ID_FILE")"
TRUST=$(cat <<JSON
{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"$CALLER"},
 "Action":"sts:AssumeRole","Condition":{"StringEquals":{"sts:ExternalId":"$EXTERNAL_ID"}}}]}
JSON
)
if aws iam get-role --role-name "$ROLE" >/dev/null 2>&1; then
  aws iam update-assume-role-policy --role-name "$ROLE" --policy-document "$TRUST"
else
  aws iam create-role --role-name "$ROLE" --assume-role-policy-document "$TRUST" --tags "$TAGS" >/dev/null
fi
aws iam put-role-policy --role-name "$ROLE" --policy-name read-demo-secrets --policy-document "$(cat <<JSON
{"Version":"2012-10-17","Statement":[
 {"Effect":"Allow","Action":["ssm:GetParameter","ssm:GetParametersByPath"],
  "Resource":["arn:aws:ssm:$REGION:$ACCOUNT:parameter${SSM_PREFIX}*","arn:aws:ssm:$REGION:$ACCOUNT:parameter${SSM_PREFIX%/}"]},
 {"Effect":"Allow","Action":"secretsmanager:GetSecretValue",
  "Resource":"arn:aws:secretsmanager:$REGION:$ACCOUNT:secret:${SM_PREFIX}*"}]}
JSON
)"
echo "iam: role $ROLE (ExternalId in $EXTERNAL_ID_FILE)"
