#!/usr/bin/env bash
# Create the AWS resources for the vercel-release-report example, all tagged
# purpose=coatcheck-demo:
#   - S3 bucket coatcheck-demo-reports-<account-id> (public access blocked,
#     default encryption)
#   - IAM user coatcheck-demo-reporter, inline policy: s3:PutObject/s3:GetObject
#     on reports/*, s3:ListBucket with the reports/ prefix condition, nothing else
#   - one access key for it, written to .aws-reporter-key (git-ignored, mode 0600)
#     together with the bucket and region; run.sh hands it to coatcheck only
# Safe to re-run (an existing key file is kept). Remove everything with ./teardown-aws.sh.
# Usage: AWS_PROFILE=… [AWS_REGION=…] ./setup-aws.sh
set -euo pipefail
cd "$(dirname "$0")"
: "${AWS_PROFILE:?set AWS_PROFILE}"
REGION="${AWS_REGION:-$(aws configure get region)}"
: "${REGION:?set AWS_REGION or a default region on the profile}"
ACCOUNT="$(aws sts get-caller-identity --query Account --output text)"
BUCKET="coatcheck-demo-reports-${ACCOUNT}"
USER_NAME=coatcheck-demo-reporter
KEY_FILE=.aws-reporter-key

if aws s3api head-bucket --bucket "$BUCKET" --region "$REGION" >/dev/null 2>&1; then
  echo "s3: bucket $BUCKET exists"
else
  if [ "$REGION" = us-east-1 ]; then
    aws s3api create-bucket --bucket "$BUCKET" --region "$REGION" >/dev/null
  else
    aws s3api create-bucket --bucket "$BUCKET" --region "$REGION" \
      --create-bucket-configuration "LocationConstraint=$REGION" >/dev/null
  fi
  echo "s3: created bucket $BUCKET"
fi
aws s3api put-public-access-block --bucket "$BUCKET" --region "$REGION" --public-access-block-configuration \
  BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true
aws s3api put-bucket-encryption --bucket "$BUCKET" --region "$REGION" --server-side-encryption-configuration \
  '{"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"AES256"}}]}'
aws s3api put-bucket-tagging --bucket "$BUCKET" --region "$REGION" --tagging 'TagSet=[{Key=purpose,Value=coatcheck-demo}]'

if aws iam get-user --user-name "$USER_NAME" >/dev/null 2>&1; then
  echo "iam: user $USER_NAME exists"
else
  aws iam create-user --user-name "$USER_NAME" --tags Key=purpose,Value=coatcheck-demo >/dev/null
  echo "iam: created user $USER_NAME"
fi
aws iam put-user-policy --user-name "$USER_NAME" --policy-name reports-only --policy-document "$(cat <<JSON
{"Version":"2012-10-17","Statement":[
 {"Effect":"Allow","Action":["s3:PutObject","s3:GetObject"],"Resource":"arn:aws:s3:::$BUCKET/reports/*"},
 {"Effect":"Allow","Action":"s3:ListBucket","Resource":"arn:aws:s3:::$BUCKET",
  "Condition":{"StringLike":{"s3:prefix":["reports/","reports/*"]}}}]}
JSON
)"
echo "iam: inline policy reports-only (reports/* only)"

if [ -s "$KEY_FILE" ]; then
  echo "key: $KEY_FILE exists, kept (delete it and re-run to rotate)"
else
  umask 077
  aws iam create-access-key --user-name "$USER_NAME" --output json \
    | jq --arg bucket "$BUCKET" --arg region "$REGION" \
        '{access_key_id: .AccessKey.AccessKeyId, secret_access_key: .AccessKey.SecretAccessKey, bucket: $bucket, region: $region}' \
    > "$KEY_FILE"
  chmod 600 "$KEY_FILE"
  echo "key: new access key for $USER_NAME in $KEY_FILE (mode 0600)"
fi
