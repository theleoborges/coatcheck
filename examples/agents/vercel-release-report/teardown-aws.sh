#!/usr/bin/env bash
# Delete everything setup-aws.sh created: the reporter's access keys and user,
# the bucket's objects and the bucket, and .aws-reporter-key.
# Usage: AWS_PROFILE=… [AWS_REGION=…] ./teardown-aws.sh
set -uo pipefail
cd "$(dirname "$0")"
: "${AWS_PROFILE:?set AWS_PROFILE}"
REGION="${AWS_REGION:-$(aws configure get region)}"
ACCOUNT="$(aws sts get-caller-identity --query Account --output text)"
BUCKET="coatcheck-demo-reports-${ACCOUNT}"
USER_NAME=coatcheck-demo-reporter
for key in $(aws iam list-access-keys --user-name "$USER_NAME" --query 'AccessKeyMetadata[].AccessKeyId' --output text 2>/dev/null); do
  aws iam delete-access-key --user-name "$USER_NAME" --access-key-id "$key" && echo "deleted access key $key"
done
aws iam delete-user-policy --user-name "$USER_NAME" --policy-name reports-only
aws iam delete-user --user-name "$USER_NAME" && echo "deleted user $USER_NAME"
aws s3 rm "s3://$BUCKET" --recursive --region "$REGION" && aws s3api delete-bucket --bucket "$BUCKET" --region "$REGION" && echo "deleted bucket $BUCKET"
rm -f .aws-reporter-key
