# Sourced by run.sh and smoke.sh: a fresh API token, the reporter key from
# .aws-reporter-key (for coatcheck only) and policy.json rendered from
# policy.template.json with the bucket and region.
KEY_FILE=.aws-reporter-key
[ -s "$KEY_FILE" ] || { echo "no $KEY_FILE: run ./setup-aws.sh first" >&2; exit 1; }
export COATCHECK_API_TOKEN="$(openssl rand -hex 32)"
export BUCKET="$(jq -r .bucket "$KEY_FILE")"
export REGION="$(jq -r .region "$KEY_FILE")"
# The secret coatcheck holds: the key (signing), bucket and region as cleartext fields.
export COATCHECK_SECRET_AWS_REPORTS="$(jq -c '{access_key_id, secret_access_key, bucket, region, _cleartext: ["bucket", "region"]}' "$KEY_FILE")"
sed -e "s/\${BUCKET}/$BUCKET/g" -e "s/\${REGION}/$REGION/g" policy.template.json > policy.json
