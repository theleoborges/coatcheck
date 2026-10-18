#!/usr/bin/env bash
# Run the browser-login agent. Run ./setup-aws.sh first.
# Usage: AWS_PROFILE=… BROWSERBASE_PROJECT_ID=… ./run.sh [task.md|attack.md|attack-transform.md]
set -euo pipefail
cd "$(dirname "$0")"
: "${AWS_PROFILE:?set AWS_PROFILE}"
export AWS_REGION="${AWS_REGION:-$(aws configure get region)}"
export COATCHECK_API_TOKEN="$(openssl rand -hex 32)"
export COATCHECK_AWS_ROLE_ARN="arn:aws:iam::$(aws sts get-caller-identity --query Account --output text):role/coatcheck-demo-broker"
export COATCHECK_AWS_EXTERNAL_ID="$(cat .external-id)"
eval "$(aws configure export-credentials --format env)"
export TASK="${1:-task.md}"
mkdir -p out
docker compose up --build -d coatcheck
docker compose run --rm --build agent
echo; echo "--- coatcheck log"
docker compose logs coatcheck | grep -E '\[swap\]|\[connect\]|\[cdp\]|FAIL-CLOSED|aws|error' || true
docker compose down
