#!/usr/bin/env bash
# Run the vercel-release-report agent. Run ./setup-aws.sh first.
# Usage: ANTHROPIC_API_KEY=… VERCEL_TOKEN=… VERCEL_PROJECT=… [VERCEL_TEAM_ID=…] ./run.sh [task.md|attack.md]
# No AWS profile is needed here: coatcheck gets the reporter's key from .aws-reporter-key.
set -euo pipefail
cd "$(dirname "$0")"
. ./env.sh
export TASK="${1:-task.md}"
mkdir -p out
# Print the swap log and stop the stack even when the agent run fails.
finish() {
  echo; echo "--- coatcheck swap log"
  docker compose logs coatcheck | grep -E '\[swap\]|\[connect\]|\[issue\]' || true
  docker compose down
}
trap finish EXIT
docker compose up --build -d coatcheck
docker compose run --rm --build agent
