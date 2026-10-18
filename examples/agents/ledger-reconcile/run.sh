#!/usr/bin/env bash
# Run the ledger-reconcile agent. Everything runs locally except the model.
# Usage: ANTHROPIC_API_KEY=… ./run.sh [task.md|attack.md]
set -euo pipefail
cd "$(dirname "$0")"
. ./env.sh
export TASK="${1:-task.md}"
mkdir -p out
# Print the logs and stop the stack even when the agent run fails.
finish() {
  echo; echo "--- coatcheck swap log"
  docker compose logs coatcheck | grep -E '\[swap\]|\[connect\]|\[issue\]' || true
  echo; echo "--- ledger log"
  docker compose logs ledger | grep -E '\[ledger\]' || true
  docker compose down
}
trap finish EXIT
docker compose up --build -d ledger coatcheck
docker compose run --rm --build agent
