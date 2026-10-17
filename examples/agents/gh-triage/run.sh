#!/usr/bin/env bash
# Run the gh-triage agent. Usage: ./run.sh [task.md]
set -euo pipefail
cd "$(dirname "$0")"
export COATCHECK_API_TOKEN="$(openssl rand -hex 32)"
export GITHUB_TOKEN="${GITHUB_TOKEN:-$(gh auth token)}"
export TASK="${1:-task.md}"
mkdir -p out
docker compose up --build -d coatcheck
docker compose run --rm --build agent
echo; echo "--- coatcheck swap log"
docker compose logs coatcheck | grep -E '\[swap\]|\[connect\]' || true
docker compose down
