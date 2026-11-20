#!/usr/bin/env bash
# Netra — full netractl command catalog gate (mock API, no cluster)
#
# Exercises every entry in cmd/netractl/commands_catalog.go against an
# httptest mock so argv→HTTP wiring cannot regress without a dedicated CI
# failure. Mutating examples are included (mock only).
#
# Usage:
#   ./scripts/ci-netractl-commands.sh
#   RACE=0 ./scripts/ci-netractl-commands.sh
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

RACE="${RACE:-1}"
COUNT="${COUNT:-1}"

RACE_FLAG=()
if [[ "$RACE" == "1" ]]; then
  RACE_FLAG=(-race)
fi

echo "==> netractl command catalog (unique names + mock API)"
go test "${RACE_FLAG[@]}" -count="$COUNT" ./cmd/netractl/ -run 'TestAllCLICommandsAgainstMock|TestCLICommandCatalogUniqueNames'

echo "ci-netractl-commands: ok"
