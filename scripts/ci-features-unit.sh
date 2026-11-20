#!/usr/bin/env bash
# Netra — features catalog + CLI status/banner unit gate (no root)
#
# Focused suite for Cilium-style operator UX: feature catalog, API handlers,
# netractl status/banner/redact helpers. Kept as an explicit script so CI and
# local agents run the same command.
#
# Usage:
#   ./scripts/ci-features-unit.sh
#   RACE=0 ./scripts/ci-features-unit.sh
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

RACE="${RACE:-1}"
COUNT="${COUNT:-1}"

RACE_FLAG=()
if [[ "$RACE" == "1" ]]; then
  RACE_FLAG=(-race)
fi

echo "==> features catalog + helm argv"
go test "${RACE_FLAG[@]}" -count="$COUNT" ./internal/features/...

echo "==> netractl banner / status / redact / install-cli"
go test "${RACE_FLAG[@]}" -count="$COUNT" ./cmd/netractl/ -run 'Banner|FormatStatus|RedactHelm|ResolveCLI|InstallSelf|DefaultCLI'

echo "==> API features handlers + route registration"
go test "${RACE_FLAG[@]}" -count="$COUNT" ./internal/api/ -run 'Feature|RegisteredAPIRoutes'

echo "ci-features-unit: ok"
