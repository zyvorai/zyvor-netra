#!/usr/bin/env bash
# Netra — Loki push sink unit gate (no root, no Loki needed)
#
# The Loki client against a fake that decodes real push payloads, the delivery
# logic it shares with the OTLP exporter (watermarks, per-node block watermarks,
# retry vs drop of a permanently rejected batch), and netrad's wiring
# (fail-fast config, lifecycle). Live counterpart against a real Loki:
# scripts/ci-loki-live.sh.
#
# Usage:
#   ./scripts/ci-loki-unit.sh
#   RACE=0 COUNT=3 ./scripts/ci-loki-unit.sh
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

RACE="${RACE:-1}"
COUNT="${COUNT:-1}"

RACE_FLAG=()
if [[ "$RACE" == "1" ]]; then
  RACE_FLAG=(-race)
fi

echo "==> pushfeed: watermarks, batching/resume, permanent-vs-transient failures"
go test "${RACE_FLAG[@]}" -count="$COUNT" ./internal/pushfeed/...

echo "==> lokipush: payload shape, bounded labels, ordering, gzip/size split, retry vs drop"
go test "${RACE_FLAG[@]}" -count="$COUNT" ./internal/lokipush/...

echo "==> otlppush: still correct on the shared delivery logic"
go test "${RACE_FLAG[@]}" -count="$COUNT" ./internal/otlppush/...

echo "==> netrad: loki wiring (fail-fast config, lifecycle)"
go test "${RACE_FLAG[@]}" -count="$COUNT" ./cmd/netrad/ -run 'StartLoki'
