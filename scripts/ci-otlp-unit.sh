#!/usr/bin/env bash
# Netra — OTLP push exporter unit gate (no root, no collector needed)
#
# Conversion of /metrics to OTLP, watermark/retry/batching semantics, and the
# HA leader-only lifecycle. The HA test is repeated (COUNT, default 3) under
# the race detector because it races two replicas over one lease.
#
# Usage:
#   ./scripts/ci-otlp-unit.sh
#   RACE=0 COUNT=1 ./scripts/ci-otlp-unit.sh
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

RACE="${RACE:-1}"
COUNT="${COUNT:-3}"

RACE_FLAG=()
if [[ "$RACE" == "1" ]]; then
  RACE_FLAG=(-race)
fi

echo "==> otlppush: conversion, watermarks, retry, batching, redirects, redaction"
go test "${RACE_FLAG[@]}" -count="$COUNT" ./internal/otlppush/...

echo "==> netrad: wiring against the real API /metrics, and HA demote tears the exporter down"
go test "${RACE_FLAG[@]}" -count="$COUNT" ./cmd/netrad/ -run 'StartOTLP|ElectionLoop'
