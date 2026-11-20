#!/usr/bin/env bash
# Netra — TLS fingerprint unit + race gate (no root, no BPF attach)
#
# Runs every Go test under internal/tlsfp plus the API surface tests that
# cover GET /api/v1/ebpf/tls-fingerprints and /risk. Intended for local
# pre-push and the GitHub `go` job (alongside the privileged
# scripts/ci-tlsfp-smoke.sh).
#
# Usage:
#   ./scripts/ci-tlsfp-unit.sh
#   RACE=0 ./scripts/ci-tlsfp-unit.sh   # skip -race
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

RACE="${RACE:-1}"
COUNT="${COUNT:-1}"

echo "==> tlsfp package tests (count=${COUNT})"
go test ./internal/tlsfp/... -count="$COUNT"

echo "==> API TLS fingerprint surface tests"
go test ./internal/api/ -run 'TLSFingerprint' -count="$COUNT"

if [[ "$RACE" == "1" ]]; then
  echo "==> tlsfp race detector"
  go test ./internal/tlsfp/... -race -count=1
fi

echo "==> PASS ci-tlsfp-unit"
