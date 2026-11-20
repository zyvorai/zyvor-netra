#!/usr/bin/env bash
# Netra — BPF attachment inventory gate (no BPF, no root)
#
# Read-only inventory of the BPF programs attached to a node's interfaces
# (docs/bpf-attachments.md) and the drift check between what the agent believes it
# attached and what the kernel reports: the collector (owner classification, the
# kernel's 15-character program names, the interface cap, a failed query recorded
# and never read as "detached"), the diagnostic for every drift case and every
# case it must NOT report, the agent's unchanged-summary protocol, the controller's
# hash-checked carry-forward, the API, the metric bounds and the health integration.
# The real-kernel half (real TCX, XDP and cls_bpf attachments, a detached hook, a
# recreated interface) needs root and runs in scripts/ci-ebpf-tests.sh.
#
# Each step asserts a minimum number of passing tests, so a renamed test cannot
# silently drop out of a -run filter.
#
# Usage:
#   ./scripts/ci-bpfattach-unit.sh
#   RACE=0 ./scripts/ci-bpfattach-unit.sh
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

RACE="${RACE:-1}"
COUNT="${COUNT:-1}"

expect_min() { # expect_min <label> <minimum passing tests> <go test args...>
  local label=$1 min=$2 out n
  shift 2
  echo "==> ${label}"
  out="$(go test -v -count="$COUNT" "$@" 2>&1)" || { echo "$out"; exit 1; }
  n="$(grep -c -- '^--- PASS' <<<"$out" || true)"
  if (( n < min )); then
    echo "$out"
    echo "${label}: only ${n} tests passed, expected at least ${min}" >&2
    exit 1
  fi
  echo "    ${n} tests passed"
}

echo "==> vet"
go vet ./internal/bpfattach/... ./internal/bpfattachdiag/... ./internal/store/ ./internal/api/ ./internal/health/
GOOS=linux go vet ./internal/bpfattach/... ./internal/agent/
GOOS=linux go vet -tags=bpfintegration ./bpf/integration/

expect_min "collector (owners, truncated names, cap, failures, hash)" 8 ./internal/bpfattach/...
expect_min "drift diagnostic (every drift case and every false alarm)" 11 ./internal/bpfattachdiag/...
expect_min "agent modes and the unchanged-summary protocol" 3 ./internal/agent/ -run 'BPFAttach'
expect_min "controller carry-forward" 3 ./internal/store/ -run 'BPFAttach'
expect_min "API, metric bounds" 3 ./internal/api/ -run 'BPFAttach'
expect_min "health integration" 1 ./internal/health/ -run 'BPFAttach'

if [[ "$RACE" == "1" ]]; then
  echo "==> race detector"
  go test -race -count=1 ./internal/bpfattach/... ./internal/bpfattachdiag/...
  go test -race -count=1 ./internal/agent/ -run 'BPFAttach'
  go test -race -count=1 ./internal/store/ -run 'BPFAttach'
  go test -race -count=1 ./internal/api/ -run 'BPFAttach'
  go test -race -count=1 ./internal/health/ -run 'BPFAttach'
fi

echo "==> non-Linux stub and arm64 build"
GOOS=darwin GOARCH=arm64 go build ./internal/bpfattach/... ./internal/agent/
GOOS=linux GOARCH=arm64 go build ./internal/bpfattach/... ./internal/agent/

echo "==> PASS ci-bpfattach-unit"
