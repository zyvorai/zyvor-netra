#!/usr/bin/env bash
# Netra — listen-queue sampling gate (no BPF, no root)
#
# TCP accept-queue depth per listener, read from inet_diag (docs/listen-queues.md):
# the fill/saturation arithmetic, the histogram and peaks, the real kernel's
# inet_diag (a backlog-1 listener that never accepts, IPv6, accept draining the
# queue, a cross-check against /proc/net/tcp), the agent's modes and the
# controller's aggregation and metric bounds. The real-kernel tests open
# loopback listeners and need no privilege; the half-open (SYN_RECV) case needs
# root and nft and runs in scripts/ci-ebpf-tests.sh.
#
# Each step asserts a minimum number of passing tests, so a renamed test cannot
# silently drop out of a -run filter.
#
# Usage:
#   ./scripts/ci-listenq-unit.sh
#   RACE=0 ./scripts/ci-listenq-unit.sh
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

RACE="${RACE:-1}"
COUNT="${COUNT:-1}"

# The real-kernel tests exist only on Linux; elsewhere just the portable logic runs.
if [[ "$(go env GOOS)" == "linux" ]]; then
  LISTENQ_MIN=13
else
  LISTENQ_MIN=7
fi

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
go vet ./internal/listenq/...

expect_min "listenq (arithmetic, histogram, peaks; real inet_diag on Linux)" "$LISTENQ_MIN" ./internal/listenq/...
expect_min "agent sampling modes and conversion" 4 ./internal/agent/ -run 'ListenQueue'
expect_min "API aggregation, endpoint, metric bounds" 6 ./internal/api/ -run 'ListenQueue'

if [[ "$RACE" == "1" ]]; then
  echo "==> race detector"
  go test -race -count=1 ./internal/listenq/...
  go test -race -count=1 ./internal/agent/ -run 'ListenQueue'
  go test -race -count=1 ./internal/api/ -run 'ListenQueue'
fi

echo "==> non-Linux stub and arm64 build"
GOOS=darwin GOARCH=arm64 go build ./internal/listenq/...
GOOS=linux GOARCH=arm64 go build ./internal/listenq/...

echo "==> PASS ci-listenq-unit"
