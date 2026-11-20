#!/usr/bin/env bash
# Netra — kernel sensor unit + race gate (no root, no BPF attach)
#
# The userspace half of the TCP event (docs/tcp-events.md) and drop attribution
# (docs/drop-info.md) sensors: tracepoint format parsing, layout derivation,
# reason names, kallsyms resolution, agent modes, controller aggregation and
# metric bounds. The kernel half is scripts/ci-ebpf-tests.sh.
#
# A gate that silently runs nothing is worse than none, so each step asserts a
# minimum number of tests actually ran: renaming a test out of a -run filter
# fails here instead of quietly dropping coverage.
#
# Usage:
#   ./scripts/ci-kernel-sensors-unit.sh
#   RACE=0 ./scripts/ci-kernel-sensors-unit.sh   # skip -race
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

RACE="${RACE:-1}"
COUNT="${COUNT:-1}"

# expect_min <label> <minimum passing tests> <go test args...>
expect_min() {
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
go vet ./internal/tpformat/... ./internal/ksym/... ./internal/tcpevents/... ./internal/dropinfo/...

expect_min "tracepoint format parsing (real 6.8 fixtures)" 11 ./internal/tpformat/...
expect_min "kallsyms resolver" 6 ./internal/ksym/...
expect_min "TCP event layouts" 4 ./internal/tcpevents/...
expect_min "drop info layouts + reason names" 6 ./internal/dropinfo/...
expect_min "agent sensor modes (off/auto/required)" 4 ./internal/agent/ -run 'TCPEvents|DropInfo'
expect_min "API aggregation, endpoints, metric bounds" 14 ./internal/api/ -run 'TCPEvent|DropInfo|DropAggregate|TestAggregate'

if [[ "$RACE" == "1" ]]; then
  echo "==> race detector"
  go test -race -count=1 ./internal/tpformat/... ./internal/ksym/... ./internal/tcpevents/... ./internal/dropinfo/...
  go test -race -count=1 ./internal/agent/ -run 'TCPEvents|DropInfo'
  go test -race -count=1 ./internal/api/ -run 'TCPEvent|DropInfo|DropAggregate|TestAggregate'
fi

# The sensors have Linux-only loaders and stub counterparts elsewhere; both
# sides must compile, or `go build` breaks on the platform CI does not use.
echo "==> non-Linux stubs and arm64 build"
GOOS=darwin GOARCH=arm64 go build ./internal/tcpevents/... ./internal/dropinfo/... ./internal/ksym/... ./internal/tpformat/... ./internal/agent/...
GOOS=linux GOARCH=arm64 go build -o /dev/null ./cmd/netra-agent

echo "==> PASS ci-kernel-sensors-unit"
