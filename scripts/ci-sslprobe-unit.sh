#!/usr/bin/env bash
# Netra — TLS plaintext sampling gate (no BPF, no root)
#
# The userspace half of docs/tls-plaintext.md: the register layouts for amd64 and
# arm64, the kernel-event decoder, libssl discovery from /proc/*/maps (one attach
# per distinct file across processes and containers; deleted and lookalike
# libraries ignored), the classification that turns plaintext into a bounded
# observation with the right role, the agent's off/auto/required modes, and the
# controller's separate TLS view and metric family. The properties that matter for
# something that sees plaintext are each a test: request text never reaches a
# result, and the TLS and packet-level families never bleed into each other.
#
# The kernel half (real verifier, real libssl, real TLS) is scripts/ci-ebpf-tests.sh
# and the end-to-end path is scripts/ci-tlssample-smoke.sh.
#
# Asserts a minimum passing-test count per step so a renamed test cannot silently
# drop out of a -run filter.
#
# Usage:
#   ./scripts/ci-sslprobe-unit.sh
#   RACE=0 ./scripts/ci-sslprobe-unit.sh
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
go vet ./internal/sslprobe/...

expect_min "layouts, event decoding, discovery, classification" 8 ./internal/sslprobe/...
expect_min "agent modes and summary" 3 ./internal/agent/ -run 'TLSSampl|AttachTLS|SummarizeTLS'
expect_min "API aggregation, endpoint, separate metric family" 5 ./internal/api/ -run 'TLS'

if [[ "$RACE" == "1" ]]; then
  echo "==> race detector"
  go test -race -count=1 ./internal/sslprobe/... ./internal/l7sample/...
  go test -race -count=1 ./internal/agent/ -run 'TLSSampl|AttachTLS|SummarizeTLS'
  go test -race -count=1 ./internal/api/ -run 'TLS'
fi

echo "==> non-Linux stub and arm64 build"
GOOS=darwin GOARCH=arm64 go build ./internal/sslprobe/...
GOOS=linux GOARCH=arm64 go build ./internal/sslprobe/...

echo "==> PASS ci-sslprobe-unit"
