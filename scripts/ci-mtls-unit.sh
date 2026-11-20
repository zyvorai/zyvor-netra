#!/usr/bin/env bash
# Netra — agent <-> controller mutual TLS gate (no BPF, no root)
#
# Real TLS listeners with real certificates (docs/agent-mtls.md): the handshake
# accepts or refuses by issuer, key usage and expiry, optional vs required, a
# certificate renewed (and half-renewed) under a live client, the API's route
# policy behind a real listener, and the agent's HTTP client and capture
# websocket presenting the certificate.
#
# Each step asserts a minimum number of passing tests, so a renamed test cannot
# silently drop out of a -run filter.
#
# Usage:
#   ./scripts/ci-mtls-unit.sh
#   RACE=0 ./scripts/ci-mtls-unit.sh
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
go vet ./internal/mtls/... ./internal/agent/ ./internal/api/ ./cmd/netrad/

expect_min "mtls package (modes, CA loading, handshakes, rotation)" 8 ./internal/mtls/...
expect_min "API policy behind a real TLS listener" 9 ./internal/api/ -run 'RequiredMode|OptionalMode|OffMode|InvalidMode|MTLSFlag'
expect_min "agent client and capture websocket" 4 ./internal/agent/ -run 'TestAgentReportsPresent|TestCaptureStreamDial|TestAgentRefuses|TestAgentWithNoMTLS'

if [[ "$RACE" == "1" ]]; then
  echo "==> race detector"
  go test -race -count=1 ./internal/mtls/...
  go test -race -count=1 ./internal/api/ -run 'RequiredMode|OptionalMode|OffMode|InvalidMode|MTLSFlag'
  go test -race -count=1 ./internal/agent/ -run 'TestAgentReportsPresent|TestCaptureStreamDial|TestAgentRefuses|TestAgentWithNoMTLS'
fi

echo "==> PASS ci-mtls-unit"
