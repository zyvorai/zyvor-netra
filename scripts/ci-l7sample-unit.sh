#!/usr/bin/env bash
# Netra — sampled L7 protocol parsing gate (no BPF, no root)
#
# The userspace half of docs/l7-sampling.md: the Redis, PostgreSQL, MySQL, Kafka,
# HTTP/1, HTTP/2 and gRPC classifiers, the kernel-event decoder and the bounded
# counters. The properties that matter for a component that reads untrusted
# payloads are each a test:
#
#   * a secret planted in a key, SQL text, path, cookie or bearer token never
#     appears in any output field;
#   * every label is from an allowlist or a validated pattern (bounded
#     cardinality), over 200 000 random and mutated inputs, and under fuzzing;
#   * nothing panics, and the counters stay bounded under adversarial input.
#
# The kernel half (real verifier, real TCP) is scripts/ci-ebpf-tests.sh.
#
# Asserts a minimum passing-test count so a renamed test cannot silently drop out.
#
# Usage:
#   ./scripts/ci-l7sample-unit.sh
#   RACE=0 FUZZTIME=0 ./scripts/ci-l7sample-unit.sh
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

RACE="${RACE:-1}"
FUZZTIME="${FUZZTIME:-20s}"
MIN_TESTS=24

echo "==> vet"
go vet ./internal/l7sample/...

echo "==> parser, decoder and counter tests"
out="$(go test -v -count=1 ./internal/l7sample/... 2>&1)" || { echo "$out"; exit 1; }
n="$(grep -c -- '^--- PASS' <<<"$out" || true)"
if (( n < MIN_TESTS )); then
  echo "$out"
  echo "l7sample: only ${n} tests passed, expected at least ${MIN_TESTS}" >&2
  exit 1
fi
echo "    ${n} tests passed"

if [[ "$RACE" == "1" ]]; then
  echo "==> race detector"
  go test -race -count=1 ./internal/l7sample/...
fi

if [[ "$FUZZTIME" != "0" ]]; then
  echo "==> fuzz the parsers for ${FUZZTIME}"
  # A crash writes its input to internal/l7sample/testdata/fuzz/ and fails here.
  go test ./internal/l7sample/ -run xxx -fuzz FuzzParse -fuzztime "$FUZZTIME"
fi

echo "==> non-Linux stub and arm64 build"
GOOS=darwin GOARCH=arm64 go build ./internal/l7sample/...
GOOS=linux GOARCH=arm64 go build ./internal/l7sample/...

echo "==> PASS ci-l7sample-unit"
