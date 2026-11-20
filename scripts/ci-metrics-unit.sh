#!/usr/bin/env bash
# Netra — per-second metrics platform gate (no BPF, no root)
#
# The Netdata-class metrics platform (docs/metrics.md): the tiered Gorilla store,
# every collector against /proc and /sys fixtures (the process collector never
# reads cmdline or environ), app collectors against fake nginx/apache/haproxy/
# Prometheus endpoints and fake Redis/memcached servers, host-netns discovery,
# workload RED series, the agent-to-netrad stream with gap replay, ML anomaly
# detection and correlation, the metric alert engine and its built-in rules, the
# exporters (remote write with in-tree snappy, OTLP, Graphite), the query, stream,
# evidence, summary and fleet APIs, and AI brief context. The real-kernel half
# (agent on a veth, iperf3 load, series moving, a rule firing) needs root and runs
# in scripts/ci-metrics-veth.sh.
#
# Each step asserts a minimum number of passing tests, so a renamed test cannot
# silently drop out of a -run filter.
#
# Usage:
#   ./scripts/ci-metrics-unit.sh
#   RACE=0 ./scripts/ci-metrics-unit.sh
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

PKGS=(./internal/tsdb/ ./internal/collectors/ ./internal/metricstream/ ./internal/anomaly/ ./internal/metricalert/ ./internal/metricexport/ ./internal/fleet/)
API_RUN='Metric|Evidence|AIDigestCites'

echo "==> vet"
go vet "${PKGS[@]}" ./internal/api/ ./internal/ai/ ./cmd/netrad/ ./cmd/netractl/ ./cmd/netra-mcp/
GOOS=linux go vet ./internal/collectors/ ./internal/agent/

echo "==> stdlib-only guard (tsdb, anomaly, metricstream)"
for p in internal/tsdb internal/anomaly internal/metricstream; do
  bad="$(go list -deps "./$p" | grep -E '^(github\.com|golang\.org|google\.golang\.org|gopkg\.in)/' | grep -v '^github.com/zyvorai/netra' || true)"
  if [[ -n "$bad" ]]; then
    echo "$p imports non-stdlib packages:" >&2
    echo "$bad" >&2
    exit 1
  fi
done

echo "==> no cmdline/environ reads in collectors"
if grep -nE '"(cmdline|environ)"' internal/collectors/*.go | grep -v _test.go; then
  echo "collectors must never read /proc/<pid>/cmdline or environ" >&2
  exit 1
fi

expect_min "tsdb (Gorilla codec, tiers, rollups, disk, queries)" 12 ./internal/tsdb/
expect_min "collectors (fixtures, process groups, apps, discovery, RED)" 16 ./internal/collectors/
expect_min "agent stream and netrad hub (handshake, replay, limits)" 3 ./internal/metricstream/
expect_min "anomaly detection, back-off, KS correlation" 5 ./internal/anomaly/
expect_min "metric alert engine and built-in rules" 9 ./internal/metricalert/
expect_min "exporters (snappy, remote write, OTLP, Graphite, cursors)" 6 ./internal/metricexport/
expect_min "API (query, stream, alerts, anomalies, evidence, summary, fleet, AI)" 12 ./internal/api/ -run "$API_RUN"
expect_min "AI brief metric context" 2 ./internal/ai/ -run 'MetricFindings|FingerprintTracksMetric'
expect_min "netrad wiring (alerts, exporters, disabled paths)" 3 ./cmd/netrad/ -run 'BuildMetrics'

if [[ "$RACE" == "1" ]]; then
  echo "==> race detector"
  go test -race -count=1 "${PKGS[@]}"
  go test -race -count=1 ./internal/api/ -run "$API_RUN"
  go test -race -count=1 ./cmd/netrad/ -run 'BuildMetrics'
fi

echo "==> non-Linux and arm64 builds"
GOOS=darwin GOARCH=arm64 go build ./internal/collectors/ ./internal/agent/ ./cmd/netrad/
GOOS=linux GOARCH=arm64 go build ./internal/collectors/ ./internal/agent/ ./cmd/netrad/

echo "==> PASS ci-metrics-unit"
