#!/usr/bin/env bash
# Netra — per-workload metrics + SLO unit gate (no root, no network)
#
# The accumulator (pod churn, agent resets, stale/returning nodes, the
# cardinality cap), the SLO registry extensions (weighted, bucketed
# observations; Status), the observer lifecycle (burn → audit → recovery) and
# the /metrics + /api/v1/slo surface. Live counterpart:
# scripts/ci-workload-obs-live.sh. Alert rules: scripts/ci-prometheus-rules.sh.
#
# Usage:
#   ./scripts/ci-workload-obs-unit.sh
#   RACE=0 COUNT=3 ./scripts/ci-workload-obs-unit.sh
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

RACE="${RACE:-1}"
COUNT="${COUNT:-1}"

RACE_FLAG=()
if [[ "$RACE" == "1" ]]; then
  RACE_FLAG=(-race)
fi

echo "==> slo: weighted/bucketed observations, SLI selector, Status"
go test "${RACE_FLAG[@]}" -count="$COUNT" ./internal/slo/...

echo "==> workloadobs: tracker, config/definition parsing, observer lifecycle"
go test "${RACE_FLAG[@]}" -count="$COUNT" ./internal/workloadobs/...

echo "==> api: workload series exposition, cardinality bound, label escaping, /api/v1/slo, OTLP conversion"
go test "${RACE_FLAG[@]}" -count="$COUNT" ./internal/api/ \
  -run 'WorkloadSeries|WorkloadAndSLO|LabelValues|Cardinality|SLOEndpoint|SLOAndWorkload|RoleTables|EveryMutating'

echo "==> netrad: fail-fast workload/SLO config, observer teardown"
go test "${RACE_FLAG[@]}" -count="$COUNT" ./cmd/netrad/ -run 'BuildWorkloadObs|StartWorkloadObs'
