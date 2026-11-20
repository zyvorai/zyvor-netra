#!/usr/bin/env bash
# Netra — the chart's PrometheusRule, checked and unit-tested with promtool
#
# Renders helm/netra's PrometheusRule (with SLOs and workload series enabled so
# every group is present), runs `promtool check rules`, then `promtool test
# rules` against deploy/prometheus/netra-rules.test.yaml — synthetic series that
# assert when each alert does and does not fire. Needs helm, python3 (PyYAML)
# and promtool (PROMTOOL=/path/to/promtool, default: from PATH).
#
# Usage:
#   ./scripts/ci-prometheus-rules.sh
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

PROMTOOL="${PROMTOOL:-promtool}"
if ! command -v "$PROMTOOL" >/dev/null 2>&1; then
  echo "promtool not found (set PROMTOOL or install Prometheus >= 2.x)" >&2
  exit 2
fi

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

echo "==> render PrometheusRule from the chart"
./scripts/render-prometheus-rules.sh >"$WORK/rules.yaml"

echo "==> promtool check rules"
"$PROMTOOL" check rules "$WORK/rules.yaml"

echo "==> promtool test rules"
cp deploy/prometheus/netra-rules.test.yaml "$WORK/"
"$PROMTOOL" test rules "$WORK/netra-rules.test.yaml"
