#!/usr/bin/env bash
# Netra — render the chart's PrometheusRule spec as a plain Prometheus rules
# file (for promtool). Used by scripts/ci-prometheus-rules.sh.
#
# Usage: ./scripts/render-prometheus-rules.sh > rules.yaml
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
helm template netra helm/netra \
  --set auth.apiKey=ci-api-key --set auth.agentKey=ci-agent-key \
  --set metrics.prometheusRule.enabled=true \
  --set metrics.workloadLabels.enabled=true \
  --set 'slo.definitions[0].name=checkout' --set 'slo.definitions[0].sli=http_5xx' --set 'slo.definitions[0].targetPct=99.9' \
  | python3 -c '
import sys, yaml
docs = [d for d in yaml.safe_load_all(sys.stdin) if d]
rule = [d for d in docs if d.get("kind") == "PrometheusRule"]
if len(rule) != 1:
    sys.exit("expected exactly one PrometheusRule, found %d" % len(rule))
yaml.safe_dump({"groups": rule[0]["spec"]["groups"]}, sys.stdout, sort_keys=False)
'
