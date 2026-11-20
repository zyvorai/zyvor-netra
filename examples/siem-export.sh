#!/usr/bin/env bash
# Copyright 2026 Zyvor AI Labs · https://zyvor.dev
# SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
#
# Pull Netra audit + anomaly records and optionally POST the OTLP/HTTP
# JSON Logs body to a collector. Requires netractl on PATH and
# NETRA_URL / NETRA_API_KEY in the environment (same as every other
# netractl invocation).
set -euo pipefail

FORMAT="${1:-jsonl}"
OUT="${NETRA_EXPORT_FILE:-}"
OTLP_ENDPOINT="${NETRA_OTLP_LOGS_URL:-}"

case "$FORMAT" in
  json|jsonl|cef|syslog|otlp) ;;
  *)
    echo "usage: $0 [json|jsonl|cef|syslog|otlp]" >&2
    exit 2
    ;;
esac

body="$(netractl export events --format "$FORMAT" --include anomaly,incident,audit --limit 200)"

if [[ -n "$OUT" ]]; then
  mkdir -p "$(dirname "$OUT")"
  printf '%s\n' "$body" >> "$OUT"
else
  printf '%s\n' "$body"
fi

if [[ "$FORMAT" == "otlp" && -n "$OTLP_ENDPOINT" ]]; then
  curl -sS -X POST \
    -H "Content-Type: application/json" \
    --data-binary "$body" \
    "$OTLP_ENDPOINT"
fi
