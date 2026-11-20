#!/usr/bin/env sh
set -eu
BASE="${NETRA_URL:-https://127.0.0.1:30870}"
CURL="curl -fsS"
[ "${NETRA_TLS_INSECURE:-false}" = "true" ] && CURL="$CURL -k"
AUTH=""
[ -n "${NETRA_API_KEY:-}" ] && AUTH="Authorization: Bearer ${NETRA_API_KEY}"
$CURL "$BASE/healthz"
if [ -n "$AUTH" ]; then
  $CURL -H "$AUTH" "$BASE/api/v1/status"
  $CURL -H "$AUTH" "$BASE/api/v1/ebpf/path?limit=5"
  $CURL -H "$AUTH" "$BASE/api/v1/ebpf/drops?limit=5"
else
  $CURL "$BASE/api/v1/status"
  $CURL "$BASE/api/v1/ebpf/path?limit=5"
  $CURL "$BASE/api/v1/ebpf/drops?limit=5"
fi
$CURL "$BASE/metrics" | grep -q netra_http_requests_total
$CURL "$BASE/metrics" | grep -q netra_tcp_connect_average_latency_us

$CURL "$BASE/metrics" | grep -q netra_kernel_skb_drops
