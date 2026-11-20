#!/usr/bin/env bash
# Netra — the web UI against a real controller (no cluster, no root, any OS with Node)
#
# Builds the UI, starts the real netrad serving it (NETRA_WEB_DIR), seeds one agent's
# report (a slow TCP flow, DNS failures, a blocked and an allowed connection, per-
# destination stats) through the real agent endpoint, and drives it with a real browser
# (Playwright/Chromium): login, every page, seeded data on screen, and a firewall action
# through the UI. See web/tests/e2e-live.cjs.
#
# Needs: go, node (with `npm --prefix web ci` done and Playwright's chromium installed:
# `cd web && npx playwright install --with-deps chromium`), curl, python3.
#
# Usage:
#   ./scripts/ci-web-e2e.sh
#   OUT_DIR=/tmp/shots ./scripts/ci-web-e2e.sh
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

PORT="${CONTROLLER_PORT:-18093}"
API_KEY="ci-web-api-key"
AGENT_KEY="ci-web-agent-key"
OUT_DIR="${OUT_DIR:-$(mktemp -d "${TMPDIR:-/tmp}/netra-web-e2e.XXXXXX")}"
BIN="$(mktemp -d "${TMPDIR:-/tmp}/netra-web-bin.XXXXXX")"
LOG="$BIN/netrad.log"
for c in go node npm curl python3; do command -v "$c" >/dev/null || { echo "missing required command: $c" >&2; exit 1; }; done

NETRAD_PID=""
cleanup() {
  set +e
  if [[ -n "$NETRAD_PID" ]]; then
    kill "$NETRAD_PID" 2>/dev/null
    for _ in $(seq 1 20); do kill -0 "$NETRAD_PID" 2>/dev/null || break; sleep 0.25; done
    kill -9 "$NETRAD_PID" 2>/dev/null; wait "$NETRAD_PID" 2>/dev/null
  fi
  rm -rf "$BIN"
}
trap cleanup EXIT

if [[ ! -f web/dist/index.html ]]; then
  echo "==> build the web UI"
  npm --prefix web ci >/dev/null
  npm --prefix web run build >/dev/null
fi

echo "==> build and start netrad serving web/dist"
CGO_ENABLED=0 go build -trimpath -o "$BIN/netrad" ./cmd/netrad
env NETRA_ALLOW_UNAUTHENTICATED=false NETRA_API_KEY="$API_KEY" NETRA_AGENT_KEY="$AGENT_KEY" NETRA_LISTEN=":${PORT}" \
  NETRA_WEB_DIR="$ROOT/web/dist" NETRA_DNSDETECT_ENABLED=true NETRA_SCANDETECT_ENABLED=true \
  "$BIN/netrad" >"$LOG" 2>&1 &
NETRAD_PID=$!
for _ in $(seq 1 60); do
  curl -sf "http://127.0.0.1:${PORT}/healthz" >/dev/null 2>&1 && break
  kill -0 "$NETRAD_PID" 2>/dev/null || { echo "netrad exited early:" >&2; tail -n 30 "$LOG" >&2; exit 1; }
  sleep 0.25
done
curl -sf "http://127.0.0.1:${PORT}/" | grep -qi '<html' || { echo "the controller does not serve the UI at /" >&2; exit 1; }

echo "==> seed one agent report through the real agent endpoint"
seed() {
  python3 - "$API_KEY" <<'PY'
import datetime, json, sys
now = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
ns = {"namespace": "production", "pod": "payments-api", "workloadKind": "Deployment", "workloadName": "payments-api"}
print(json.dumps({
  "node": "ci-web", "observedAt": now, "mode": "observe",
  "hooks": ["cgroup-egress", "cgroup-ingress"],
  "programs": [{"name": "netra_cg_egress", "attached": True}],
  "tcpHealth": [dict(ns, comm="curl", family="ipv4", remoteIp="203.0.113.9", remotePort=443, srttUs=900000, rtos=1, retransmissions=25, activeEstablished=12)],
  "dnsHealth": [dict(ns, name="api.example.com", queries=12, responses=10, failures=4, totalLatencyUs=2500000, maxLatencyUs=1200000)],
  "stats": [
    dict(ns, destinationIp="203.0.113.5", port=443, protocol="TCP", direction="egress", hook="cgroup", packets=40, bytes=6000, blocked=7),
    dict(ns, destinationIp="198.51.100.9", port=443, protocol="TCP", direction="egress", hook="cgroup", packets=900, bytes=120000, blocked=0),
  ],
  "events": [
    dict(ns, timestampNs=1, observedAt=now, direction="egress", family="ipv4", sourceIp="10.42.0.8", destinationIp="203.0.113.5", sourcePort=40000, destinationPort=443, protocol="TCP", action="blocked", reason="deny_ip", comm="curl", hook="cgroup"),
    dict(ns, timestampNs=2, observedAt=now, direction="egress", family="ipv4", sourceIp="10.42.0.8", destinationIp="198.51.100.9", sourcePort=40002, destinationPort=443, protocol="TCP", action="observed", comm="curl", hook="cgroup"),
  ],
}))
PY
}
post_report() { seed | curl -sf -X POST -H "X-Netra-Agent-Key: ${AGENT_KEY}" -H 'Content-Type: application/json' --data-binary @- "http://127.0.0.1:${PORT}/api/v1/agents/report" >/dev/null; }
post_report
# Keep the report fresh for the whole run: a stale agent would change what every page shows.
( for _ in $(seq 1 120); do sleep 3; post_report 2>/dev/null || true; done ) &
FEEDER=$!
trap 'kill "$FEEDER" 2>/dev/null; cleanup' EXIT

echo "==> drive the UI with a real browser"
cd web
NETRA_URL="http://127.0.0.1:${PORT}" NETRA_API_KEY="$API_KEY" OUT_DIR="$OUT_DIR" SEED_NODE=ci-web SEED_IP=203.0.113.5 \
  node tests/e2e-live.cjs
echo "    screenshots and report.json: ${OUT_DIR}"
echo "==> PASS web e2e"
