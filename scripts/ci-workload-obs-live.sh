#!/usr/bin/env bash
# Netra — per-workload metrics + SLOs against a REAL netrad (GitHub CI)
#
# Boots the real netrad binary, then plays the part of a node agent: POSTs
# cumulative counter reports to /api/v1/agents/report exactly as an agent does,
# and checks what /metrics, /api/v1/slo and the audit log say. It exercises the
# cases the accumulator exists for — growth, the cardinality cap and __other__,
# an agent counter reset, a workload vanishing, and an SLO burn that pages —
# and asserts no exported counter ever goes down. No root, cluster or agent.
#
# Usage:
#   ./scripts/ci-workload-obs-live.sh
#   CONTROLLER_PORT=19093 ./scripts/ci-workload-obs-live.sh
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

BIN_DIR="${BIN_DIR:-$ROOT/bin}"
CONTROLLER_PORT="${CONTROLLER_PORT:-18093}"
API_KEY="ci-wobs-api-key"
AGENT_KEY="ci-wobs-agent-key"
API="http://127.0.0.1:${CONTROLLER_PORT}"
TMP="${TMPDIR:-/tmp}"
LOG="${TMP}/netra-ci-wobs-netrad.log"
TICK_WAIT="${TICK_WAIT:-7}" # observer interval below is 5s; wait past one full tick

mkdir -p "$BIN_DIR"
echo "==> build netrad"
CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o "${BIN_DIR}/netrad" ./cmd/netrad

NETRAD_PID=""
cleanup() {
  if [[ -n "$NETRAD_PID" ]] && kill -0 "$NETRAD_PID" 2>/dev/null; then
    kill "$NETRAD_PID" 2>/dev/null || true
    wait "$NETRAD_PID" 2>/dev/null || true
  fi
}
trap cleanup EXIT

echo "==> start netrad on :${CONTROLLER_PORT} (workload series on, cap 2, one SLO, 5s interval)"
export NETRA_ALLOW_UNAUTHENTICATED=false
export NETRA_API_KEY="$API_KEY"
export NETRA_AGENT_KEY="$AGENT_KEY"
export NETRA_LISTEN=":${CONTROLLER_PORT}"
export NETRA_METRICS_WORKLOAD_LABELS=on
export NETRA_METRICS_WORKLOAD_MAX=2
export NETRA_WORKLOAD_OBS_INTERVAL=5s
export NETRA_SLO_DEFINITIONS='[{"name":"checkout","namespace":"shop","workload":"Deployment/checkout","sli":"http_5xx","targetPct":"99.9","window":"7d"}]'
unset NETRA_TLS_CERT NETRA_TLS_KEY NETRA_STATE_FILE NETRA_METRICS_TOKEN || true
"${BIN_DIR}/netrad" >"$LOG" 2>&1 &
NETRAD_PID=$!
for _ in $(seq 1 80); do
  curl -sf "${API}/healthz" >/dev/null 2>&1 && break
  kill -0 "$NETRAD_PID" 2>/dev/null || { echo "netrad exited early:" >&2; tail -n 60 "$LOG" >&2; exit 1; }
  sleep 0.25
done
curl -sf "${API}/healthz" >/dev/null

FAIL=0
PASS=0
check() { # check <name> <want> <got>
  if [[ "$2" == "$3" ]]; then PASS=$((PASS + 1)); printf '  ok   %s\n' "$1"
  else FAIL=$((FAIL + 1)); printf '  FAIL %s: want %s, got %s\n' "$1" "$2" "$3" >&2; fi
}

# report <spec>: post one agent report. spec is "name:packets:bytes:ok:e5xx" per
# workload, space separated. Every workload lives in namespace "shop".
report() {
  python3 - "$API" "$AGENT_KEY" "$@" <<'PY'
import datetime, json, sys, urllib.request, zlib
api, key, *specs = sys.argv[1:]
# Real agents stamp every report; the controller judges staleness from it.
now = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
stats, http = [], []
for spec in specs:
    name, packets, nbytes, ok, e5 = spec.split(":")
    cg = zlib.crc32(name.encode()) + 1000  # one cgroup per workload, as on a real node
    # Real agents report a pod's direct controller: a Deployment's pods show up
    # as ReplicaSet "<deployment>-<pod-template-hash>". Mirror that; netrad must
    # still export (and SLO-match) the workload as Deployment/<name>.
    ident = {"cgroupId": cg, "namespace": "shop", "workloadKind": "ReplicaSet", "workloadName": name + "-6c4b4dfd7c"}
    stats.append({**ident, "sourceIp": "10.0.0.1", "destinationIp": "10.0.0.2", "port": 80, "protocol": "tcp",
                  "hook": "egress", "direction": "egress", "packets": int(packets), "bytes": int(nbytes), "blocked": 0})
    http.append({**ident, "status": 200, "count": int(ok)})
    http.append({**ident, "status": 503, "count": int(e5)})
body = json.dumps({"observedAt": now, "node": "ci-node-1", "mode": "observe", "interfaces": [], "standalone": True, "stats": stats, "httpStatus": http}).encode()
req = urllib.request.Request(api + "/api/v1/agents/report", data=body, method="POST",
                             headers={"Content-Type": "application/json", "X-Netra-Agent-Key": key})
with urllib.request.urlopen(req) as r:
    assert r.status == 202, r.status
PY
}

metrics() { curl -sf -H "Authorization: Bearer ${API_KEY}" "${API}/metrics"; }
series() { # series <name{labels}> -> value (empty if absent)
  metrics | awk -v s="$1" 'index($0, s " ") == 1 { print $2 }'
}
ALL_SNAPSHOTS=()
snapshot() { ALL_SNAPSHOTS+=("$(metrics | grep '^netra_workload_.*_total{' || true)"); }
wait_tick() { sleep "$TICK_WAIT"; }

# ---- 0. Baseline: history is not growth --------------------------------------
echo "==> baseline (an agent's lifetime totals must not count as growth)"
report "checkout:900000:9000000:800000:0" "cart:500000:5000000:0:0" "web:2000000:20000000:0:0" "batch:100000:1000000:0:0"
wait_tick
check "no series carries pre-existing history" "0" "$(series 'netra_workload_packets_total{namespace="__other__",workload="__other__"}')"
check "nothing named yet" "0" "$(series 'netra_workload_series_named')"
snapshot

# ---- 1. Growth, the cap, __other__ -------------------------------------------
echo "==> growth with a cap of 2 named workloads"
report "checkout:900500:9005000:800400:0" "cart:500050:5000500:0:0" "web:2001000:20010000:0:0" "batch:100010:1000100:0:0"
wait_tick
check "busiest workload web is named (packets +1000)" "1000" "$(series 'netra_workload_packets_total{namespace="shop",workload="Deployment/web"}')"
check "second busiest checkout is named (packets +500)" "500" "$(series 'netra_workload_packets_total{namespace="shop",workload="Deployment/checkout"}')"
check "exactly two workloads named" "2" "$(series 'netra_workload_series_named')"
check "the rest roll into __other__ (cart 50 + batch 10)" "60" "$(series 'netra_workload_packets_total{namespace="__other__",workload="__other__"}')"
check "cart has no series of its own" "" "$(series 'netra_workload_packets_total{namespace="shop",workload="Deployment/cart"}')"
check "no source is capped in this small report" "0" "$(series 'netra_workload_report_truncated{source="flows"}')"
check "cardinality stays at cap + 1 series per family" "3" "$(metrics | grep -c '^netra_workload_packets_total{')"
check "http responses counted for checkout" "400" "$(series 'netra_workload_http_responses_total{namespace="shop",workload="Deployment/checkout"}')"
snapshot

# ---- 2. Agent restart: counters restart from zero ----------------------------
echo "==> agent counter reset and a vanished workload"
before_web="$(series 'netra_workload_packets_total{namespace="shop",workload="Deployment/web"}')"
# web's flow now reports 300 (far below 2001000): the agent restarted. cart disappears (pod gone).
report "checkout:900600:9006000:800500:0" "web:300:3000:0:0" "batch:100020:1000200:0:0"
wait_tick
after_web="$(series 'netra_workload_packets_total{namespace="shop",workload="Deployment/web"}')"
check "a reset counts what was seen since the restart, never a huge or negative jump" "$((before_web + 300))" "$after_web"
check "checkout keeps growing normally" "600" "$(series 'netra_workload_packets_total{namespace="shop",workload="Deployment/checkout"}')"
snapshot

# ---- 3. SLO: healthy so far, then a burn pages --------------------------------
echo "==> SLO"
slo="$(curl -sf -H "Authorization: Bearer ${API_KEY}" "${API}/api/v1/slo")"
check "SLO endpoint enabled" "True" "$(echo "$slo" | python3 -c 'import sys,json; print(json.load(sys.stdin)["enabled"])')"
check "checkout SLO healthy on clean traffic" "none" "$(echo "$slo" | python3 -c 'import sys,json; print(json.load(sys.stdin)["items"][0]["severity"])')"

echo "    injecting a 5xx storm on checkout (about 9% errors against a 0.1% budget)..."
ok=800500; bad=0
for i in 1 2 3; do
  ok=$((ok + 1000)); bad=$((bad + 100))
  report "checkout:$((900600 + i * 1000)):9006000:${ok}:${bad}" "web:$((300 + i)):3000:0:0" "batch:100020:1000200:0:0"
  wait_tick
done
sev="$(curl -sf -H "Authorization: Bearer ${API_KEY}" "${API}/api/v1/slo" | python3 -c 'import sys,json; print(json.load(sys.stdin)["items"][0]["severity"])')"
check "the burn pages" "page" "$sev"
check "netra_slo_alert_state is 2" "2" "$(series 'netra_slo_alert_state{slo="checkout"}')"
check "budget is spent" "0.000000" "$(series 'netra_slo_budget_remaining{slo="checkout"}')"
check "5xx counted per workload" "300" "$(series 'netra_workload_http_5xx_total{namespace="shop",workload="Deployment/checkout"}')"
snapshot

actors="$(curl -sf -H "Authorization: Bearer ${API_KEY}" "${API}/api/v1/audit?limit=200" | python3 -c "
import sys, json
ev = [i for i in json.load(sys.stdin)['items'] if i.get('actor') == 'slo']
print(' '.join(sorted({i['action'] + ':' + i['target'] for i in ev})))")"
check "the burn was written to the audit log" "slo.burn:checkout" "$actors"

# ---- 4. Nothing ever went backwards -------------------------------------------
echo "==> monotonicity across every scrape taken above"
mono_rc=0
python3 - "${ALL_SNAPSHOTS[@]}" <<'PY' || mono_rc=$?
import sys, re
prev = {}
for n, snap in enumerate(sys.argv[1:]):
    for line in snap.splitlines():
        m = re.match(r'(\S+\{[^}]*\}) (\d+)$', line)
        if not m:
            continue
        key, val = m.group(1), int(m.group(2))
        if key in prev and val < prev[key]:
            print("DECREASED between scrapes %d and %d: %s %d -> %d" % (n - 1, n, key, prev[key], val), file=sys.stderr)
            sys.exit(1)
        prev[key] = val
if not prev:
    print("no series were captured", file=sys.stderr)
    sys.exit(1)
PY
check "no exported counter decreased" 0 "$mono_rc"

echo
echo "workload obs live: ${PASS} passed, ${FAIL} failed"
if [[ "$FAIL" -ne 0 ]]; then
  echo "--- netrad log (tail) ---" >&2
  tail -n 60 "$LOG" >&2 || true
  exit 1
fi
