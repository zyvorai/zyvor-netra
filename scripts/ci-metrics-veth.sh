#!/usr/bin/env bash
# Netra — per-second metrics platform smoke (iperf3 + veth)
#
# Runs the real host collectors, the anomaly detector and the stream sender
# (internal/metricsmoke, -tags=metricsveth) against a real netrad, then puts
# iperf3 load on a veth and checks, end to end:
#
#   1. The node appears in GET /api/v1/metrics/nodes and streams series.
#   2. net.net for the veth moves under load (kilobits/s well above idle).
#   3. TCP series move (ipv4.tcppackets).
#   4. An anomaly is flagged on the veth after a quiet training phase.
#   5. A metric alert rule (mounted from NETRA_METRICALERT_DIR) fires.
#   6. GET /api/v1/metrics/evidence answers for the veth metric.
#   7. The process collector never exposes cmdline or environ.
#
# The eBPF datapath is not loaded: collectors read /proc and /sys only.
# Requires: Linux, root, go, iperf3, iproute2, curl, python3.
# Usage:
#   sudo ./scripts/ci-metrics-veth.sh
#   sudo CONTROLLER_PORT=31990 TRAIN_SECONDS=90 ./scripts/ci-metrics-veth.sh
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

NODE="${NODE:-ci-metrics}"
IFACE0="${IFACE0:-netra-met0}"
IFACE1="${IFACE1:-netra-met1}"
PEER_NS="${PEER_NS:-netra-met-peer}"
IP0="${IP0:-10.255.79.1}"
IP1="${IP1:-10.255.79.2}"
IPERF_PORT="${IPERF_PORT:-5201}"
CONTROLLER_PORT="${CONTROLLER_PORT:-31990}"
CONTROLLER="http://127.0.0.1:${CONTROLLER_PORT}"
API_KEY="${NETRA_API_KEY:-ci-api-key}"
AGENT_KEY="${NETRA_AGENT_KEY:-ci-agent-key}"
TRAIN_SECONDS="${TRAIN_SECONDS:-75}"
LOAD_SECONDS="${LOAD_SECONDS:-20}"
WORK_DIR="${WORK_DIR:-$(mktemp -d /tmp/netra-metrics-smoke.XXXXXX)}"

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "missing required command: $1" >&2
    exit 1
  }
}
need_cmd go
need_cmd ip
need_cmd iperf3
need_cmd curl
need_cmd python3

if [[ "$(uname -s)" != "Linux" ]]; then
  echo "this smoke test requires Linux (veth, /proc)" >&2
  exit 1
fi
if [[ "${EUID}" -ne 0 ]]; then
  echo "run as root (needed to create a veth pair)" >&2
  exit 1
fi

cleanup() {
  set +e
  for _p in "${IPERF_PID:-}" "${FEED_PID:-}" "${NETRAD_PID:-}"; do
    [[ -n "$_p" ]] || continue
    kill "$_p" 2>/dev/null
    for _ in $(seq 1 20); do kill -0 "$_p" 2>/dev/null || break; sleep 0.25; done
    kill -9 "$_p" 2>/dev/null
    wait "$_p" 2>/dev/null
  done
  ip link del "$IFACE0" 2>/dev/null
  ip netns del "$PEER_NS" 2>/dev/null
}
trap cleanup EXIT

auth() { curl -sf -H "Authorization: Bearer ${API_KEY}" "$@"; }

echo "==> build netrad and the collector driver"
go build -o "$WORK_DIR/netrad" ./cmd/netrad
go test -c -tags=metricsveth -o "$WORK_DIR/feed.test" ./internal/metricsmoke/

echo "==> veth ${IFACE0} <-> ${IFACE1} in netns ${PEER_NS}"
ip link del "$IFACE0" 2>/dev/null || true
ip netns del "$PEER_NS" 2>/dev/null || true
ip netns add "$PEER_NS"
ip link add "$IFACE0" type veth peer name "$IFACE1"
ip addr add "${IP0}/24" dev "$IFACE0"
ip link set "$IFACE0" up
ip link set "$IFACE1" netns "$PEER_NS"
ip -n "$PEER_NS" addr add "${IP1}/24" dev "$IFACE1"
ip -n "$PEER_NS" link set "$IFACE1" up
ip -n "$PEER_NS" link set lo up

ip netns exec "$PEER_NS" iperf3 -s -B "$IP1" -p "$IPERF_PORT" >"$WORK_DIR/iperf-s.log" 2>&1 &
IPERF_PID=$!

echo "==> metric alert rule for the veth"
mkdir -p "$WORK_DIR/metricalert.d"
cat >"$WORK_DIR/metricalert.d/smoke.yaml" <<EOF
alerts:
  - alarm: smoke_veth_sent
    on: net.net
    charts: net.${IFACE0}
    dimensions: sent
    lookup: max -20s
    every: 2s
    units: kilobits/s
    warn: \$this > 5000
    info: smoke veth transmit bandwidth
EOF

echo "==> netrad on :${CONTROLLER_PORT}"
export NETRA_ALLOW_UNAUTHENTICATED=false
export NETRA_API_KEY="$API_KEY"
export NETRA_AGENT_KEY="$AGENT_KEY"
export NETRA_LISTEN=":${CONTROLLER_PORT}"
export NETRA_METRICS_DIR=-
export NETRA_METRICALERT_DIR="$WORK_DIR/metricalert.d"
unset NETRA_TLS_CERT NETRA_TLS_KEY NETRA_FLEET_PEERS || true
"$WORK_DIR/netrad" >"$WORK_DIR/netrad.log" 2>&1 &
NETRAD_PID=$!
ok=0
for _ in $(seq 1 40); do
  if auth "${CONTROLLER}/api/v1/status" >/dev/null; then ok=1; break; fi
  kill -0 "$NETRAD_PID" 2>/dev/null || break
  sleep 0.25
done
if [[ "$ok" -ne 1 ]]; then
  echo "controller never became ready; log:" >&2
  tail -n 80 "$WORK_DIR/netrad.log" >&2 || true
  exit 1
fi

echo "==> collector driver streaming as node ${NODE} (training ${TRAIN_SECONDS}s)"
NETRA_SMOKE_SERVER="$CONTROLLER" NETRA_SMOKE_NODE="$NODE" NETRA_AGENT_KEY="$AGENT_KEY" \
  NETRA_SMOKE_SECONDS=$((TRAIN_SECONDS + LOAD_SECONDS + 60)) NETRA_SMOKE_TRAIN_SECONDS="$TRAIN_SECONDS" \
  "$WORK_DIR/feed.test" -test.run TestFeedController -test.v -test.timeout 30m >"$WORK_DIR/feed.log" 2>&1 &
FEED_PID=$!

sleep 10
echo "==> 1/7 node streams"
auth "${CONTROLLER}/api/v1/metrics/nodes" >"$WORK_DIR/nodes.json"
NODE="$NODE" python3 - "$WORK_DIR/nodes.json" <<'PY'
import json, os, sys
body = json.load(open(sys.argv[1]))
hit = [n for n in body.get("nodes") or [] if n.get("node") == os.environ["NODE"]]
if not hit or (hit[0].get("stats") or {}).get("series", 0) < 50:
    print("FAIL: node not streaming", body, file=sys.stderr)
    sys.exit(1)
print(f"ok: {os.environ['NODE']} streams {hit[0]['stats']['series']} series")
PY

echo "==> quiet phase until models train"
sleep $((TRAIN_SECONDS - 5))

echo "==> iperf3 load ${LOAD_SECONDS}s ${IP0} -> ${IP1}:${IPERF_PORT}"
iperf3 -c "$IP1" -B "$IP0" -p "$IPERF_PORT" -t "$LOAD_SECONDS" -b 200M >"$WORK_DIR/iperf-c.log" 2>&1 || {
  echo "iperf3 client failed" >&2
  cat "$WORK_DIR/iperf-s.log" "$WORK_DIR/iperf-c.log" >&2 || true
  exit 1
}
sleep 6

q() { auth "${CONTROLLER}/api/v1/metrics/data?$1"; }

echo "==> 2/7 net.net moves on ${IFACE0}"
q "context=net.net&nodes=${NODE}&charts=net.${IFACE0}&dimensions=sent&after=-60&points=60&group=max" >"$WORK_DIR/net.json"
python3 - "$WORK_DIR/net.json" <<'PY'
import json, sys
body = json.load(open(sys.argv[1]))
vals = [v for d in body.get("dimensions") or [] for v in d.get("values") or [] if v is not None]
peak = max(vals or [0])
if peak < 10000:
    print(f"FAIL: net.net sent peak {peak} kilobits/s", body, file=sys.stderr)
    sys.exit(1)
print(f"ok: net.net sent peak {peak:.0f} kilobits/s")
PY

echo "==> 3/7 TCP series move"
q "context=ipv4.tcppackets&nodes=${NODE}&after=-60&points=60&group=max" >"$WORK_DIR/tcp.json"
python3 - "$WORK_DIR/tcp.json" <<'PY'
import json, sys
body = json.load(open(sys.argv[1]))
vals = [v for d in body.get("dimensions") or [] for v in d.get("values") or [] if v is not None]
if max(vals or [0]) < 100:
    print("FAIL: ipv4.tcppackets did not move", body, file=sys.stderr)
    sys.exit(1)
print(f"ok: ipv4.tcppackets peak {max(vals):.0f} packets/s")
PY

echo "==> 4/7 anomaly flagged on the veth"
auth "${CONTROLLER}/api/v1/metrics/anomalies?after=-60&nodes=${NODE}&top=200" >"$WORK_DIR/anomalies.json"
IFACE0="$IFACE0" python3 - "$WORK_DIR/anomalies.json" <<'PY'
import json, os, sys
body = json.load(open(sys.argv[1]))
iface = os.environ["IFACE0"]
hit = [r for r in body.get("ranked") or [] if r.get("chart", "").endswith("." + iface) and r.get("anomalyRate", 0) > 0]
if not hit:
    print("FAIL: no anomalous dimension on", iface, json.dumps(body)[:2000], file=sys.stderr)
    sys.exit(1)
top = hit[0]
print(f"ok: {top['chart']}/{top['dimension']} anomalous {top['anomalyRate']:.0f}% of the last minute")
PY

echo "==> 5/7 metric alert fires"
auth "${CONTROLLER}/api/v1/metrics/alerts?all=true" >"$WORK_DIR/alerts.json"
python3 - "$WORK_DIR/alerts.json" <<'PY'
import json, sys
body = json.load(open(sys.argv[1]))
active = [a for a in body.get("active") or [] if a.get("rule") == "smoke_veth_sent"]
hist = [h for h in body.get("history") or [] if h.get("rule") == "smoke_veth_sent" and h.get("to") in ("warning", "critical")]
if not hist:
    print("FAIL: smoke_veth_sent never raised", json.dumps(body)[:2000], file=sys.stderr)
    sys.exit(1)
state = active[0]["status"] if active else "recovered"
print(f"ok: smoke_veth_sent raised (now {state})")
PY

echo "==> 6/7 evidence for the veth metric"
auth "${CONTROLLER}/api/v1/metrics/evidence?context=net.net&node=${NODE}&after=-120" >"$WORK_DIR/evidence.json"
python3 - "$WORK_DIR/evidence.json" <<'PY'
import json, sys
body = json.load(open(sys.argv[1]))
if "flows" not in body.get("kinds", []) or not body.get("links"):
    print("FAIL: evidence", body, file=sys.stderr)
    sys.exit(1)
print(f"ok: evidence kinds={','.join(body['kinds'])} links={len(body['links'])}")
PY

echo "==> 7/7 process groups carry comm only"
q "context=app.processes&nodes=${NODE}&group_by=chart&after=-60&points=5" >"$WORK_DIR/procs.json"
python3 - "$WORK_DIR/procs.json" <<'PY'
import json, sys
raw = open(sys.argv[1]).read()
body = json.loads(raw)
if not body.get("dimensions"):
    print("FAIL: no process groups", body, file=sys.stderr)
    sys.exit(1)
for d in body["dimensions"]:
    v = (d.get("labels") or {}).get("app_group", "")
    if v.startswith("-") or len(v.encode()) > 15:
        print("FAIL: app_group is not a comm (max 15 bytes):", v, file=sys.stderr)
        sys.exit(1)
if "cmdline" in raw or "environ" in raw:
    print("FAIL: cmdline/environ in response", file=sys.stderr)
    sys.exit(1)
print(f"ok: {len(body['dimensions'])} process groups, comm labels only")
PY

echo "==> PASS metrics veth+iperf3 smoke"
echo "    node=${NODE} iface=${IFACE0} logs in ${WORK_DIR}"
