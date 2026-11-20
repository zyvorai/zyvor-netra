#!/usr/bin/env bash
# Netra — flow-observe integration smoke (iperf3 + veth)
#
# Proves the read-only observe APIs one step at a time, on Linux, without
# loading the full node agent. Real TCP crosses a veth. The controller
# sees it the same way it sees a node agent: two reports whose counters
# are the veth RX counters, and whose pid/comm/stack come from /proc of
# the live iperf3 server. No payloads, no argv.
#
#   1. Flow history returns the veth peer, port, and packet delta.
#   2. RED rate for that pod is non-zero.
#   3. appProtocol is the well-known-port hint for the iperf port (3306 → mysql).
#   4. comm and pid on the flow match /proc.
#   5. An inferred trace span names that peer. No pod-IP link without Kubernetes.
#   6. Profiles returns the kernel stack read from /proc/<pid>/stack.
#   7. Workload-events answers. Without a kube client, available is false.
#   8. Prometheus netra_flowlog_records has no pod or destination label.
#
# Requires: Linux, root, go, iperf3, iproute2, curl, python3.
# Usage:
#   sudo ./scripts/ci-flow-observe-veth.sh
#   sudo CONTROLLER_PORT=31980 ./scripts/ci-flow-observe-veth.sh
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

NODE="${NODE:-ci-veth}"
IFACE0="${IFACE0:-netra-obs0}"
IFACE1="${IFACE1:-netra-obs1}"
PEER_NS="${PEER_NS:-netra-obs-peer}"
IP0="${IP0:-10.255.78.1}"
IP1="${IP1:-10.255.78.2}"
# 3306 is the mysql port hint. The bytes are iperf3, not a MySQL parser.
IPERF_PORT="${IPERF_PORT:-3306}"
CONTROLLER_PORT="${CONTROLLER_PORT:-31980}"
CONTROLLER="http://127.0.0.1:${CONTROLLER_PORT}"
API_KEY="${NETRA_API_KEY:-ci-api-key}"
AGENT_KEY="${NETRA_AGENT_KEY:-ci-agent-key}"
BIN_DIR="${BIN_DIR:-$(mktemp -d /tmp/netra-obs-bin.XXXXXX)}"

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
  echo "this smoke test requires Linux (veth)" >&2
  exit 1
fi
if [[ "${EUID}" -ne 0 ]]; then
  echo "run as root (needed to create a veth pair)" >&2
  exit 1
fi

cleanup() {
  set +e
  [[ -n "${IPERF_PID:-}" ]] && kill "$IPERF_PID" 2>/dev/null
  [[ -n "${NETRAD_PID:-}" ]] && kill "$NETRAD_PID" 2>/dev/null
  [[ -n "${SLEEP_PID:-}" ]] && kill "$SLEEP_PID" 2>/dev/null
  # Bounded: a process that ignores SIGTERM must not hang the job in `wait`
  # (a hung agent kept a CI job running for six hours). Give each a moment,
  # then SIGKILL, then reap.
  for _p in "${IPERF_PID:-}" "${NETRAD_PID:-}" "${SLEEP_PID:-}"; do
    [[ -n "$_p" ]] || continue
    for _ in $(seq 1 20); do kill -0 "$_p" 2>/dev/null || break; sleep 0.25; done
    kill -9 "$_p" 2>/dev/null
    wait "$_p" 2>/dev/null
  done
  ip link del "$IFACE0" 2>/dev/null
  ip netns del "$PEER_NS" 2>/dev/null
}
trap cleanup EXIT

auth() { curl -sf -H "Authorization: Bearer ${API_KEY}" "$@"; }

echo "==> build netrad"
mkdir -p "$BIN_DIR"
go build -o "$BIN_DIR/netrad" ./cmd/netrad

echo "==> veth ${IFACE0} <-> ${IFACE1} in netns ${PEER_NS} (${IP0}/24 <-> ${IP1}/24)"
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

echo "==> iperf3 server in ${PEER_NS} on ${IP1}:${IPERF_PORT}"
ip netns exec "$PEER_NS" iperf3 -s -B "$IP1" -p "$IPERF_PORT" >/tmp/netra-obs-iperf-s.log 2>&1 &
IPERF_PID=$!
sleep 0.4
if ! kill -0 "$IPERF_PID" 2>/dev/null; then
  echo "iperf3 server exited; log:" >&2
  cat /tmp/netra-obs-iperf-s.log >&2 || true
  exit 1
fi

echo "==> netrad on :${CONTROLLER_PORT}"
export NETRA_ALLOW_UNAUTHENTICATED=false
export NETRA_API_KEY="$API_KEY"
export NETRA_AGENT_KEY="$AGENT_KEY"
export NETRA_LISTEN=":${CONTROLLER_PORT}"
unset NETRA_TLS_CERT NETRA_TLS_KEY || true
"$BIN_DIR/netrad" >/tmp/netra-obs-netrad.log 2>&1 &
NETRAD_PID=$!

ok=0
for _ in $(seq 1 40); do
  if auth "${CONTROLLER}/api/v1/status" >/dev/null; then
    ok=1
    break
  fi
  if ! kill -0 "$NETRAD_PID" 2>/dev/null; then
    echo "netrad exited early; log:" >&2
    tail -n 80 /tmp/netra-obs-netrad.log >&2 || true
    exit 1
  fi
  sleep 0.25
done
if [[ "$ok" -ne 1 ]]; then
  echo "controller never became ready; log:" >&2
  tail -n 80 /tmp/netra-obs-netrad.log >&2 || true
  exit 1
fi

rx_of() {
  ip -j -s link show "$1" | python3 -c '
import json, sys
row = json.load(sys.stdin)[0]
stats = row.get("stats64") or row.get("stats") or {}
rx = stats.get("rx") or {}
print(int(rx.get("packets") or 0), int(rx.get("bytes") or 0))
'
}

read rx_before bytes_before < <(rx_of "$IFACE0")
echo "==> veth RX before iperf: packets=${rx_before} bytes=${bytes_before}"

post_report() {
  local packets="$1" bytes="$2" observed="$3" stack_pid="$4" folded="$5"
  NODE="$NODE" IP1="$IP1" PORT="$IPERF_PORT" \
    PACKETS="$packets" BYTES="$bytes" OBSERVED="$observed" \
    IPERF_PID="$IPERF_PID" IPERF_COMM="$IPERF_COMM" \
    STACK_PID="$stack_pid" FOLDED="$folded" \
    python3 - <<'PY'
import json, os
pid = int(os.environ["IPERF_PID"])
report = {
    "node": os.environ["NODE"],
    "standalone": True,
    "mode": "observe",
    "observedAt": os.environ["OBSERVED"],
    "stats": [{
        "destinationIp": os.environ["IP1"],
        "port": int(os.environ["PORT"]),
        "protocol": "TCP",
        "direction": "egress",
        "packets": int(os.environ["PACKETS"]),
        "bytes": int(os.environ["BYTES"]),
        "namespace": "app",
        "pod": "iperf",
        "workloadName": "iperf",
    }],
    "tcpHealth": [{
        "remoteIp": os.environ["IP1"],
        "remotePort": int(os.environ["PORT"]),
        "pid": pid,
        "comm": os.environ["IPERF_COMM"],
        "srttUs": 2000,
        "namespace": "app",
        "pod": "iperf",
    }],
}
folded = os.environ.get("FOLDED") or ""
stack_pid = int(os.environ.get("STACK_PID") or "0")
if folded and stack_pid:
    report["stackSamples"] = [{
        "node": os.environ["NODE"],
        "pid": stack_pid,
        "comm": os.environ["IPERF_COMM"] if stack_pid == pid else "sleep",
        "folded": folded,
        "frames": folded.count(";"),
    }]
with open("/tmp/netra-obs-report.json", "w", encoding="utf-8") as f:
    json.dump(report, f)
PY
  curl -sf -X POST \
    -H "Content-Type: application/json" \
    -H "X-Netra-Agent-Key: ${AGENT_KEY}" \
    "${CONTROLLER}/api/v1/agents/report" \
    -d @/tmp/netra-obs-report.json \
    >/dev/null
}

IPERF_COMM="$(tr -d '\n' </proc/"${IPERF_PID}"/comm)"
echo "==> baseline report (iperf pid=${IPERF_PID} comm=${IPERF_COMM})"
post_report "$rx_before" "$bytes_before" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" 0 ""

echo "==> iperf3 client ${IP0} -> ${IP1}:${IPERF_PORT}"
iperf3 -c "$IP1" -B "$IP0" -p "$IPERF_PORT" -t 3 -b 10M >/tmp/netra-obs-iperf-c.log 2>&1 || {
  echo "iperf3 client failed" >&2
  cat /tmp/netra-obs-iperf-s.log >&2 || true
  cat /tmp/netra-obs-iperf-c.log >&2 || true
  exit 1
}

read rx_after bytes_after < <(rx_of "$IFACE0")
echo "==> veth RX after iperf: packets=${rx_after} bytes=${bytes_after}"
if [[ "$rx_after" -le "$rx_before" ]]; then
  echo "veth ${IFACE0} did not see new packets" >&2
  exit 1
fi

stack_pid="$IPERF_PID"
folded=""
if [[ -r "/proc/${IPERF_PID}/stack" ]]; then
  folded="$(python3 - "$IPERF_PID" "$IPERF_COMM" <<'PY'
import sys
pid, comm = sys.argv[1], sys.argv[2]
try:
    text = open(f"/proc/{pid}/stack", encoding="utf-8", errors="replace").read()
except OSError:
    sys.exit(0)
frames = []
for line in text.splitlines():
    line = line.strip()
    if "]" in line:
        line = line.split("]", 1)[1].strip()
    if "+" in line:
        line = line.split("+", 1)[0].strip()
    if line and not line.startswith("0x"):
        frames.append(line)
    if len(frames) >= 8:
        break
if not frames:
    sys.exit(0)
frames.reverse()
print(comm + ";" + ";".join(frames))
PY
)"
fi
if [[ -z "$folded" ]]; then
  sleep 30 &
  SLEEP_PID=$!
  sleep 0.2
  stack_pid="$SLEEP_PID"
  folded="$(python3 - "$SLEEP_PID" <<'PY'
import sys
pid = sys.argv[1]
text = open(f"/proc/{pid}/stack", encoding="utf-8", errors="replace").read()
frames = []
for line in text.splitlines():
    line = line.strip()
    if "]" in line:
        line = line.split("]", 1)[1].strip()
    if "+" in line:
        line = line.split("+", 1)[0].strip()
    if line and not line.startswith("0x"):
        frames.append(line)
    if len(frames) >= 8:
        break
if not frames:
    sys.exit(1)
frames.reverse()
print("sleep;" + ";".join(frames))
PY
)" || {
    echo "could not read /proc/<pid>/stack for iperf or sleep" >&2
    exit 1
  }
fi

sleep 1
echo "==> second report with veth delta"
post_report "$rx_after" "$bytes_after" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$stack_pid" "$folded"

echo "==> 1/8 flow history"
auth "${CONTROLLER}/api/v1/flows/history?since=1h&peer=${IP1}&pod=iperf&limit=20" >/tmp/netra-obs-history.json
IP1="$IP1" PORT="$IPERF_PORT" IPERF_PID="$IPERF_PID" IPERF_COMM="$IPERF_COMM" \
  RX_BEFORE="$rx_before" RX_AFTER="$rx_after" python3 - <<'PY'
import json, os, sys
with open("/tmp/netra-obs-history.json", encoding="utf-8") as f:
    body = json.load(f)
recs = body.get("records") or []
want_port = int(os.environ["PORT"])
want_pid = int(os.environ["IPERF_PID"])
want_comm = os.environ["IPERF_COMM"]
delta = int(os.environ["RX_AFTER"]) - int(os.environ["RX_BEFORE"])
hit = [r for r in recs if r.get("peer") == os.environ["IP1"] and r.get("port") == want_port]
if len(hit) != 1:
    print(f"FAIL: history records {len(hit)} want 1", file=sys.stderr)
    print(body, file=sys.stderr)
    sys.exit(1)
rec = hit[0]
if rec.get("packets") != delta:
    print(f"FAIL: packets {rec.get('packets')} != veth delta {delta}", file=sys.stderr)
    sys.exit(1)
if rec.get("pod") != "iperf" or rec.get("namespace") != "app":
    print(f"FAIL: workload {rec.get('namespace')}/{rec.get('pod')}", file=sys.stderr)
    sys.exit(1)
print(f"ok: history peer={rec.get('peer')} port={rec.get('port')} packets={rec.get('packets')} (veth delta)")
PY

echo "==> 2/8 RED"
auth "${CONTROLLER}/api/v1/insights/red?window=5m" >/tmp/netra-obs-red.json
python3 - <<'PY'
import json, sys
with open("/tmp/netra-obs-red.json", encoding="utf-8") as f:
    body = json.load(f)
rows = [r for r in (body.get("rows") or []) if r.get("pod") == "iperf"]
if len(rows) != 1 or not rows[0].get("packets") or not rows[0].get("ratePerSec"):
    print("FAIL: RED row", rows, file=sys.stderr)
    sys.exit(1)
print(f"ok: RED pod=iperf packets={rows[0].get('packets')} rate={rows[0].get('ratePerSec')}/s srtt={rows[0].get('avgSrttUs')}")
PY

echo "==> 3/8 app protocol hint"
python3 - <<'PY'
import json, sys
with open("/tmp/netra-obs-history.json", encoding="utf-8") as f:
    rec = json.load(f)["records"][0]
if rec.get("appProtocol") != "mysql":
    print(f"FAIL: appProtocol {rec.get('appProtocol')!r} want mysql (port hint, not a parser)", file=sys.stderr)
    sys.exit(1)
print("ok: appProtocol=mysql from port 3306")
PY
miss="$(auth "${CONTROLLER}/api/v1/flows/history?since=1h&app=kafka")"
printf '%s\n' "$miss" | python3 -c 'import json,sys; d=json.load(sys.stdin); assert d.get("matched")==0, d; print("ok: app=kafka matched 0")'

echo "==> 4/8 process on the flow"
IPERF_PID="$IPERF_PID" IPERF_COMM="$IPERF_COMM" python3 - <<'PY'
import json, os, sys
with open("/tmp/netra-obs-history.json", encoding="utf-8") as f:
    rec = json.load(f)["records"][0]
raw = json.dumps(rec)
if rec.get("pid") != int(os.environ["IPERF_PID"]) or rec.get("comm") != os.environ["IPERF_COMM"]:
    print(f"FAIL: pid/comm {rec.get('pid')} {rec.get('comm')!r}", file=sys.stderr)
    sys.exit(1)
if '"cmdline"' in raw or '"argv"' in raw:
    print("FAIL: record has cmdline/argv", file=sys.stderr)
    sys.exit(1)
print(f"ok: comm={rec.get('comm')} pid={rec.get('pid')}")
PY

echo "==> 5/8 inferred trace"
auth "${CONTROLLER}/api/v1/insights/traces?since=15m" >/tmp/netra-obs-traces.json
IP1="$IP1" PORT="$IPERF_PORT" IPERF_COMM="$IPERF_COMM" python3 - <<'PY'
import json, os, sys
with open("/tmp/netra-obs-traces.json", encoding="utf-8") as f:
    body = json.load(f)
spans = body.get("spans") or []
want = [s for s in spans if s.get("peer") == os.environ["IP1"] and s.get("port") == int(os.environ["PORT"])]
if len(want) != 1 or not want[0].get("inferred"):
    print("FAIL: span", spans, file=sys.stderr)
    sys.exit(1)
sp = want[0]
if sp.get("comm") != os.environ["IPERF_COMM"]:
    print(f"FAIL: span comm {sp.get('comm')!r}", file=sys.stderr)
    sys.exit(1)
limits = " ".join(body.get("limitations") or [])
if "traceparent" not in limits and "Inferred" not in limits:
    print("FAIL: missing inference limitation", file=sys.stderr)
    sys.exit(1)
print(f"ok: span {sp.get('name')} inferred (no propagated traceparent)")
PY

echo "==> 6/8 kernel stack profile"
auth "${CONTROLLER}/api/v1/insights/profiles" >/tmp/netra-obs-profiles.json
STACK_PID="$stack_pid" python3 - <<'PY'
import json, os, sys
with open("/tmp/netra-obs-profiles.json", encoding="utf-8") as f:
    body = json.load(f)
want = int(os.environ["STACK_PID"])
samples = [s for s in (body.get("samples") or []) if s.get("pid") == want]
if len(samples) != 1 or not samples[0].get("folded") or samples[0].get("frames", 0) < 1:
    print("FAIL: profiles", body, file=sys.stderr)
    sys.exit(1)
raw = json.dumps(samples[0])
if '"cmdline"' in raw or '"argv"' in raw:
    print("FAIL: profile has cmdline/argv", file=sys.stderr)
    sys.exit(1)
print(f"ok: profile pid={want} frames={samples[0].get('frames')}")
PY

echo "==> 7/8 workload warning events"
auth "${CONTROLLER}/api/v1/insights/workload-events" >/tmp/netra-obs-events.json
python3 - <<'PY'
import json, sys
with open("/tmp/netra-obs-events.json", encoding="utf-8") as f:
    body = json.load(f)
if body.get("available") is not False:
    print(f"FAIL: expected available=false without kube, got {body.get('available')!r}", file=sys.stderr)
    sys.exit(1)
text = " ".join(body.get("limitations") or [])
if "Warning" not in text or "Journal" not in text:
    print("FAIL: limitations", body.get("limitations"), file=sys.stderr)
    sys.exit(1)
print("ok: workload-events available=false (no kube client); Warning-only contract present")
PY

echo "==> 8/8 prometheus cardinality"
curl -sf "${CONTROLLER}/metrics" >/tmp/netra-obs-metrics.txt
python3 - <<'PY'
import sys
lines = [ln for ln in open("/tmp/netra-obs-metrics.txt", encoding="utf-8") if ln.startswith("netra_flowlog_records ")]
if len(lines) != 1:
    print("FAIL: metric lines", lines, file=sys.stderr)
    sys.exit(1)
if "{" in lines[0] or float(lines[0].split()[-1]) < 1:
    print("FAIL: metric", lines[0], file=sys.stderr)
    sys.exit(1)
print(f"ok: {lines[0].rstrip()} (no pod or destination label)")
PY

echo "==> PASS flow-observe veth+iperf3 smoke"
echo "    node=${NODE} peer=${IP1} port=${IPERF_PORT} pid=${IPERF_PID} comm=${IPERF_COMM}"
echo "    veth delta packets=$((rx_after - rx_before)) bytes=$((bytes_after - bytes_before))"
