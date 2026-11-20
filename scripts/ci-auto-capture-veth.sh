#!/usr/bin/env bash
# Netra — auto-capture integration smoke (iperf3 + veth + AF_PACKET feeder)
#
# Proves the opt-in heavy-load auto-capture path end-to-end on Linux without
# loading the full node agent / eBPF capture object:
#   1. Stand up a veth pair and generate TCP with iperf3.
#   2. Run netrad with NETRA_AUTO_CAPTURE + AF_PACKET backend.
#   3. POST a synthetic softnetDropped≥1000 agent report (reliable trigger;
#      real softnet counters are too flaky under CI load alone).
#   4. Stream real AF_PACKET frames from the veth into the agent capture WS.
#   5. Assert a non-empty classic PCAP landed under NETRA_AUTO_CAPTURE_DIR
#      and capture history links an artifact.
#   6. Assert the drop-incident context JSON frozen beside that PCAP names
#      this node and the live iperf3 process (pid/comm from /proc, no cmdline).
#
# Requires: Linux, root (or CAP_NET_ADMIN + CAP_NET_RAW), go, iperf3, iproute2, curl, python3.
# Usage:
#   sudo ./scripts/ci-auto-capture-veth.sh
#   sudo CONTROLLER_PORT=30970 ./scripts/ci-auto-capture-veth.sh
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

NODE="${NODE:-ci-veth}"
IFACE0="${IFACE0:-netra-ci0}"
IFACE1="${IFACE1:-netra-ci1}"
PEER_NS="${PEER_NS:-netra-ci-peer}"
IP0="${IP0:-10.255.77.1}"
IP1="${IP1:-10.255.77.2}"
IPERF_PORT="${IPERF_PORT:-5201}"
CONTROLLER_PORT="${CONTROLLER_PORT:-30870}"
CONTROLLER="http://127.0.0.1:${CONTROLLER_PORT}"
API_KEY="${NETRA_API_KEY:-ci-api-key}"
AGENT_KEY="${NETRA_AGENT_KEY:-ci-agent-key}"
CAPTURE_DURATION="${CAPTURE_DURATION:-12s}"
# Feeder must outlive the capture so Finalize runs after history is recorded.
FEEDER_DURATION="${FEEDER_DURATION:-25s}"
ARTIFACT_DIR="${ARTIFACT_DIR:-$(mktemp -d /tmp/netra-autocap.XXXXXX)}"
BIN_DIR="${BIN_DIR:-$(mktemp -d /tmp/netra-ci-bin.XXXXXX)}"
POLL_INTERVAL="${POLL_INTERVAL:-2s}"

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
  echo "this smoke test requires Linux (AF_PACKET + veth)" >&2
  exit 1
fi
if [[ "${EUID}" -ne 0 ]]; then
  echo "run as root (needed for veth + AF_PACKET CAP_NET_RAW)" >&2
  exit 1
fi

cleanup() {
  set +e
  [[ -n "${FEEDER_PID:-}" ]] && kill "$FEEDER_PID" 2>/dev/null
  [[ -n "${IPERF_PID:-}" ]] && kill "$IPERF_PID" 2>/dev/null
  [[ -n "${NETRAD_PID:-}" ]] && kill "$NETRAD_PID" 2>/dev/null
  # Bounded: a process that ignores SIGTERM must not hang the job in `wait`
  # (a hung agent kept a CI job running for six hours). Give each a moment,
  # then SIGKILL, then reap.
  for _p in "${FEEDER_PID:-}" "${IPERF_PID:-}" "${NETRAD_PID:-}"; do
    [[ -n "$_p" ]] || continue
    for _ in $(seq 1 20); do kill -0 "$_p" 2>/dev/null || break; sleep 0.25; done
    kill -9 "$_p" 2>/dev/null
    wait "$_p" 2>/dev/null
  done
  ip link del "$IFACE0" 2>/dev/null
  ip netns del "$PEER_NS" 2>/dev/null
}
trap cleanup EXIT

echo "==> build netrad + netra-ci-feeder"
mkdir -p "$BIN_DIR" "$ARTIFACT_DIR"
go build -o "$BIN_DIR/netrad" ./cmd/netrad
go build -o "$BIN_DIR/netra-ci-feeder" ./cmd/netra-ci-feeder

echo "==> veth ${IFACE0} <-> ${IFACE1} in netns ${PEER_NS} (${IP0}/24 <-> ${IP1}/24)"
# Peer must live in a separate netns — same-netns veth pairs are short-circuited
# by the local stack and never appear on AF_PACKET/tcpdump.
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

echo "==> start iperf3 server in ${PEER_NS} on ${IP1}:${IPERF_PORT}"
ip netns exec "$PEER_NS" iperf3 -s -B "$IP1" -p "$IPERF_PORT" >/tmp/netra-ci-iperf-s.log 2>&1 &
IPERF_PID=$!
sleep 0.5

echo "==> start netrad (auto-capture + afpacket) on :${CONTROLLER_PORT}"
export NETRA_ALLOW_UNAUTHENTICATED=false
export NETRA_API_KEY="$API_KEY"
export NETRA_AGENT_KEY="$AGENT_KEY"
export NETRA_LISTEN=":${CONTROLLER_PORT}"
export NETRA_AUTO_CAPTURE=true
export NETRA_AUTO_CAPTURE_BACKEND=afpacket
export NETRA_AUTO_CAPTURE_DURATION="$CAPTURE_DURATION"
export NETRA_AUTO_CAPTURE_COOLDOWN=30m
export NETRA_AUTO_CAPTURE_PROTOCOL=tcp
export NETRA_AUTO_CAPTURE_MAX_PPS=5000
export NETRA_AUTO_CAPTURE_DIR="$ARTIFACT_DIR"
export NETRA_ALERT_POLL_INTERVAL="$POLL_INTERVAL"
# Keep softnet from re-firing every poll and restarting the capture mid-stream.
export NETRA_ALERT_COOLDOWN=30m
# No TLS — plain HTTP for the smoke.
unset NETRA_TLS_CERT NETRA_TLS_KEY || true

"$BIN_DIR/netrad" >/tmp/netra-ci-netrad.log 2>&1 &
NETRAD_PID=$!

echo "==> wait for controller"
ok=0
for _ in $(seq 1 40); do
  if curl -sf -H "Authorization: Bearer ${API_KEY}" "${CONTROLLER}/api/v1/status" >/dev/null; then
    ok=1
    break
  fi
  if ! kill -0 "$NETRAD_PID" 2>/dev/null; then
    echo "netrad exited early; log:" >&2
    tail -n 80 /tmp/netra-ci-netrad.log >&2 || true
    exit 1
  fi
  sleep 0.25
done
if [[ "$ok" -ne 1 ]]; then
  echo "controller never became ready; log:" >&2
  tail -n 80 /tmp/netra-ci-netrad.log >&2 || true
  exit 1
fi

echo "==> POST synthetic softnet critical report for node=${NODE}"
# Softnet ≥1000 is synthetic (real counters are flaky in CI). Process identity
# is the live iperf3 server: pid and comm come from /proc, not a made-up name.
NOW="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
HOST_NAME="$(hostname -s 2>/dev/null || hostname)"
KERNEL="$(uname -r)"
IPERF_COMM="$(tr -d '\n' <"/proc/${IPERF_PID}/comm")"
IPERF_RSS_KB="$(awk '/^VmRSS:/ {print $2}' "/proc/${IPERF_PID}/status")"
IPERF_RSS_KB="${IPERF_RSS_KB:-0}"
NODE="$NODE" NOW="$NOW" HOST_NAME="$HOST_NAME" KERNEL="$KERNEL" \
  IPERF_PID="$IPERF_PID" IPERF_COMM="$IPERF_COMM" IPERF_RSS_KB="$IPERF_RSS_KB" \
  python3 - <<'PY'
import json, os
rss = int(os.environ.get("IPERF_RSS_KB") or "0") * 1024
proc = {
    "pid": int(os.environ["IPERF_PID"]),
    "comm": os.environ.get("IPERF_COMM") or "iperf3",
    "cpuPercent": 90.0,
    "rssBytes": rss,
}
report = {
    "node": os.environ["NODE"],
    "standalone": True,
    "mode": "observe",
    "observedAt": os.environ["NOW"],
    "stack": {"softnetProcessed": 10000, "softnetDropped": 1500, "softnetTimeSqueeze": 0},
    "stats": [],
    "events": [],
    "nodeResources": {
        "host": {
            "hostname": os.environ["HOST_NAME"],
            "kernelRelease": os.environ["KERNEL"],
            "cpuCores": 2,
            "cpuPercent": 180,
            "memoryTotalBytes": 1000000000,
            "memoryUsedBytes": 950000000,
            "loadAvg1": 3.5,
        },
        "workloads": [{"pod": "iperf", "cpuPercent": 40, "memoryUsedBytes": 1000000}],
    },
    "hostProcesses": {"byCpu": [proc], "byMemory": [proc]},
}
with open("/tmp/netra-ci-report.json", "w", encoding="utf-8") as f:
    json.dump(report, f)
print(f"report process pid={proc['pid']} comm={proc['comm']} rss={rss}")
PY
curl -sf -X POST \
  -H "Content-Type: application/json" \
  -H "X-Netra-Agent-Key: ${AGENT_KEY}" \
  "${CONTROLLER}/api/v1/agents/report" \
  -d @/tmp/netra-ci-report.json \
  >/dev/null

echo "==> wait for auto-capture session"
active=0
for _ in $(seq 1 30); do
  if curl -sf -H "Authorization: Bearer ${API_KEY}" "${CONTROLLER}/api/v1/capture/status" \
    | python3 -c "import json,sys; d=json.load(sys.stdin); raise SystemExit(0 if any(a.get('node')=='${NODE}' for a in d.get('active',[])) else 1)"; then
    active=1
    break
  fi
  sleep 0.5
done
if [[ "$active" -ne 1 ]]; then
  echo "auto-capture never started; netrad log:" >&2
  grep -E 'auto-capture|alert' /tmp/netra-ci-netrad.log | tail -n 40 >&2 || true
  tail -n 40 /tmp/netra-ci-netrad.log >&2 || true
  exit 1
fi
echo "    capture active on ${NODE}"

echo "==> start AF_PACKET feeder on ${IFACE0}"
"$BIN_DIR/netra-ci-feeder" \
  -controller "$CONTROLLER" \
  -agent-key "$AGENT_KEY" \
  -node "$NODE" \
  -iface "$IFACE0" \
  -protocol tcp \
  -duration "$FEEDER_DURATION" \
  -max-pps 5000 \
  >/tmp/netra-ci-feeder.log 2>&1 &
FEEDER_PID=$!
sleep 0.5

echo "==> generate iperf3 TCP ${IP0} -> ${IP1}:${IPERF_PORT}"
# Cap bitrate so AF_PACKET + userspace encode keep up under MaxPPS.
iperf3 -c "$IP1" -B "$IP0" -p "$IPERF_PORT" -t 8 -b 20M -P 1 >/tmp/netra-ci-iperf-c.log 2>&1 || {
  echo "iperf3 client failed; server log:" >&2
  cat /tmp/netra-ci-iperf-s.log >&2 || true
  cat /tmp/netra-ci-iperf-c.log >&2 || true
  exit 1
}

echo "==> wait for capture to expire (feeder stays connected)"
for _ in $(seq 1 60); do
  if curl -sf -H "Authorization: Bearer ${API_KEY}" "${CONTROLLER}/api/v1/capture/status" \
    | python3 -c "import json,sys; d=json.load(sys.stdin); raise SystemExit(0 if not any(a.get('node')=='${NODE}' for a in d.get('active',[])) else 1)"; then
    break
  fi
  sleep 0.5
done

echo "==> stop feeder (Finalize patches capture history)"
if [[ -n "${FEEDER_PID:-}" ]]; then
  kill "$FEEDER_PID" 2>/dev/null || true
  wait "$FEEDER_PID" 2>/dev/null || true
  FEEDER_PID=""
fi
sleep 1

echo "==> assert PCAP artifact on disk"
shopt -s nullglob
pcaps=("$ARTIFACT_DIR"/*.pcap)
if [[ ${#pcaps[@]} -lt 1 ]]; then
  echo "no PCAP under ${ARTIFACT_DIR}" >&2
  ls -la "$ARTIFACT_DIR" >&2 || true
  echo "feeder log:" >&2
  cat /tmp/netra-ci-feeder.log >&2 || true
  exit 1
fi

python3 - "$ARTIFACT_DIR" <<'PY'
import glob, os, struct, sys
adir = sys.argv[1]
paths = sorted(glob.glob(os.path.join(adir, "*.pcap")))
assert paths, "no pcap"
path = paths[-1]
with open(path, "rb") as f:
    hdr = f.read(24)
    assert len(hdr) == 24, "short global header"
    magic = struct.unpack("<I", hdr[:4])[0]
    assert magic in (0xa1b2c3d4, 0xd4c3b2a1, 0xa1b23c4d, 0x4d3cb2a1), f"bad magic {magic:#x}"
    size = os.path.getsize(path)
assert size > 24, f"pcap only has global header ({size} bytes) — no frames recorded"
print(f"ok: {path} ({size} bytes)")
PY

echo "==> assert capture history links an artifact and a drop context"
hist="$(curl -sf -H "Authorization: Bearer ${API_KEY}" "${CONTROLLER}/api/v1/capture/history?limit=5")"
aid="$(echo "$hist" | python3 -c "
import json, sys
d = json.load(sys.stdin)
entries = d.get('entries') or []
auto = [e for e in entries if str(e.get('requestor','')).startswith('auto-capture:')]
if not auto:
    print('FAIL: no auto-capture history entry', file=sys.stderr)
    print(d, file=sys.stderr)
    sys.exit(1)
e = auto[0]
frames = int(e.get('artifactFrames') or 0)
aid = e.get('artifactId') or ''
print(f\"history: requestor={e.get('requestor')} artifactId={aid!r} frames={frames} context={e.get('contextAvailable')}\", file=sys.stderr)
if frames < 1 or not aid:
    print('FAIL: history missing artifact link', file=sys.stderr)
    sys.exit(1)
if not e.get('contextAvailable'):
    print('FAIL: history missing contextAvailable', file=sys.stderr)
    sys.exit(1)
print(aid)
")"
ctx="$(curl -sf -H "Authorization: Bearer ${API_KEY}" "${CONTROLLER}/api/v1/capture/artifacts/${aid}/context")"
printf '%s\n' "$ctx" >/tmp/netra-ci-context.json
NODE="$NODE" HOST_NAME="$HOST_NAME" IPERF_PID="$IPERF_PID" IPERF_COMM="$IPERF_COMM" ARTIFACT_DIR="$ARTIFACT_DIR" AID="$aid" \
  python3 - <<'PY'
import json, os, sys
with open("/tmp/netra-ci-context.json", encoding="utf-8") as f:
    ctx = json.load(f)
node = ctx.get("node") or {}
want_node = os.environ["NODE"]
if node.get("name") != want_node:
    print(f"FAIL: context node {node.get('name')!r} != {want_node}", file=sys.stderr)
    sys.exit(1)
if node.get("hostname") != os.environ["HOST_NAME"]:
    print(f"FAIL: hostname {node.get('hostname')!r}", file=sys.stderr)
    sys.exit(1)
if not ctx.get("cpuHot") or not ctx.get("memoryHot"):
    print(f"FAIL: pressure cpuHot={ctx.get('cpuHot')} memoryHot={ctx.get('memoryHot')}", file=sys.stderr)
    sys.exit(1)
procs = ctx.get("topProcessesByCpu") or []
want_pid = int(os.environ["IPERF_PID"])
want_comm = os.environ["IPERF_COMM"]
if not procs or procs[0].get("pid") != want_pid or procs[0].get("comm") != want_comm:
    print(f"FAIL: top process {procs[:1]!r} want pid={want_pid} comm={want_comm}", file=sys.stderr)
    sys.exit(1)
raw = json.dumps(ctx)
if '"cmdline"' in raw or '"argv"' in raw:
    print("FAIL: context includes cmdline/argv", file=sys.stderr)
    sys.exit(1)
path = os.path.join(os.environ["ARTIFACT_DIR"], os.environ["AID"] + ".context.json")
if not os.path.isfile(path) or os.path.getsize(path) < 20:
    print(f"FAIL: missing context file {path}", file=sys.stderr)
    sys.exit(1)
print(f"ok: context node={node.get('name')} host={node.get('hostname')} process={want_comm} pid={want_pid} file={path}")
PY

echo "==> PASS auto-capture veth+iperf3 smoke"
echo "    artifacts: ${ARTIFACT_DIR}"
echo "    feeder frames: $(grep -E 'frames=' /tmp/netra-ci-feeder.log | tail -n1 || true)"
