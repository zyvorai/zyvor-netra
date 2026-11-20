#!/usr/bin/env bash
# Netra — TLS fingerprint CI smoke (openssl + iperf3 + datapath sampler)
#
# Proves always-on JA3/JA4 end-to-end on Linux:
#   1. Compile bpf/netra_tlsfp.c (+ netra_tc for the agent).
#   2. Run privileged BPF_PROG_TEST_RUN integration tests for the sampler.
#   3. Start netrad + netra-agent with NETRA_TLSFP=required.
#   4. Generate real ClientHellos with openssl s_client (and curl HTTPS).
#   5. Generate background TCP with iperf3 (must not break agent / hooks).
#   6. Assert GET /api/v1/ebpf/tls-fingerprints reports uniqueJa3 > 0 and
#      the agent lists hook tlsfp-cgroup-egress.
#
# Requires: Linux root, go, clang, llvm, iperf3, openssl, curl, python3, iproute2.
# Usage:
#   sudo ./scripts/ci-tlsfp-smoke.sh
#   sudo CONTROLLER_PORT=30971 ./scripts/ci-tlsfp-smoke.sh
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

CONTROLLER_PORT="${CONTROLLER_PORT:-30871}"
CONTROLLER="http://127.0.0.1:${CONTROLLER_PORT}"
API_KEY="${NETRA_API_KEY:-ci-api-key}"
AGENT_KEY="${NETRA_AGENT_KEY:-ci-agent-key}"
BIN_DIR="${BIN_DIR:-$(mktemp -d /tmp/netra-tlsfp-bin.XXXXXX)}"
BPF_DIR="${BPF_DIR:-$(mktemp -d /tmp/netra-tlsfp-bpf.XXXXXX)}"
PIN_PATH="${PIN_PATH:-/sys/fs/bpf/netra-ci-tlsfp}"
IPERF_PORT="${IPERF_PORT:-5202}"
PEER_NS="${PEER_NS:-netra-tlsfp-peer}"
IFACE0="${IFACE0:-netra-tlsfp0}"
IFACE1="${IFACE1:-netra-tlsfp1}"
IP0="${IP0:-10.255.78.1}"
IP1="${IP1:-10.255.78.2}"

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "missing required command: $1" >&2
    exit 1
  }
}

need_cmd go
need_cmd clang
need_cmd curl
need_cmd python3
need_cmd openssl
need_cmd iperf3
need_cmd ip

if [[ "$(uname -s)" != "Linux" ]]; then
  echo "this smoke test requires Linux (eBPF + cgroup)" >&2
  exit 1
fi
if [[ "${EUID}" -ne 0 ]]; then
  echo "run as root (needed for BPF load + cgroup attach + veth)" >&2
  exit 1
fi

cleanup() {
  set +e
  [[ -n "${AGENT_PID:-}" ]] && kill "$AGENT_PID" 2>/dev/null
  [[ -n "${NETRAD_PID:-}" ]] && kill "$NETRAD_PID" 2>/dev/null
  [[ -n "${IPERF_PID:-}" ]] && kill "$IPERF_PID" 2>/dev/null
  # Bounded: a process that ignores SIGTERM must not hang the job in `wait`
  # (a hung agent kept a CI job running for six hours). Give each a moment,
  # then SIGKILL, then reap.
  for _p in "${AGENT_PID:-}" "${NETRAD_PID:-}" "${IPERF_PID:-}"; do
    [[ -n "$_p" ]] || continue
    for _ in $(seq 1 20); do kill -0 "$_p" 2>/dev/null || break; sleep 0.25; done
    kill -9 "$_p" 2>/dev/null
    wait "$_p" 2>/dev/null
  done
  ip link del "$IFACE0" 2>/dev/null
  ip netns del "$PEER_NS" 2>/dev/null
  rm -rf "$PIN_PATH" 2>/dev/null
}
trap cleanup EXIT

ARCH="$(uname -m)"
INC="/usr/include/${ARCH}-linux-gnu"
echo "==> compile BPF objects into ${BPF_DIR}"
clang -target bpfel -O2 -g -Wall -Wextra -Werror -I"$INC" \
  -mllvm -bpf-stack-size=1024 \
  -c bpf/netra_tc.c -o "${BPF_DIR}/netra_tc.o"
clang -target bpfel -O2 -g -Wall -Wextra -Werror -I"$INC" \
  -c bpf/netra_edge_intel.c -o "${BPF_DIR}/netra_edge_intel.o"
clang -target bpfel -O2 -g -Wall -Wextra -Werror -I"$INC" \
  -c bpf/netra_capture.c -o "${BPF_DIR}/netra_capture.o"
clang -target bpfel -O2 -g -Wall -Wextra -Werror -I"$INC" \
  -c bpf/netra_tlsfp.c -o "${BPF_DIR}/netra_tlsfp.o"
cp "${BPF_DIR}/netra_tc.o" /tmp/netra_tc.o
cp "${BPF_DIR}/netra_tlsfp.o" /tmp/netra_tlsfp.o

echo "==> BPF integration tests (load + allow-return; live emit is below)"
go test -tags=bpfintegration -c -o "${BIN_DIR}/bpfintegration.test" ./bpf/integration/
NETRA_BPF_TEST_OBJECT=/tmp/netra_tc.o \
NETRA_BPF_TLSFP_TEST_OBJECT=/tmp/netra_tlsfp.o \
  "${BIN_DIR}/bpfintegration.test" -test.v -test.run 'TestTLSFP'

echo "==> build netrad + netra-agent"
mkdir -p "$BIN_DIR"
go build -o "${BIN_DIR}/netrad" ./cmd/netrad
go build -o "${BIN_DIR}/netra-agent" ./cmd/netra-agent

echo "==> veth + iperf3 background TCP (${IP0} <-> ${IP1})"
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
ip netns exec "$PEER_NS" iperf3 -s -B "$IP1" -p "$IPERF_PORT" >/tmp/netra-tlsfp-iperf-s.log 2>&1 &
IPERF_PID=$!
sleep 0.3

echo "==> start netrad on :${CONTROLLER_PORT}"
export NETRA_ALLOW_UNAUTHENTICATED=false
export NETRA_API_KEY="$API_KEY"
export NETRA_AGENT_KEY="$AGENT_KEY"
export NETRA_LISTEN=":${CONTROLLER_PORT}"
unset NETRA_TLS_CERT NETRA_TLS_KEY || true
"${BIN_DIR}/netrad" >/tmp/netra-tlsfp-netrad.log 2>&1 &
NETRAD_PID=$!

ok=0
for _ in $(seq 1 40); do
  if curl -sf -H "Authorization: Bearer ${API_KEY}" "${CONTROLLER}/api/v1/status" >/dev/null; then
    ok=1
    break
  fi
  if ! kill -0 "$NETRAD_PID" 2>/dev/null; then
    echo "netrad exited early:" >&2
    tail -n 80 /tmp/netra-tlsfp-netrad.log >&2 || true
    exit 1
  fi
  sleep 0.25
done
if [[ "$ok" -ne 1 ]]; then
  echo "controller never ready:" >&2
  tail -n 80 /tmp/netra-tlsfp-netrad.log >&2 || true
  exit 1
fi

echo "==> start netra-agent (TLSFP required, L7/edge/capture/tcx off)"
rm -rf "$PIN_PATH"
mkdir -p "$PIN_PATH"
export NODE_NAME="${NODE_NAME:-ci-tlsfp}"
export NETRA_SERVER="$CONTROLLER"
export NETRA_AGENT_KEY="$AGENT_KEY"
export NETRA_BPF_OBJECT="${BPF_DIR}/netra_tc.o"
export NETRA_BPF_EDGE_OBJECT="${BPF_DIR}/netra_edge_intel.o"
export NETRA_BPF_CAPTURE_OBJECT="${BPF_DIR}/netra_capture.o"
export NETRA_BPF_TLSFP_OBJECT="${BPF_DIR}/netra_tlsfp.o"
export NETRA_BPF_PIN="$PIN_PATH"
export NETRA_CGROUP_PATH=/sys/fs/cgroup
export NETRA_CGROUP_ENABLED=true
export NETRA_TLSFP=required
export NETRA_L7=off
export NETRA_EDGE_INTEL=off
export NETRA_CAPTURE=off
export NETRA_TCX=off
export NETRA_INTERFACES=
export NETRA_XDP_INTERFACES=
"${BIN_DIR}/netra-agent" >/tmp/netra-tlsfp-agent.log 2>&1 &
AGENT_PID=$!

# Wait for TLSFP attach log / agent report
attached=0
for _ in $(seq 1 60); do
  if grep -q 'TLS fingerprint sampler attached' /tmp/netra-tlsfp-agent.log 2>/dev/null; then
    attached=1
    break
  fi
  if ! kill -0 "$AGENT_PID" 2>/dev/null; then
    echo "agent exited early:" >&2
    tail -n 120 /tmp/netra-tlsfp-agent.log >&2 || true
    exit 1
  fi
  sleep 0.5
done
if [[ "$attached" -ne 1 ]]; then
  echo "TLSFP never attached:" >&2
  tail -n 120 /tmp/netra-tlsfp-agent.log >&2 || true
  exit 1
fi
echo "    tlsfp sampler attached"

echo "==> openssl + curl ClientHellos + iperf3 TCP"
for host in example.com www.cloudflare.com 1.1.1.1; do
  timeout 8 openssl s_client -connect "${host}:443" -servername "${host}" </dev/null >/dev/null 2>&1 || true
done
curl -4 -s -o /dev/null -m 8 https://example.com/ || true
curl -4 -s -o /dev/null -m 8 https://www.cloudflare.com/ || true
iperf3 -c "$IP1" -B "$IP0" -p "$IPERF_PORT" -t 3 -b 10M >/tmp/netra-tlsfp-iperf-c.log 2>&1 || {
  echo "iperf3 client warning (non-fatal for JA3); log:" >&2
  cat /tmp/netra-tlsfp-iperf-c.log >&2 || true
}

echo "==> wait for uniqueJa3 > 0"
got=0
for _ in $(seq 1 40); do
  if curl -sf -H "Authorization: Bearer ${API_KEY}" \
    "${CONTROLLER}/api/v1/ebpf/tls-fingerprints" \
    | python3 -c 'import json,sys; d=json.load(sys.stdin); raise SystemExit(0 if int((d.get("stats") or {}).get("uniqueJa3") or 0)>0 else 1)'; then
    got=1
    break
  fi
  sleep 0.5
done
if [[ "$got" -ne 1 ]]; then
  echo "no JA3 fingerprints observed; agent log:" >&2
  tail -n 80 /tmp/netra-tlsfp-agent.log >&2 || true
  curl -s -H "Authorization: Bearer ${API_KEY}" "${CONTROLLER}/api/v1/ebpf/tls-fingerprints" >&2 || true
  curl -s -H "Authorization: Bearer ${API_KEY}" "${CONTROLLER}/api/v1/agents" >&2 || true
  exit 1
fi

curl -sf -H "Authorization: Bearer ${API_KEY}" "${CONTROLLER}/api/v1/agents" \
  | python3 -c '
import json,sys
items=(json.load(sys.stdin).get("items") or [])
assert items, "no agents"
hooks=items[0].get("hooks") or []
assert "tlsfp-cgroup-egress" in hooks, hooks
fps=items[0].get("tlsFingerprints") or []
print("hooks_ok tlsfp-cgroup-egress fps", len(fps))
'

curl -sf -H "Authorization: Bearer ${API_KEY}" \
  "${CONTROLLER}/api/v1/ebpf/tls-fingerprints" | python3 -m json.tool | head -40

echo "==> PASS tlsfp openssl+iperf3 smoke"
