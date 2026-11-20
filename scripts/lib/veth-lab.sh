#!/usr/bin/env bash
# Shared setup for the real-agent, real-kernel CI scripts (Linux, root):
# a controller, a node agent, and a veth pair into a network namespace with HTTP
# servers on the far side. Source it, set the variables it lists, call the functions.
#
#   Required before sourcing:  LAB_NAME (short, unique per script), CONTROLLER_PORT
#   Provided:                  D BIN BPF BASE API_KEY AGENT_KEY NS IF0 IF1 IP0 IP1 V6_0 V6_1
#                              NETRAD_LOG AGENT_LOG PIDS NETRAD_PID AGENT_PID
#   Functions:                 lab_build lab_netrad lab_veth lab_servers lab_agent
#                              lab_api lab_reach lab_fail lab_dump   (cleanup is a trap)
#
# A script that needs the same lab twice in one run (two agents) must call lab_agent
# with a different NODE_NAME; everything else is created once.
# shellcheck shell=bash

: "${LAB_NAME:?set LAB_NAME before sourcing veth-lab.sh}"
: "${CONTROLLER_PORT:?set CONTROLLER_PORT before sourcing veth-lab.sh}"

ROOT="${ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)}"
BASE="http://127.0.0.1:${CONTROLLER_PORT}"
API_KEY="${API_KEY:-ci-${LAB_NAME}-api-key}"
AGENT_KEY="${AGENT_KEY:-ci-${LAB_NAME}-agent-key}"
D="$(mktemp -d "/tmp/netra-${LAB_NAME}.XXXXXX")"
BIN="$D/bin"; BPF="$D/bpf"; mkdir -p "$BIN" "$BPF"
PIN_PATH="/sys/fs/bpf/netra-ci-${LAB_NAME}"
NS="nl-${LAB_NAME}"; IF0="nl${LAB_NAME:0:3}0"; IF1="nl${LAB_NAME:0:3}1"
IP0="${IP0:-10.255.90.1}"; IP1="${IP1:-10.255.90.2}"
V6_0="${V6_0:-fd00:ca:90::1}"; V6_1="${V6_1:-fd00:ca:90::2}"
NETRAD_LOG="$D/netrad.log"; AGENT_LOG="$D/agent.log"
PIDS=(); NETRAD_PID=""; AGENT_PID=""

lab_need() { command -v "$1" >/dev/null 2>&1 || { echo "missing required command: $1" >&2; exit 1; }; }
for _c in go clang curl python3 ip; do lab_need "$_c"; done
[[ "$(uname -s)" == "Linux" ]] || { echo "requires Linux (eBPF + cgroup + netns)" >&2; exit 1; }
[[ "${EUID}" -eq 0 ]] || { echo "run as root (BPF load, cgroup attach, netns)" >&2; exit 1; }

lab_cleanup() {
  set +e
  for p in "${PIDS[@]}"; do kill -9 "$p" 2>/dev/null; done
  # Do not wait: a BPF verifier stall is uninterruptible and would hang CI.
  ip netns pids "$NS" 2>/dev/null | xargs -r kill -9 2>/dev/null
  ip link del "$IF0" 2>/dev/null
  ip netns del "$NS" 2>/dev/null
  rm -rf "$PIN_PATH" 2>/dev/null
  [[ "${KEEP:-}" == 1 ]] || rm -rf "$D"
}
trap lab_cleanup EXIT

lab_dump() {
  echo "----- config" >&2; curl -s -H "Authorization: Bearer ${API_KEY}" "${BASE}/api/v1/ebpf/config" >&2 || true; echo >&2
  echo "----- netrad log" >&2; tail -n 15 "$NETRAD_LOG" >&2 || true
  echo "----- agent log" >&2; tail -n 25 "$AGENT_LOG" >&2 || true
}
lab_fail() { echo "FAIL: $*" >&2; lab_dump; exit 1; }
lab_api() { curl -sf -H "Authorization: Bearer ${API_KEY}" -H 'Content-Type: application/json' "$@"; }
# lab_reach <curl args...>: an HTTP 200 within a short timeout
lab_reach() { [[ "$(curl -s -g -o /dev/null --connect-timeout 2 --max-time 3 -w '%{http_code}' "$@" 2>/dev/null)" == 200 ]]; }

# lab_build [bpf object ...]: compile the named bpf/<name>.c objects (default netra_tc)
# and build netrad, netra-agent and any extra ./cmd/<name> passed via LAB_EXTRA_CMDS.
lab_build() {
  local arch inc name
  arch="$(uname -m)"; inc="/usr/include/${arch}-linux-gnu"
  echo "==> compile BPF objects and build the binaries"
  for name in "${@:-netra_tc}"; do
    local extra=()
    [[ "$name" == "netra_tc" ]] && extra=(-mllvm -bpf-stack-size=1024)
    clang -target bpfel -O2 -g -Wall -Wextra -Werror -I"$inc" ${extra[@]+"${extra[@]}"} -c "$ROOT/bpf/${name}.c" -o "$BPF/${name}.o"
  done
  (cd "$ROOT" && go build -o "$BIN/netrad" ./cmd/netrad && go build -o "$BIN/netra-agent" ./cmd/netra-agent)
  for name in ${LAB_EXTRA_CMDS:-}; do (cd "$ROOT" && go build -o "$BIN/$name" "./cmd/$name"); done
}

# lab_netrad [env ...]: start the controller and wait until it answers.
lab_netrad() {
  echo "==> start netrad on :${CONTROLLER_PORT}"
  env NETRA_ALLOW_UNAUTHENTICATED=false NETRA_API_KEY="$API_KEY" NETRA_AGENT_KEY="$AGENT_KEY" NETRA_LISTEN=":${CONTROLLER_PORT}" "$@" \
    "$BIN/netrad" >>"$NETRAD_LOG" 2>&1 &
  NETRAD_PID=$!; PIDS+=("$NETRAD_PID")
  local _
  for _ in $(seq 1 60); do
    curl -sf -H "Authorization: Bearer ${API_KEY}" "${BASE}/api/v1/status" >/dev/null 2>&1 && return 0
    kill -0 "$NETRAD_PID" 2>/dev/null || lab_fail "netrad exited early"
    sleep 0.25
  done
  lab_fail "controller never ready"
}

# lab_veth: a veth pair, IF0 (root namespace) <-> IF1 (in $NS), IPv4 and IPv6.
lab_veth() {
  echo "==> veth into a namespace"
  ip netns del "$NS" 2>/dev/null || true
  ip link del "$IF0" 2>/dev/null || true
  ip netns add "$NS"
  ip link add "$IF0" type veth peer name "$IF1"
  ip addr add "${IP0}/24" dev "$IF0"
  ip -6 addr add "${V6_0}/64" dev "$IF0" nodad
  ip link set "$IF0" up
  ip link set "$IF1" netns "$NS"
  ip -n "$NS" addr add "${IP1}/24" dev "$IF1"
  ip -n "$NS" -6 addr add "${V6_1}/64" dev "$IF1" nodad
  ip -n "$NS" link set "$IF1" up
  ip -n "$NS" link set lo up
}

# lab_servers <port>...: dual-stack HTTP servers in the namespace answering 200 "ok".
lab_servers() {
  cat >"$D/server.py" <<'PY'
import socket, sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
class H(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    def do_GET(self):
        self.send_response(200); self.send_header("Content-Length", "2"); self.end_headers(); self.wfile.write(b"ok")
    def log_message(self, *a): pass
class S(ThreadingHTTPServer):
    address_family = socket.AF_INET6
    def server_bind(self):
        self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)   # dual stack
        super().server_bind()
S(("::", int(sys.argv[1])), H).serve_forever()
PY
  local p
  for p in "$@"; do
    ip netns exec "$NS" python3 "$D/server.py" "$p" >"$D/server-$p.log" 2>&1 &
    PIDS+=($!)
  done
  sleep 0.6
}

# lab_agent <env ...>: start the agent (core datapath object from $BPF) and wait for attach.
# Extra objects the caller compiled are wired by passing NETRA_BPF_*_OBJECT in the env.
lab_agent() {
  echo "==> start netra-agent"
  rm -rf "$PIN_PATH"; mkdir -p "$PIN_PATH"
  env NODE_NAME="${NODE_NAME:-ci-${LAB_NAME}}" NETRA_SERVER="$BASE" NETRA_AGENT_KEY="$AGENT_KEY" \
    NETRA_BPF_OBJECT="$BPF/netra_tc.o" NETRA_BPF_PIN="$PIN_PATH" NETRA_CGROUP_PATH=/sys/fs/cgroup NETRA_CGROUP_ENABLED=true \
    "$@" "$BIN/netra-agent" >>"$AGENT_LOG" 2>&1 &
  AGENT_PID=$!; PIDS+=("$AGENT_PID")
  local _
  for _ in $(seq 1 80); do
    grep -q 'Netra standalone datapath attached' "$AGENT_LOG" 2>/dev/null && break
    kill -0 "$AGENT_PID" 2>/dev/null || lab_fail "the agent exited early"
    sleep 0.5
  done
  grep -q 'Netra standalone datapath attached' "$AGENT_LOG" || lab_fail "the datapath never attached"
  for _ in $(seq 1 40); do
    curl -sf -H "Authorization: Bearer ${API_KEY}" "${BASE}/api/v1/agents" | grep -q "\"${NODE_NAME:-ci-${LAB_NAME}}\"" && return 0
    sleep 0.5
  done
  lab_fail "the agent never reported to the controller"
}
