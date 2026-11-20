#!/usr/bin/env bash
# Netra — enforcement really drops packets, and stops when it should (Linux, root)
#
# Real netrad + real netra-agent (core datapath: cgroup_skb egress/ingress and connect
# hooks, no optional sensors) on a real veth pair into a network namespace, with an HTTP
# server on the far side. Every step is paired: traffic flows, a rule is applied, traffic
# stops, the rule is removed, traffic flows again. Asserts:
#
#   observe   a deny rule NEVER blocks in observe mode (only enforce mode drops)
#   enforce   exact IP (egress and ingress, each only its own direction), CIDR and port rules drop, and only what they
#             name (a second port on the same host keeps working); IPv6 the same; an
#             allow rule overrides a deny rule; removing the rule restores traffic
#   evidence  the drop is recorded: the controller's block export
#             names the destination
#   bounds    an enforcement lease expires on its own (traffic flows again with the deny
#             rule still listed); and if the controller dies the agent fails open to
#             observe after NETRA_FAILSAFE_AFTER
#
# Usage:
#   sudo ./scripts/ci-enforce-veth.sh
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
# shellcheck disable=SC2034 # read by the sourced lab library
LAB_NAME=enf; CONTROLLER_PORT="${CONTROLLER_PORT:-31982}"
# shellcheck source=lib/veth-lab.sh
source "$ROOT/scripts/lib/veth-lab.sh"

NET="10.255.90.0/24"
P1=18781; P2=18782; P3=18783
fail() { lab_fail "$@"; }

lab_build netra_tc
lab_netrad
lab_veth
lab_servers "$P1" "$P2"
# A server in the root namespace too, so a connection can be started FROM the far side
# (the direction an ingress rule guards).
python3 "$D/server.py" "$P3" >"$D/server-$P3.log" 2>&1 &
PIDS+=($!)
sleep 0.4

reach() { lab_reach "$@"; }
U4="http://${IP1}:${P1}/"; U4b="http://${IP1}:${P2}/"; U6="http://[${V6_1}]:${P1}/"
# reach_in: an HTTP 200 for a request made from INSIDE the namespace (a connection started by the far side)
reach_in() { [[ "$(ip netns exec "$NS" curl -s -o /dev/null --connect-timeout 2 --max-time 3 -w '%{http_code}' "$@" 2>/dev/null)" == 200 ]]; }
UIN="http://${IP0}:${P3}/"
reach "$U4" && reach "$U4b" && reach "$U6" && reach_in "$UIN" || fail "the servers are not reachable over the veth before any agent runs (test setup)"

# Core datapath only, a fast fail-open, on the whole cgroup tree.
NODE_NAME=ci-enforce lab_agent \
  NETRA_L7=off NETRA_TLSFP=off NETRA_EDGE_INTEL=off NETRA_CAPTURE=off NETRA_TCX=off NETRA_TCP_EVENTS=off NETRA_DROP_INFO=off \
  NETRA_LISTEN_QUEUES=off NETRA_INTERFACES='' NETRA_XDP_INTERFACES='' NETRA_FAILSAFE_AFTER=12s

api() { lab_api "$@"; }
post() { api -X POST -d "$2" "${BASE}$1" >/dev/null || lab_fail "POST $1 $2"; }
del()  { api -X DELETE "${BASE}$1" >/dev/null || lab_fail "DELETE $1"; }
mode() { api -X PUT -d "{\"mode\":\"$1\"}" "${BASE}/api/v1/ebpf/mode${2:+?lease=$2}" >/dev/null || lab_fail "set mode $1"; }

# The agent picks up configuration every 3 seconds, so wait for the effect, bounded.
expect_open_in()    { local why="$1"; shift; for _ in $(seq 1 30); do reach_in "$@" && return 0; sleep 1; done; lab_fail "$why: traffic never flowed"; }
expect_blocked_in() { local why="$1"; shift; for _ in $(seq 1 30); do reach_in "$@" || return 0; sleep 1; done; lab_fail "$why: traffic was not blocked"; }
expect_open()    { local why="$1"; shift; for _ in $(seq 1 30); do reach "$@" && return 0; sleep 1; done; lab_fail "$why: traffic never flowed"; }
expect_blocked() { local why="$1"; shift; for _ in $(seq 1 30); do reach "$@" || return 0; sleep 1; done; lab_fail "$why: traffic was not blocked"; }
stays_open()     { local why="$1"; shift; sleep 8; reach "$@" || lab_fail "$why: traffic was blocked but must not be"; }

echo "==> baseline"
expect_open "baseline v4" "$U4"; expect_open "baseline v6" "$U6"
echo "    open on both families"

echo "==> observe mode never blocks, even with a deny rule"
post /api/v1/ebpf/deny "{\"ip\":\"${IP1}\",\"direction\":\"both\"}"
stays_open "deny rule in observe mode" "$U4"
echo "    deny ${IP1} in observe: still open"

echo "==> enforce mode: the exact-IP rule drops, and the drop is recorded"
mode enforce 5m
expect_blocked "exact IP deny (egress+ingress)" "$U4"
ok=0
for _ in $(seq 1 20); do
  if api "${BASE}/api/v1/export/blocks?format=json&limit=50" | grep -q "${IP1}"; then ok=1; break; fi
  sleep 1
done
[[ "$ok" == 1 ]] || lab_fail "the drop was not recorded: the block export never named ${IP1}"
api "${BASE}/api/v1/export/blocks?format=json&limit=50" | python3 -c '
import json, sys
recs = json.load(sys.stdin)
recs = recs if isinstance(recs, list) else recs.get("items", recs.get("records", []))
mine = [r for r in recs if "'"${IP1}"'" in json.dumps(r)]
assert mine, ("no block record names '"${IP1}"'", recs[:2])
print("    blocked; the block export records it:", json.dumps(mine[0])[:220])'
del "/api/v1/ebpf/deny/${IP1}"
expect_open "after removing the exact-IP rule" "$U4"
echo "    rule removed: open again"

echo "==> an allow rule overrides a deny rule"
post /api/v1/ebpf/deny "{\"ip\":\"${IP1}\",\"direction\":\"both\"}"
expect_blocked "deny before allow" "$U4"
post /api/v1/ebpf/allow "{\"ip\":\"${IP1}\"}"
expect_open "allow overriding deny" "$U4"
del "/api/v1/ebpf/allow/${IP1}"
expect_blocked "deny again after the allow is removed" "$U4"
del "/api/v1/ebpf/deny/${IP1}"
expect_open "after clearing deny" "$U4"
echo "    deny -> allow wins -> allow removed -> deny wins -> cleared"

echo "==> direction: an egress rule guards connections we start, an ingress rule those the peer starts"
# Replies to a connection we started are exempt (connection tracking), so an ingress rule
# is proven with a connection started from the far side, and never blocks our own.
post /api/v1/ebpf/deny "{\"ip\":\"${IP1}\",\"direction\":\"ingress\"}"
expect_blocked_in "ingress deny: a connection started by ${IP1}" "$UIN"
reach "$U4" || lab_fail "an ingress rule blocked a connection WE started (its replies must be exempt)"
del "/api/v1/ebpf/deny/${IP1}"; expect_open_in "after the ingress rule is removed" "$UIN"
post /api/v1/ebpf/deny "{\"ip\":\"${IP1}\",\"direction\":\"egress\"}"
expect_blocked "egress deny: a connection we start" "$U4"
reach_in "$UIN" || lab_fail "an egress rule blocked a connection started by the far side"
del "/api/v1/ebpf/deny/${IP1}"; expect_open "after the egress rule is removed" "$U4"
echo "    ingress and egress rules each guard only their own direction"

echo "==> a CIDR rule drops the whole prefix"
post /api/v1/ebpf/cidr "{\"cidr\":\"${NET}\",\"direction\":\"egress\"}"
expect_blocked "CIDR deny" "$U4"
post /api/v1/ebpf/cidr/delete "{\"cidr\":\"${NET}\",\"direction\":\"egress\"}"
expect_open "after CIDR removed" "$U4"

echo "==> a port rule drops only that port on the same host"
post /api/v1/ebpf/port "{\"port\":${P1},\"protocol\":\"TCP\",\"direction\":\"egress\"}"
expect_blocked "port ${P1} deny" "$U4"
reach "$U4b" || lab_fail "the port rule for ${P1} also blocked port ${P2} on the same host"
post /api/v1/ebpf/port/delete "{\"port\":${P1},\"protocol\":\"TCP\",\"direction\":\"egress\"}"
expect_open "after port rule removed" "$U4"
echo "    ${P1} blocked while ${P2} stayed open"

echo "==> IPv6 rules drop IPv6 and leave IPv4 alone"
post /api/v1/ebpf/deny "{\"ip\":\"${V6_1}\",\"direction\":\"both\"}"
expect_blocked "IPv6 deny" "$U6"
reach "$U4" || lab_fail "an IPv6 deny rule blocked IPv4"
del "/api/v1/ebpf/deny/${V6_1}"
expect_open "after the IPv6 rule is removed" "$U6"

echo "==> switching back to observe stops enforcement without removing rules"
post /api/v1/ebpf/deny "{\"ip\":\"${IP1}\",\"direction\":\"both\"}"
expect_blocked "deny in enforce" "$U4"
mode observe
expect_open "enforce -> observe with the rule still listed" "$U4"
api "${BASE}/api/v1/ebpf/config" | grep -q "${IP1}" || lab_fail "the deny rule disappeared when the mode changed"
echo "    open in observe; rule still present"

echo "==> an enforcement lease expires on its own (about 70 s)"
mode enforce 1m
expect_blocked "deny under a fresh lease" "$U4"
sleep 70
expect_open "after the 1 minute lease expired" "$U4"
api "${BASE}/api/v1/ebpf/config" | grep -q "${IP1}" || lab_fail "the deny rule was dropped when the lease expired"
echo "    lease expired: open again, deny rule intact"

echo "==> if the controller dies the agent fails open to observe"
mode enforce 10m
expect_blocked "deny before the controller dies" "$U4"
kill -9 "$NETRAD_PID"; wait "$NETRAD_PID" 2>/dev/null || true
expect_open "after the controller died (fail-open, NETRA_FAILSAFE_AFTER=12s)" "$U4"
grep -q "forced Netra datapath to observe" "$AGENT_LOG" || lab_fail "the agent did not log its fail-open"
echo "    controller killed: the agent forced observe and traffic flows"

echo "==> PASS enforce veth"
