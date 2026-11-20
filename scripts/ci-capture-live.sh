#!/usr/bin/env bash
# Netra — manual packet capture, end to end, on both backends (Linux, root)
#
# Real netrad + real netra-agent on a veth into a namespace, real HTTP traffic. For each
# backend (eBPF/TCX, AF_PACKET) a filtered capture is started through the API and a
# separate client plays the browser's part: it opens the controller's capture WebSocket,
# decodes the streamed frames, and writes a classic .pcap. Asserts:
#
#   filter    every captured frame matches the filter (TCP, the server host, the chosen
#             port); traffic to a second port on the same host is NOT captured
#   fidelity  both directions are seen; the frames parse as Ethernet/IP/TCP; the .pcap is a
#             valid libpcap file with exactly the streamed frames, readable by tcpdump
#   control   a capture with no filter is refused; an unknown backend is refused; the
#             active capture is listed while it runs; stopping it works once (a second
#             stop is a 404) and ends the stream; the session lands in the history with
#             its backend, requestor and stop reason; a capture with a duration ends on
#             its own
#
# Usage:
#   sudo ./scripts/ci-capture-live.sh
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
# shellcheck disable=SC2034 # read by the sourced lab library
LAB_NAME=cap; CONTROLLER_PORT="${CONTROLLER_PORT:-31984}"
# shellcheck disable=SC2034 # read by the sourced lab library
LAB_EXTRA_CMDS="netra-ci-capture-client"
# shellcheck source=lib/veth-lab.sh
source "$ROOT/scripts/lib/veth-lab.sh"

NODE="ci-cap"; export NODE_NAME="$NODE"
P1=18791; P2=18792
U1="http://${IP1}:${P1}/"; U2="http://${IP1}:${P2}/"

lab_build netra_tc netra_capture
lab_netrad
lab_veth
lab_servers "$P1" "$P2"
lab_reach "$U1" && lab_reach "$U2" || lab_fail "the servers are not reachable before any agent runs (test setup)"
lab_agent \
  NETRA_BPF_CAPTURE_OBJECT="$BPF/netra_capture.o" NETRA_CAPTURE=auto NETRA_INTERFACES="$IF0" \
  NETRA_L7=off NETRA_TLSFP=off NETRA_EDGE_INTEL=off NETRA_TCP_EVENTS=off NETRA_DROP_INFO=off NETRA_LISTEN_QUEUES=off NETRA_XDP_INTERFACES=''
grep -q 'capture-tcx-ingress' "$AGENT_LOG" || lab_fail "the eBPF capture hooks did not attach on ${IF0}"

CLIENT="$BIN/netra-ci-capture-client"
start_capture() { # start_capture <json body> -> HTTP status
  curl -s -o "$D/start.out" -w '%{http_code}' -X PUT -H "Authorization: Bearer ${API_KEY}" -H 'Content-Type: application/json' -d "$1" "${BASE}/api/v1/vms/${NODE}/capture"
}
traffic() { # a burst to both ports: only the first is inside the filter
  for _ in $(seq 1 6); do curl -s -o /dev/null --max-time 3 "$U1" || true; curl -s -o /dev/null --max-time 3 "$U2" || true; done
}
pcap_check() { # pcap_check <file> <frames>: libpcap header, exact frame count, readable by tcpdump
  python3 - "$1" "$2" <<'PY'
import struct, sys
path, want = sys.argv[1], int(sys.argv[2])
b = open(path, "rb").read()
assert len(b) >= 24, "pcap shorter than its global header"
magic, vmaj, vmin, _, _, snap, link = struct.unpack("<IHHiIII", b[:24])
assert magic == 0xa1b2c3d4 and (vmaj, vmin) == (2, 4) and link == 1, ("not a classic Ethernet pcap", hex(magic), vmaj, vmin, link)
off, n = 24, 0
while off < len(b):
    assert off + 16 <= len(b), "truncated pcap record header"
    _, _, caplen, _ = struct.unpack("<IIII", b[off:off+16])
    off += 16 + caplen; n += 1
assert off == len(b), "pcap does not end on a record boundary"
assert n == want, ("the pcap holds %d records but %d frames were streamed" % (n, want))
PY
  if command -v tcpdump >/dev/null 2>&1; then
    tcpdump -nr "$1" >"$D/tcpdump.out" 2>&1 || lab_fail "tcpdump could not read the pcap: $(tail -3 "$D/tcpdump.out")"
    [[ "$(grep -c 'IP' "$D/tcpdump.out")" -ge 1 ]] || lab_fail "tcpdump shows no IP packets in the pcap"
  fi
}

echo "==> a capture with no filter, or an unknown backend, is refused"
code="$(start_capture '{"backend":"ebpf"}')"
[[ "$code" == 400 ]] || lab_fail "an unfiltered capture returned HTTP $code, want 400"
code="$(start_capture "{\"backend\":\"quantum\",\"protocol\":\"tcp\",\"host\":\"${IP1}\"}")"
[[ "$code" == 400 ]] || lab_fail "an unknown backend returned HTTP $code, want 400"
echo "    both refused with 400"

run_backend() { # run_backend <ebpf|afpacket>
  local backend="$1" pcap="$D/$1.pcap" sum="$D/$1.json"
  echo "==> ${backend}: capture TCP to ${IP1}:${P1}, streamed and saved as a pcap"
  rm -f "$D/ready.$backend"
  "$CLIENT" -controller "$BASE" -key "$API_KEY" -node "$NODE" -out "$pcap" -duration 16s -ready-file "$D/ready.$backend" >"$sum" &
  local cpid=$!; PIDS+=("$cpid")
  for _ in $(seq 1 40); do [[ -f "$D/ready.$backend" ]] && break; sleep 0.25; done
  [[ -f "$D/ready.$backend" ]] || lab_fail "${backend}: the capture client never connected to the WebSocket"
  local status
  status="$(start_capture "{\"backend\":\"${backend}\",\"protocol\":\"tcp\",\"host\":\"${IP1}\",\"port\":${P1},\"durationSeconds\":40}")"
  [[ "$status" == 200 ]] || lab_fail "${backend}: starting the capture returned HTTP ${status}: $(cat "$D/start.out")"
  # The agent picks the request up on its next 3 s sync; keep generating traffic meanwhile.
  for _ in $(seq 1 8); do traffic; sleep 1; done
  lab_api "${BASE}/api/v1/capture/status" | grep -q "\"${NODE}\"" || lab_fail "${backend}: the active capture is not listed in /capture/status"
  wait "$cpid" || lab_fail "${backend}: the capture client failed"
  python3 - "$sum" "$IP0" "$IP1" "$P1" "$P2" "$backend" <<'PY' || lab_fail "${backend}: capture content"
import json, sys
s = json.load(open(sys.argv[1])); ip0, ip1, p1, p2, be = sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5], sys.argv[6]
assert s["frames"] > 0, ("no frames were captured", s)
assert s["undecoded"] == 0, ("frames that do not parse as Ethernet/IP/TCP", s)
assert set(s["protocols"]) == {"tcp"}, ("only TCP was asked for", s["protocols"])
assert set(s["families"]) == {"ipv4"}, s["families"]
assert p2 not in s["dstPorts"] and p2 not in s["srcPorts"], ("traffic to the second port leaked through the filter", s["dstPorts"], s["srcPorts"])
for t in s["tuples"]:
    src, dst = t.split(">")
    hosts = {src.rsplit(":", 1)[0], dst.rsplit(":", 1)[0]}
    ports = {src.rsplit(":", 1)[1], dst.rsplit(":", 1)[1]}
    assert ip1 in hosts, ("a frame that does not involve the filtered host", t)
    assert p1 in ports, ("a frame that does not involve the filtered port", t)
assert {"ingress", "egress"} <= set(s["directions"]), ("both directions are expected: requests leave, replies arrive", s["directions"])
print("    %d frames, directions %s, tuples %d, second port absent" % (s["frames"], s["directions"], len(s["tuples"])))
PY
  local frames
  frames="$(python3 -c "import json;print(json.load(open('$sum'))['frames'])")"
  pcap_check "$pcap" "$frames"
  echo "    pcap valid: ${frames} records"
  local code
  code="$(curl -s -o /dev/null -w '%{http_code}' -X DELETE -H "Authorization: Bearer ${API_KEY}" "${BASE}/api/v1/vms/${NODE}/capture")"
  [[ "$code" == 200 ]] || lab_fail "${backend}: stopping the capture returned HTTP $code, want 200"
  code="$(curl -s -o /dev/null -w '%{http_code}' -X DELETE -H "Authorization: Bearer ${API_KEY}" "${BASE}/api/v1/vms/${NODE}/capture")"
  [[ "$code" == 404 ]] || lab_fail "${backend}: a second stop returned HTTP $code, want 404"
  lab_api "${BASE}/api/v1/capture/status" | grep -q "\"${NODE}\"" && lab_fail "${backend}: the stopped capture is still listed as active"
  lab_api "${BASE}/api/v1/capture/history" >"$D/history.json"
  python3 - "$D/history.json" "$backend" "$NODE" "$IP1" "$P1" <<'PY' || lab_fail "${backend}: capture history"
import json, sys
path, be, node, host, port = sys.argv[1:6]
h = json.load(open(path))
items = h.get("entries", []) if isinstance(h, dict) else h
mine = [e for e in items if e.get("node") == node and e.get("backend") == be]
assert mine, ("no history entry for this session", be, items[:3])
e = mine[-1]
assert e.get("reason") == "manual", ("stop reason", e)
assert e.get("requestor"), ("no requestor recorded", e)
assert e.get("host") == host and str(e.get("port")) == port, ("the filter was not recorded", e)
print("    history: %s stopped %s by %s" % (be, e["reason"], e["requestor"]))
PY
}

run_backend ebpf
run_backend afpacket

echo "==> a capture with a duration ends on its own"
status="$(start_capture "{\"backend\":\"ebpf\",\"protocol\":\"tcp\",\"host\":\"${IP1}\",\"port\":${P1},\"durationSeconds\":4}")"
[[ "$status" == 200 ]] || lab_fail "starting a 4 s capture returned HTTP $status"
lab_api "${BASE}/api/v1/capture/status" | grep -q "\"${NODE}\"" || lab_fail "the 4 s capture is not listed while active"
ended=0
for _ in $(seq 1 30); do
  if ! lab_api "${BASE}/api/v1/capture/status" | grep -q "\"${NODE}\""; then ended=1; break; fi
  sleep 1
done
[[ "$ended" == 1 ]] || lab_fail "a capture with durationSeconds=4 never ended"
lab_api "${BASE}/api/v1/capture/history" | python3 -c 'import json,sys; e=json.load(sys.stdin)["entries"]; sys.exit(0 if any(x.get("reason")=="expired" for x in e) else 1)' || lab_fail "the expired capture is not in the history with reason expired"
echo "    ended on its own; history reason expired"

echo "==> PASS capture live"
