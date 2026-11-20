#!/usr/bin/env bash
# Netra — iperf3 traffic generator for manually verifying packet capture
#
# Generates real, deterministic traffic on a known host:port so a Netra
# capture session started against that same host/port has something to
# show in Live View / Capture History. Not part of any automated test
# suite: it needs a real reachable target and (for the client role) a
# running `iperf3 -s` on that target.
#
# For the automated Linux CI smoke (veth netns + auto-capture PCAP assert),
# use scripts/ci-auto-capture-veth.sh instead (GitHub job auto-capture-veth).
#
#   # On the node you'll capture from, start a receiver:
#   ./scripts/iperf3-traffic-gen.sh --server --port 5201
#
#   # From another host (or the same one), generate traffic against it —
#   # start a Netra capture on the target node/port first, then run:
#   ./scripts/iperf3-traffic-gen.sh 10.0.0.9 --port 5201 --duration 30 --protocol tcp
set -euo pipefail

PORT=5201
DURATION=30
PROTOCOL=tcp
SERVER_MODE=false
TARGET=""

usage() {
  sed -n '2,15p' "$0" | sed 's/^# \{0,1\}//'
  exit "${1:-0}"
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --server) SERVER_MODE=true; shift ;;
    --port) PORT="$2"; shift 2 ;;
    --duration) DURATION="$2"; shift 2 ;;
    --protocol) PROTOCOL="$2"; shift 2 ;;
    -h|--help) usage 0 ;;
    -*) echo "unknown flag: $1" >&2; usage 1 ;;
    *) TARGET="$1"; shift ;;
  esac
done

if ! command -v iperf3 >/dev/null 2>&1; then
  echo "iperf3 not found. Install it first:" >&2
  echo "  Debian/Ubuntu: sudo apt-get install -y iperf3" >&2
  echo "  RHEL/Fedora:   sudo yum install -y iperf3" >&2
  echo "  macOS:         brew install iperf3" >&2
  exit 1
fi

if [[ "$PROTOCOL" != "tcp" && "$PROTOCOL" != "udp" ]]; then
  echo "protocol must be tcp or udp, got: $PROTOCOL" >&2
  exit 1
fi

if $SERVER_MODE; then
  echo "Starting iperf3 server on port ${PORT} (Ctrl-C to stop)…"
  exec iperf3 -s -p "$PORT"
fi

if [[ -z "$TARGET" ]]; then
  echo "target host/IP is required (or pass --server to run as the receiver)" >&2
  usage 1
fi

PROTO_FLAG=()
[[ "$PROTOCOL" == "udp" ]] && PROTO_FLAG=(-u)

echo "Generating ${PROTOCOL} traffic against ${TARGET}:${PORT} for ${DURATION}s…"
iperf3 -c "$TARGET" -p "$PORT" -t "$DURATION" "${PROTO_FLAG[@]}"
