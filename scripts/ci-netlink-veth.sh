#!/usr/bin/env bash
# Netra — netlink change recorder real-kernel smoke (veth, no BPF)
#
# Drives the real RTNL recorder against a real kernel, inside a throwaway network
# namespace so the host's network is never touched:
#
#   1. veth create, address add/del, route add/del (via a gateway), permanent
#      neighbor add/del, MTU change, link down and delete are each recorded with
#      the right kind, action, interface name and fields, and the full snapshot
#      shows the same objects.
#   2. A route storm larger than the kernel receive buffer overflows the
#      subscription (ENOBUFS). The recorder must count and record the overrun,
#      re-establish the subscription, resnapshot, and record a route added
#      afterwards. The library ends a subscription on the first ENOBUFS and never
#      reopens it; this proves the supervisor does.
#
# The tests are internal/netlinkwatch/kernel_linux_test.go. They skip unless
# NETRA_NETLINK_KERNEL_TESTS=1, which only this script sets, so `go test ./...`
# never changes a network.
#
# Requires: Linux, root, go, iproute2.
# Usage:
#   sudo ./scripts/ci-netlink-veth.sh
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

NS="${NS:-netra-netlink-test}"
BIN_DIR="${BIN_DIR:-$(mktemp -d /tmp/netra-netlink-bin.XXXXXX)}"

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "missing required command: $1" >&2
    exit 1
  }
}

need_cmd go
need_cmd ip

if [[ "$(uname -s)" != "Linux" ]]; then
  echo "this smoke test requires Linux (RTNL, veth)" >&2
  exit 1
fi
if [[ "${EUID}" -ne 0 ]]; then
  echo "run as root (needed to create a namespace and a veth pair)" >&2
  exit 1
fi

cleanup() {
  set +e
  ip netns del "$NS" 2>/dev/null
  rm -rf "$BIN_DIR"
}
trap cleanup EXIT

echo "==> build the kernel test binary"
mkdir -p "$BIN_DIR"
go test -c -o "$BIN_DIR/netlinkwatch.test" ./internal/netlinkwatch/

echo "==> throwaway network namespace ${NS}"
ip netns del "$NS" 2>/dev/null || true
ip netns add "$NS"
ip -n "$NS" link set lo up

echo "==> real-kernel tests inside ${NS}"
out="$(ip netns exec "$NS" env NETRA_NETLINK_KERNEL_TESTS=1 \
  "$BIN_DIR/netlinkwatch.test" -test.v -test.count=1 -test.timeout=180s -test.run 'TestKernel' 2>&1)" || {
  echo "$out"
  echo "kernel tests failed" >&2
  exit 1
}
echo "$out"

# A skipped test is not a pass: without this a missing guard variable, or a
# missing root, would print "ok" while proving nothing.
n="$(grep -c -- '^--- PASS: TestKernel' <<<"$out" || true)"
if (( n < 2 )); then
  echo "only ${n} kernel tests passed, expected 2 (a skip does not count)" >&2
  exit 1
fi

echo "==> PASS ci-netlink-veth (${n} kernel tests)"
