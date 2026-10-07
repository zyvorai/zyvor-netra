#!/usr/bin/env bash
# Netra — eBPF compile + userspace C tests + privileged BPF_PROG_TEST_RUN
#
# Mirrors the GitHub `ebpf` job so local and CI share one script:
#   1. Compile bpf/tests/*.c helpers and run them.
#   2. Compile netra_tc / edge / capture / tlsfp / tcpevents / dropinfo BPF objects.
#   3. Build bpf/integration tests and run under sudo (CAP_BPF).
#
# Requires: Linux, clang, llvm, linux-libc-dev, go; root (or CAP_BPF) for
# the integration binary.
#
# Usage:
#   sudo ./scripts/ci-ebpf-tests.sh
#   SKIP_INTEGRATION=1 ./scripts/ci-ebpf-tests.sh   # compile + C tests only
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

SKIP_INTEGRATION="${SKIP_INTEGRATION:-0}"
ARCH="$(uname -m)"
INC="/usr/include/${ARCH}-linux-gnu"
OUT="${OUT_DIR:-/tmp}"

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "missing required command: $1" >&2
    exit 1
  }
}

need_cmd cc
need_cmd clang
need_cmd go

if [[ "$(uname -s)" != "Linux" ]]; then
  echo "ci-ebpf-tests requires Linux" >&2
  exit 1
fi

echo "==> userspace BPF helper tests"
cc -std=c11 -O2 -Wall -Wextra -Werror -Ibpf bpf/tests/ipv6_walk_test.c -o "${OUT}/netra-ipv6-walk-test"
"${OUT}/netra-ipv6-walk-test"
cc -std=c11 -O2 -Wall -Wextra -Werror -Ibpf bpf/tests/icmp_parse_test.c -o "${OUT}/netra-icmp-test"
"${OUT}/netra-icmp-test"
cc -std=c11 -O2 -Wall -Wextra -Werror -Ibpf bpf/tests/l7_parse_test.c -o "${OUT}/netra-l7-parse-test"
"${OUT}/netra-l7-parse-test"
cc -std=c11 -O2 -Wall -Wextra -Werror bpf/tests/abi_layout_test.c -o "${OUT}/netra-abi-layout-test"
"${OUT}/netra-abi-layout-test"

cc -std=c11 -O2 -Wall -Wextra -Werror bpf/tests/dns_event_abi_test.c -o "${OUT}/netra-dns-event-abi-test"
"${OUT}/netra-dns-event-abi-test"

echo "==> compile BPF objects → ${OUT}"
# Every bpf/netra_*.c is compiled, so a new sensor cannot be added and forgotten
# here. netra_tc.c alone needs the larger stack estimate (see Dockerfile.agent).
for src in bpf/netra_*.c; do
  name="$(basename "$src" .c)"
  extra=()
  [[ "$name" == "netra_tc" ]] && extra=(-mllvm -bpf-stack-size=1024)
  echo "    ${src}"
  clang -target bpfel -O2 -g -Wall -Wextra -Werror -I"$INC" \
    ${extra[@]+"${extra[@]}"} -c "$src" -o "${OUT}/${name}.o"
done

if [[ "$SKIP_INTEGRATION" == "1" ]]; then
  echo "==> SKIP_INTEGRATION=1 — compiled objects only"
  echo "==> PASS ci-ebpf-tests (compile-only)"
  exit 0
fi

if [[ "${EUID}" -ne 0 ]]; then
  echo "integration tests need root (CAP_BPF); re-run with sudo or SKIP_INTEGRATION=1" >&2
  exit 1
fi

echo "==> build + run bpfintegration (sudo)"
BIN="${OUT}/bpfintegration.test"
# Prefer the invoking user's Go caches when run via sudo -E.
go test -tags=bpfintegration -c -o "$BIN" ./bpf/integration/
NETRA_BPF_TEST_OBJECT="${OUT}/netra_tc.o" \
NETRA_BPF_TLSFP_TEST_OBJECT="${OUT}/netra_tlsfp.o" \
NETRA_BPF_TCPEVENTS_TEST_OBJECT="${OUT}/netra_tcpevents.o" \
NETRA_BPF_DROPINFO_TEST_OBJECT="${OUT}/netra_dropinfo.o" \
NETRA_BPF_NODEISO_TEST_OBJECT="${OUT}/netra_nodeiso.o" \
NETRA_BPF_L7SAMPLE_TEST_OBJECT="${OUT}/netra_l7sample.o" \
NETRA_BPF_SSL_TEST_OBJECT="${OUT}/netra_ssl.o" \
NETRA_BPF_RTNL_TEST_OBJECT="${OUT}/netra_rtnl.o" \
  "$BIN" -test.v

# Sampled L7 protocol observer (docs/l7-sampling.md). These load the real object
# into the real verifier, attach it to a scratch cgroup holding only the test
# process, and drive genuine loopback TCP. They must pass AND not skip: a skip
# here (no cgroup v2, no permission) means the kernel half silently did not run.
# One of them captures every payload length from 1 to 140 bytes and requires the
# bytes back exactly, which is what guards the chunked copy and the bounds checks
# the verifier needs.
echo "==> L7 sampler: real verifier + real TCP, every payload length exact"
l7_log="${OUT}/l7sample.log"
NETRA_BPF_L7SAMPLE_TEST_OBJECT="${OUT}/netra_l7sample.o" \
  "$BIN" -test.v -test.count=1 -test.run 'TestL7Sample' >"$l7_log" 2>&1 || { cat "$l7_log"; exit 1; }
l7_pass="$(grep -c -- '^--- PASS: TestL7Sample' "$l7_log" || true)"
if grep -q -- '^--- SKIP: TestL7Sample' "$l7_log" || (( l7_pass < 7 )); then
  cat "$l7_log"
  echo "L7 sampler tests: ${l7_pass} passed (want 7) or some skipped" >&2
  exit 1
fi
echo "    ${l7_pass} passed"

# TLS plaintext sampler (docs/tls-plaintext.md): uprobes on the system's real libssl
# and genuine TLS between a Python HTTPS server and client (CPython calls
# SSL_read_ex/SSL_write_ex). They must pass AND not skip: a skip here (no python3,
# no openssl, no libssl mapped) means the kernel half silently did not run. The
# process allowlist is checked to be enforced in the kernel before any byte is copied.
echo "==> TLS sampler: real verifier + real libssl uprobes + real TLS"
ssl_log="${OUT}/ssl.log"
NETRA_BPF_SSL_TEST_OBJECT="${OUT}/netra_ssl.o" \
  "$BIN" -test.v -test.count=1 -test.run 'TestSSL' >"$ssl_log" 2>&1 || { cat "$ssl_log"; exit 1; }
ssl_pass="$(grep -c -- '^--- PASS: TestSSL' "$ssl_log" || true)"
if grep -q -- '^--- SKIP: TestSSL' "$ssl_log" || (( ssl_pass < 7 )); then
  cat "$ssl_log"
  echo "TLS sampler tests: ${ssl_pass} passed (want 7) or some skipped" >&2
  exit 1
fi
echo "    ${ssl_pass} passed"

# Who changed the network (bpf/netra_rtnl.c): the real object is loaded (an fentry on
# rtnetlink_rcv_msg, resolved against the running kernel's BTF) and the network is
# changed from this test process and from a child `ip`; the records must name each
# requester (comm, pid, cgroup, message type, interface), a read-only dump must
# record nothing, and nothing may be dropped. A second test runs the real netlink
# recorder, the sensor and the joiner together and requires each recorded change to be
# attributed: to `ip`, to this process, and, for a veth's carrier lost when its peer is
# set down, to the kernel and NOT to the `ip link set` that happened at that moment. A
# third checks that a change made in ANOTHER network namespace is not recorded at all.
# Only the kernel decides who the requester is, so this cannot be checked anywhere
# else. It must pass AND not skip.
echo "==> rtnl actor: real fentry on rtnetlink_rcv_msg names the process that changed the network"
rtnl_log="${OUT}/rtnl.log"
NETRA_BPF_RTNL_TEST_OBJECT="${OUT}/netra_rtnl.o" \
  "$BIN" -test.v -test.count=1 -test.run 'TestRTNLActor' >"$rtnl_log" 2>&1 || { cat "$rtnl_log"; exit 1; }
rtnl_pass="$(grep -c -- '^--- PASS: TestRTNLActor' "$rtnl_log" || true)"
if grep -q -- '^--- SKIP: TestRTNLActor' "$rtnl_log" || (( rtnl_pass < 3 )); then
  cat "$rtnl_log"
  echo "rtnl actor tests: ${rtnl_pass} passed (want 3) or some skipped" >&2
  exit 1
fi
echo "    ${rtnl_pass} passed"

# BPF attachment inventory (docs/bpf-attachments.md). Netra's real programs are
# attached (TCX ingress and egress, XDP, and a classic cls_bpf filter on the peer)
# to a scratch veth next to somebody else's program, and the real collector must
# report each with the right owner and the kernel's execution order; then a hook is
# detached and the interface deleted and recreated, and the drift diagnostic must
# say so. They must pass AND not skip: a skip here (no TCX, no permission) means
# the kernel half silently did not run.
echo "==> BPF attachments: real TCX/XDP/cls_bpf inventory and hook drift on a real kernel"
ba_log="${OUT}/bpfattach.log"
NETRA_BPF_TEST_OBJECT="${OUT}/netra_tc.o" \
  "$BIN" -test.v -test.count=1 -test.run 'TestBPFAttach' >"$ba_log" 2>&1 || { cat "$ba_log"; exit 1; }
ba_pass="$(grep -c -- '^--- PASS: TestBPFAttach' "$ba_log" || true)"
if grep -q -- '^--- SKIP: TestBPFAttach' "$ba_log" || (( ba_pass < 2 )); then
  cat "$ba_log"
  echo "BPF attachment tests: ${ba_pass} passed (want 2) or some skipped" >&2
  exit 1
fi
echo "    ${ba_pass} passed"

# Agent map reads. The agent reads several 131 072-entry LRU hash maps every few
# seconds; it used to walk each entry with two syscalls, decode and format all of
# them, sort all of them, and keep 1 000, which cost about two cores on a busy
# node. It now scans in batches and ranks raw bytes (internal/mapscan). These run
# against REAL BPF maps as root and must (a) pass, (b) not skip (a skip here means
# maps could not be created, i.e. the check silently did not happen), and (c) the
# new readers must return exactly what the legacy loops (kept as the reference in
# internal/agent/legacy_readers_test.go) returned.
echo "==> agent map reads: batched scan + top-N equal the legacy loops on real BPF maps"
mr_log="${OUT}/mapread.log"
go test -count=1 -race -v ./internal/mapscan >"$mr_log" 2>&1 || { cat "$mr_log"; exit 1; }
go test -count=1 -race -v -run 'TestNewReaders|TestReadersBelow|TestReadersFail|TestCountEntries' ./internal/agent >>"$mr_log" 2>&1 || { cat "$mr_log"; exit 1; }
mr_pass="$(grep -c -- '^--- PASS' "$mr_log" || true)"
if grep -q -- '--- SKIP' "$mr_log" || (( mr_pass < 15 )); then
  cat "$mr_log"
  echo "map read tests: ${mr_pass} passed (want at least 15) or some skipped" >&2
  exit 1
fi
echo "    ${mr_pass} passed"

# Listen queues (no BPF): half-open connections need the handshake's last ACK to
# go missing, which needs root and nft. Everything else in internal/listenq runs
# unprivileged in the `go` job (scripts/ci-listenq-unit.sh).
echo "==> listen queues: half-open (SYN_RECV) connections attributed to their listener"
lq_log="${OUT}/listenq-halfopen.log"
go test -count=1 -v -run 'TestDumpCountsHalfOpenConnections' ./internal/listenq >"$lq_log" 2>&1 || { cat "$lq_log"; exit 1; }
if grep -q -- '--- PASS: TestDumpCountsHalfOpenConnections' "$lq_log"; then
  echo "    passed"
else
  echo "    skipped: $(grep -m1 'diag_linux_test.go' "$lq_log" | sed 's/^ *//')"
fi

# The agent reads /dev/kmsg on every report. That read once blocked forever at
# the end of the kernel ring buffer on any quiet host (a fresh node, a CI runner),
# so the agent never reported and could not be stopped. Run the real-device case
# as root, where /dev/kmsg is readable.
echo "==> kmsg: reading the real kernel log must return, not block"
km_log="${OUT}/kmsg.log"
go test -count=1 -v -run 'TestSnapshotOfTheRealKernelLogReturns' ./internal/kmsg >"$km_log" 2>&1 || { cat "$km_log"; exit 1; }
grep -q -- '--- PASS: TestSnapshotOfTheRealKernelLogReturns' "$km_log" || { cat "$km_log"; echo "the real /dev/kmsg test did not run" >&2; exit 1; }
echo "    passed"

# Mutation guard. netra_dropinfo.c must never invent a tuple for a packet that
# is not IP; TestDropInfoNonIPFrame* proves that. This proves the test still
# *bites*: the same program with the safety check removed (family guessed from
# the header bytes) must make it fail. A test that passes on the mutant has
# stopped testing anything.
if [[ -e /sys/kernel/btf/vmlinux ]]; then
  echo "==> mutation guard: dropinfo family-guessing mutant must fail the non-IP test"
  base_log="${OUT}/dropinfo-nonip-base.log"
  NETRA_BPF_DROPINFO_TEST_OBJECT="${OUT}/netra_dropinfo.o" \
    "$BIN" -test.v -test.run 'TestDropInfoNonIPFrame' >"$base_log" 2>&1 || { cat "$base_log"; exit 1; }
  if ! grep -q -- '--- PASS: TestDropInfoNonIPFrame' "$base_log"; then
    echo "    skipped: the non-IP test did not run on this host (cannot inject a frame on lo)"
  else
    mut_src="${OUT}/netra_dropinfo_mut.c"
    sed 's/    if (ethertype == ETH_P_IP_HOST) {/    if (ethertype == ETH_P_IP_HOST || ethertype != ETH_P_IPV6_HOST) {/' \
      bpf/netra_dropinfo.c >"$mut_src"
    if cmp -s bpf/netra_dropinfo.c "$mut_src"; then
      echo "mutation guard is stale: the mutated line no longer exists in bpf/netra_dropinfo.c" >&2
      exit 1
    fi
    clang -target bpfel -O2 -g -Wall -Wextra -Werror -I"$INC" -c "$mut_src" -o "${OUT}/netra_dropinfo_mut.o"
    if NETRA_BPF_DROPINFO_TEST_OBJECT="${OUT}/netra_dropinfo_mut.o" \
      "$BIN" -test.v -test.run 'TestDropInfoNonIPFrame' >"${OUT}/dropinfo-nonip-mut.log" 2>&1; then
      cat "${OUT}/dropinfo-nonip-mut.log"
      echo "MUTANT SURVIVED: TestDropInfoNonIPFrame passes with the ethertype check removed" >&2
      exit 1
    fi
    echo "    mutant killed (test failed as it must)"
  fi
else
  echo "==> mutation guard skipped: kernel has no BTF"
fi

echo "==> PASS ci-ebpf-tests"
