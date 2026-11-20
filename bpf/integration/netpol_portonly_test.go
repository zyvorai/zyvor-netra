// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

//go:build linux && bpfintegration

package bpfintegration

import (
	"bytes"
	"net"
	"testing"
)

// TestNetPolRuleKeyEncoding is a real, confirmed regression guard for the
// exact class of bug this whole test package was built to catch — but it
// deliberately doesn't invoke the kernel at all, for a reason discovered
// live in this package's own first CI run (see below).
//
// Originally this test drove netra_cgroup_egress via Program.Test() with
// synthetic packets, the same shape as TestSynDropCIDR. That attempt
// surfaced a real, separate constraint of BPF_PROG_TEST_RUN itself:
// bpf_get_current_cgroup_id() (bpf/netra_tc.c:1977, the value
// netpol_v2_lookup4 keys every lookup on) reads the cgroup associated with
// the skb's owning socket — for a cgroup_skb hook attached to a real
// socket send/receive, that's meaningful; for a synthetic __sk_buff built
// by BPF_PROG_TEST_RUN with no real socket behind it, there is no such
// association, and the helper returned 0 throughout. netpol_v2_lookup4's
// own guard (`if (!en || !*en || !cgroup_id) return 0`) then makes every
// single lookup a no-op regardless of what's seeded in netpol_rules4 —
// confirmed via diagnostics logged during that run (netpol_v2_enabled
// readback and a same-key Go-side map readback were both correct; only
// packets run through the actual program never matched). This is a
// genuine gap in what BPF_PROG_TEST_RUN can exercise for this specific
// program type, not a bug in netpol_v2_lookup4, the map-key encoding, or
// this test package's harness — cilium/ebpf's RunOptions has no field to
// inject cgroup context, so there is no userspace-side fix available.
//
// TestSynDropCIDR/TestSynDropExactIP (netra_egress, a tc-hook program)
// don't have this problem: cgroup_id is always 0 on that path by design
// (bpf/netra_tc.c sets `__u64 cgroup_id = 0;` unconditionally in the
// HOOK_TC branch), so nothing about their behavior depends on a value
// BPF_PROG_TEST_RUN can't provide.
//
// What's still genuinely worth guarding here, and what this test does
// instead: the exact byte-level encoding a Go-side map write must produce
// to match what the kernel computes from a real packet + a real cgroup_skb
// hook (verified against the live diagnostic dump from that same CI run:
// cgroupID=6520, peer=1.2.3.4, port=443 exactly reproduced these bytes).
// This is precisely the class of bug this package fixed once already
// (internal/agent.applyNetPolV2's Port byte-order fix, 0.27.52) — a
// silent, no-panic, no-error mismatch that only manifests as "the rule
// never matches." A live-cluster functional check (real traffic, real
// attached cgroup hook, real socket) remains the only way to prove
// netpol_v2_lookup4's runtime behavior end-to-end; see docs/native-netpol.md.
func TestNetPolRuleKeyEncoding(t *testing.T) {
	const dirEgress = 2
	const protoTCP = 6

	t.Run("exact peer + port 443 matches the live-observed byte layout", func(t *testing.T) {
		// port 443 (0x01bb) is deliberately non-palindromic — the class of
		// port that exposed the byte-order bug this package regression-
		// guards. Expected bytes captured live from bpf/integration CI
		// run 34856509908's diagnostic dump of a Go-written key, confirmed
		// there to byte-for-byte match what a real cgroup_skb hook's
		// bpf_get_current_cgroup_id()+a real packet's dport produce on
		// that same real kernel.
		key := netpolRuleKey(6520, net.ParseIP("1.2.3.4"), 443, protoTCP, dirEgress)
		want := "78190000000000000102030401bb0602"
		if got := hexBytes(key[:]); got != want {
			t.Fatalf("netpolRuleKey(6520, 1.2.3.4, 443, TCP, egress) = %s, want %s", got, want)
		}
	})

	t.Run("port-only (nil peer) uses the zero wildcard sentinel and touches nothing else", func(t *testing.T) {
		exact := netpolRuleKey(6520, net.ParseIP("1.2.3.4"), 443, protoTCP, dirEgress)
		portOnly := netpolRuleKey(6520, nil, 443, protoTCP, dirEgress)
		if !bytes.Equal(portOnly[8:12], []byte{0, 0, 0, 0}) {
			t.Fatalf("port-only key's peer bytes = %x, want all-zero", portOnly[8:12])
		}
		if !bytes.Equal(exact[0:8], portOnly[0:8]) {
			t.Fatalf("cgroup_id bytes must be identical between exact-peer and port-only keys: %x vs %x", exact[0:8], portOnly[0:8])
		}
		if !bytes.Equal(exact[12:16], portOnly[12:16]) {
			t.Fatalf("port/protocol/direction bytes must be identical between exact-peer and port-only keys: %x vs %x", exact[12:16], portOnly[12:16])
		}
	})
}

func hexBytes(b []byte) string {
	const hexdigits = "0123456789abcdef"
	out := make([]byte, len(b)*2)
	for i, v := range b {
		out[i*2] = hexdigits[v>>4]
		out[i*2+1] = hexdigits[v&0xf]
	}
	return string(out)
}
