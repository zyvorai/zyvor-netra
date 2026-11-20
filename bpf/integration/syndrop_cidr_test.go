// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

//go:build linux && bpfintegration

package bpfintegration

import (
	"net"
	"testing"
)

// TestSynDropCIDR proves, deterministically and in-process against the real
// compiled netra_egress program, the exact distinction live-cluster testing
// couldn't isolate (see CHANGELOG.md's 0.27.51 "Update" note): SYN-drop
// mode's `!syn_new` gate (bpf/netra_tc.c:1958-1960) is a pure TCP-flag check
// on the *current packet* (SYN set, ACK clear), not a conntrack/"is this
// connection established" check — a fresh, empty conntrack map doesn't
// change the verdict at all, since decide4() runs for every packet that
// isn't itself a new-SYN, regardless of prior connection state. Each case
// below uses a distinct source port so conntrack entries never collide
// across cases (ct_key includes ports — see bpf/netra_tc.c:793-799).
func TestSynDropCIDR(t *testing.T) {
	coll := loadCollection(t)
	setEnforceMode(t, coll)
	prog := mustProgram(t, coll, "netra_egress")

	blockedCIDR := mustMap(t, coll, "blocked_cidr_v4")
	syndropCIDR := mustMap(t, coll, "syndrop_cidr_v4")

	const dirEgress = 2
	testCIDR := net.ParseIP("203.0.113.0")    // TEST-NET-3, RFC 5737
	testAddr := net.ParseIP("203.0.113.42")   // inside the /24
	unaffected := net.ParseIP("198.51.100.9") // TEST-NET-2, outside the /24
	srcIP := net.ParseIP("10.0.0.5")

	// Full CIDR block only — no SYN-drop flag yet. Every packet (SYN or
	// not) to an address in the CIDR must be dropped; a different
	// destination must be unaffected. This is the control this project's
	// live testing already confirmed by hand (203.0.113.0/24 was never
	// actually reachable, but 8.8.8.8/32 and 127.0.0.1/32 controls were)
	// — reproduced here deterministically.
	if err := blockedCIDR.Put(cidrKey4(24, dirEgress, testCIDR), uint8(1)); err != nil {
		t.Fatalf("seed blocked_cidr_v4: %v", err)
	}

	t.Run("full_block/new_syn_dropped", func(t *testing.T) {
		frame := buildTCFrame(srcIP, testAddr, 40001, 443, tcpSYN)
		ret, _, err := prog.Test(frame)
		if err != nil {
			t.Fatalf("Program.Test: %v", err)
		}
		if ret != tcActShot {
			t.Fatalf("full CIDR block, new SYN: want TC_ACT_SHOT, got %s", fmtVerdict(ret))
		}
	})

	t.Run("full_block/non_syn_also_dropped", func(t *testing.T) {
		frame := buildTCFrame(srcIP, testAddr, 40002, 443, tcpACK)
		ret, _, err := prog.Test(frame)
		if err != nil {
			t.Fatalf("Program.Test: %v", err)
		}
		if ret != tcActShot {
			t.Fatalf("full CIDR block (no SYN-drop flag), non-SYN packet: want TC_ACT_SHOT, got %s", fmtVerdict(ret))
		}
	})

	t.Run("full_block/different_destination_unaffected", func(t *testing.T) {
		frame := buildTCFrame(srcIP, unaffected, 40003, 443, tcpSYN)
		ret, _, err := prog.Test(frame)
		if err != nil {
			t.Fatalf("Program.Test: %v", err)
		}
		if ret != tcActOK {
			t.Fatalf("unrelated destination: want TC_ACT_OK, got %s", fmtVerdict(ret))
		}
	})

	// Now flag the same CIDR for SYN-drop mode.
	if err := syndropCIDR.Put(cidrKey4(24, dirEgress, testCIDR), uint8(1)); err != nil {
		t.Fatalf("seed syndrop_cidr_v4: %v", err)
	}

	t.Run("syn_drop_flagged/new_syn_still_dropped", func(t *testing.T) {
		frame := buildTCFrame(srcIP, testAddr, 40004, 443, tcpSYN)
		ret, _, err := prog.Test(frame)
		if err != nil {
			t.Fatalf("Program.Test: %v", err)
		}
		if ret != tcActShot {
			t.Fatalf("SYN-drop flagged, new SYN: want TC_ACT_SHOT (a genuinely new connection attempt must still be dropped), got %s", fmtVerdict(ret))
		}
	})

	t.Run("syn_drop_flagged/non_syn_let_through", func(t *testing.T) {
		// This is the exact case live-cluster testing could not cleanly
		// prove (see CHANGELOG.md 0.27.51): a non-SYN packet for a
		// deny-matched, SYN-drop-flagged address/direction must now pass.
		frame := buildTCFrame(srcIP, testAddr, 40005, 443, tcpACK)
		ret, _, err := prog.Test(frame)
		if err != nil {
			t.Fatalf("Program.Test: %v", err)
		}
		if ret != tcActOK {
			t.Fatalf("SYN-drop flagged, non-SYN packet: want TC_ACT_OK (the SYN-drop exception must apply), got %s", fmtVerdict(ret))
		}
	})

	t.Run("syn_drop_flagged/different_destination_unaffected", func(t *testing.T) {
		frame := buildTCFrame(srcIP, unaffected, 40006, 443, tcpACK)
		ret, _, err := prog.Test(frame)
		if err != nil {
			t.Fatalf("Program.Test: %v", err)
		}
		if ret != tcActOK {
			t.Fatalf("unrelated destination: want TC_ACT_OK, got %s", fmtVerdict(ret))
		}
	})
}

// TestSynDropExactIP mirrors TestSynDropCIDR for the original (0.27.34,
// live-verified then) exact-IP syndrop_v4/blocked_v4 maps — this project's
// first automated regression guard for a feature that, until now, has only
// ever been checked by hand on a live cluster.
func TestSynDropExactIP(t *testing.T) {
	coll := loadCollection(t)
	setEnforceMode(t, coll)
	prog := mustProgram(t, coll, "netra_egress")

	blockedV4 := mustMap(t, coll, "blocked_v4")
	syndropV4 := mustMap(t, coll, "syndrop_v4")

	const dirEgress = 2
	testAddr := net.ParseIP("203.0.113.77")
	srcIP := net.ParseIP("10.0.0.6")

	var addrKey [4]byte
	copy(addrKey[:], testAddr.To4())
	if err := blockedV4.Put(addrKey, uint8(1)); err != nil {
		t.Fatalf("seed blocked_v4: %v", err)
	}
	if err := syndropV4.Put(syndropKey4(testAddr, dirEgress), uint8(1)); err != nil {
		t.Fatalf("seed syndrop_v4: %v", err)
	}

	t.Run("new_syn_still_dropped", func(t *testing.T) {
		frame := buildTCFrame(srcIP, testAddr, 40101, 443, tcpSYN)
		ret, _, err := prog.Test(frame)
		if err != nil {
			t.Fatalf("Program.Test: %v", err)
		}
		if ret != tcActShot {
			t.Fatalf("want TC_ACT_SHOT, got %s", fmtVerdict(ret))
		}
	})

	t.Run("non_syn_let_through", func(t *testing.T) {
		frame := buildTCFrame(srcIP, testAddr, 40102, 443, tcpACK)
		ret, _, err := prog.Test(frame)
		if err != nil {
			t.Fatalf("Program.Test: %v", err)
		}
		if ret != tcActOK {
			t.Fatalf("want TC_ACT_OK, got %s", fmtVerdict(ret))
		}
	})
}
