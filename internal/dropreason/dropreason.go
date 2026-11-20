// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

// Package dropreason gives a best-effort human-readable name to the raw
// SKB_DROP_REASON_* enum values netra_kfree_skb (bpf/netra_tc.c) captures
// from the kernel's kfree_skb raw tracepoint.
//
// The enum is not a stable kernel ABI — its numeric values have shifted and
// grown across releases since it was introduced (5.17+, see
// include/net/dropreason-core.h upstream). This table is seeded from the
// low-numbered, longstanding values shared across recent LTS kernels
// (5.15 through 6.x) and is deliberately not exhaustive: unknown values
// fall back to a numeric label rather than guessing.
package dropreason

import "fmt"

var names = map[uint32]string{
	0:  "not-specified",
	2:  "no-socket",
	3:  "pkt-too-small",
	4:  "tcp-csum",
	5:  "socket-filter",
	6:  "udp-csum",
	7:  "netfilter-drop",
	8:  "otherhost",
	9:  "ip-csum",
	10: "ip-inhdr",
	11: "ip-rpfilter",
	12: "unicast-in-l2-multicast",
	13: "xfrm-policy",
	14: "ip-noproto",
	15: "socket-rcvbuff",
	16: "proto-mem",
	17: "tcp-md5-notfound",
	18: "tcp-md5-unexpected",
	19: "tcp-md5-failure",
	20: "socket-backlog",
	21: "tcp-flags",
	22: "tcp-zerowindow",
	23: "tcp-old-data",
	24: "tcp-overwindow",
	25: "tcp-ofomerge",
	26: "tcp-rfc7323-paws",
	27: "tcp-old-ack",
	28: "tcp-too-old-ack",
	29: "tcp-ack-unsent-data",
	30: "tcp-offset-out-of-range",
	31: "tcp-closed",
	32: "tcp-fastopen",
	33: "tcp-min-ttl",
	34: "ip-outnoroutes",
	35: "ip-tunnel-over-limit",
	36: "no-route",
	37: "ip-tunnel-error",
	38: "unhandled-proto",
	39: "empty-skb",
	40: "csum-complete-check",
	41: "no-write-space",
	42: "no-buffer-space",
	43: "no-mem",
	44: "duplicate-fragment",
	45: "fragment-reassembly-timeout",
	46: "fragment-too-large",
	47: "invalid-fragment",
	48: "queue-purge",
	49: "tap-filter",
	50: "tap-txfilter",
	51: "icmp-csum",
	52: "invalid-proto",
	53: "ip-invalid-source",
	54: "ip-invalid-dest",
	55: "pkt-too-big",
	56: "duplicate-segment",
}

// Name returns the best-effort mainline-kernel name for a raw
// skb_drop_reason enum value, e.g. "no-socket", "netfilter-drop". Falls
// back to "reason #<n>" for values not in the table, since the enum shifts
// across kernel versions and this table is not exhaustive.
func Name(reason uint32) string {
	if n, ok := names[reason]; ok {
		return n
	}
	return fmt.Sprintf("reason #%d", reason)
}
