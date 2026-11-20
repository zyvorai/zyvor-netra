// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

// Package rtnlactor says which process asked for a network change.
//
// The netlink recorder (internal/netlinkwatch) hears every link, address, route
// and neighbor change over RTNL multicast, but a multicast notification does not
// name its requester. bpf/netra_rtnl.c is an fentry on rtnetlink_rcv_msg, which
// runs in the requesting task, and emits one Record per request that modifies
// state: the process's comm, pid and cgroup, and the RTM_* message type. This
// package loads it, decodes its records and (in join.go) joins them to recorded
// changes.
//
// Only the comm (the 16-byte process name), ids and cgroup are captured: no argv,
// no environment, no message payload. The sensor only observes.
package rtnlactor

import (
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"time"
)

// EventSize is the size of the kernel's struct rtnl_event (bpf/netra_rtnl.c).
const EventSize = 96

// NLMFCreate is NLM_F_CREATE: the request creates an object rather than operating
// on an existing one.
const NLMFCreate = 0x400

// Address families as a route request carries them (rtm_family).
const (
	afInet  = 2
	afInet6 = 10
)

// RTM_* message types the program records, restated from linux/rtnetlink.h.
const (
	RTMNewLink  = 16
	RTMDelLink  = 17
	RTMSetLink  = 19
	RTMNewAddr  = 20
	RTMDelAddr  = 21
	RTMNewRoute = 24
	RTMDelRoute = 25
	RTMNewNeigh = 28
	RTMDelNeigh = 29
)

// Record is one request that modifies network state.
type Record struct {
	// TS is the kernel's monotonic timestamp; Wall is the same instant as wall
	// clock time, derived when the record was read.
	TS   uint64
	Wall time.Time
	// CgroupID is the requester's cgroup, the id the agent maps to a workload.
	CgroupID uint64
	// TGID is the process id and PID the thread id.
	TGID, PID uint32
	// Type is the RTM_* message type.
	Type uint16
	// Flags is the message's nlmsg_flags; NLMFCreate marks a create.
	Flags uint16
	// IfIndex is the interface the request names by index: the fixed field of a link,
	// address or neighbor request, or a route's RTA_OIF. 0 when it names none by
	// index (a route may be multipath, and modern `ip link set dev X` names the device
	// only by name).
	IfIndex uint32
	// Len is the whole message's length. A link request of 32 bytes (the netlink
	// header and the ifinfomsg, no attributes) with no index names no device at all:
	// iproute2 sends one at the start of every `ip link` command to probe whether the
	// kernel supports RTM_NEWLINK, and it changes nothing.
	Len uint32
	// NetNS is the inode of the network namespace the request applies to; 0 when the
	// kernel program could not read it. Interface indexes are per namespace, so a
	// request only explains a change in the same one.
	NetNS uint32
	// IfName is the device a link request names by IFLA_IFNAME when it gives no
	// index; empty otherwise. For a create it is the new link's name, which says
	// nothing about a peer created with it.
	IfName string
	// Dest is a route request's destination in the form the recorder uses for the
	// change it causes ("10.91.0.0/24", "2001:db8::/32", "default"); empty for every
	// other kind of request. Two processes adding routes on one interface in the same
	// instant are told apart by it.
	Dest string
	// Comm is the process name (at most 15 characters, as the kernel keeps it).
	Comm string
}

// Parse decodes one struct rtnl_event (little endian, 48 bytes).
func Parse(b []byte) (Record, error) {
	if len(b) < EventSize {
		return Record{}, fmt.Errorf("rtnl event is %d bytes, want %d", len(b), EventSize)
	}
	le := binary.LittleEndian
	return Record{
		TS:       le.Uint64(b[0:8]),
		CgroupID: le.Uint64(b[8:16]),
		TGID:     le.Uint32(b[16:20]),
		PID:      le.Uint32(b[20:24]),
		Type:     le.Uint16(b[24:26]),
		Flags:    le.Uint16(b[26:28]),
		IfIndex:  le.Uint32(b[28:32]),
		Len:      le.Uint32(b[36:40]),
		Comm:     comm(b[40:56]),
		Dest:     routeDest(le.Uint16(b[24:26]), b[32], b[33], b[56:72]),
		IfName:   comm(b[72:88]),
		NetNS:    le.Uint32(b[88:92]),
	}, nil
}

// routeDest formats a route request's destination like netlinkwatch does for the
// recorded change: a CIDR, or "default" for a prefix length of 0.
func routeDest(typ uint16, family, dstLen uint8, dst []byte) string {
	if typ != RTMNewRoute && typ != RTMDelRoute {
		return ""
	}
	if dstLen == 0 {
		return "default"
	}
	var ip net.IP
	var bits int
	switch family {
	case afInet:
		ip, bits = net.IP(dst[:4]), 32
	case afInet6:
		ip, bits = net.IP(dst[:16]), 128
	default:
		return ""
	}
	if int(dstLen) > bits {
		return ""
	}
	return (&net.IPNet{IP: ip, Mask: net.CIDRMask(int(dstLen), bits)}).String()
}

// comm reads a NUL-terminated kernel task name.
func comm(b []byte) string {
	if i := strings.IndexByte(string(b), 0); i >= 0 {
		b = b[:i]
	}
	return string(b)
}

// TypeName is the RTM_* name of a recorded message type.
func TypeName(t uint16) string {
	switch t {
	case RTMNewLink:
		return "RTM_NEWLINK"
	case RTMDelLink:
		return "RTM_DELLINK"
	case RTMSetLink:
		return "RTM_SETLINK"
	case RTMNewAddr:
		return "RTM_NEWADDR"
	case RTMDelAddr:
		return "RTM_DELADDR"
	case RTMNewRoute:
		return "RTM_NEWROUTE"
	case RTMDelRoute:
		return "RTM_DELROUTE"
	case RTMNewNeigh:
		return "RTM_NEWNEIGH"
	case RTMDelNeigh:
		return "RTM_DELNEIGH"
	}
	return fmt.Sprintf("RTM_%d", t)
}
