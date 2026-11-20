// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

// Package tcpevents loads and reads bpf/netra_tcpevents.c: TCP retransmit, RST
// and state-transition counters taken from four kernel tracepoints. The kernel
// side aggregates; this package supplies each tracepoint's record layout (from
// the running kernel's own format files), attaches the programs, and turns the
// maps back into a Snapshot.
package tcpevents

import (
	"errors"
	"fmt"

	"github.com/zyvorai/netra/internal/tpformat"
)

// Absent is the offset meaning "this field does not exist on this kernel"
// (bpf/netra_tcpevents.c: TPL_ABSENT).
const Absent = 0xFFFF

// Layout mirrors struct tp_layout in bpf/netra_tcpevents.c byte for byte
// (twelve uint16 offsets, then valid and a pad byte: 26 bytes, no padding).
//
// A flow tracepoint uses one of two record shapes. Classic (Linux 6.8): Sport,
// Dport, Family, Saddr, Daddr, Saddr6, Daddr6, with SaSrc/SaDst Absent. Sockaddr
// (tcp_send_reset on newer kernels, seen on 6.17): SaSrc/SaDst locate a pair of
// 28-byte struct sockaddr_in6-sized blobs and every classic field is Absent.
type Layout struct {
	Sport, Dport, Family uint16
	Saddr, Daddr         uint16
	Saddr6, Daddr6       uint16
	OldState, NewState   uint16
	Protocol             uint16
	SaSrc, SaDst         uint16
	Valid, Pad           uint8
}

// sockaddrSize is sizeof(struct sockaddr_in6), the size of the address blobs a
// sockaddr-style record carries.
const sockaddrSize = 28

// Tracepoint identifies one of the four sensors.
type Tracepoint struct {
	Name    string // agent-facing name
	Group   string // tracefs group
	Event   string // tracefs event
	Program string // program name in the object
	Var     string // .rodata variable holding its Layout
	state   bool   // inet_sock_set_state rather than a flow tracepoint
}

// Tracepoints are the four sensors, in attach order.
var Tracepoints = []Tracepoint{
	{Name: "retransmit", Group: "tcp", Event: "tcp_retransmit_skb", Program: "netra_tp_retransmit", Var: "L_retrans"},
	{Name: "send_reset", Group: "tcp", Event: "tcp_send_reset", Program: "netra_tp_send_reset", Var: "L_send_reset"},
	{Name: "receive_reset", Group: "tcp", Event: "tcp_receive_reset", Program: "netra_tp_receive_reset", Var: "L_recv_reset"},
	{Name: "state", Group: "sock", Event: "inet_sock_set_state", Program: "netra_tp_state", Var: "L_set_state", state: true},
}

// LayoutFor derives a tracepoint's Layout from its parsed format. It fails,
// rather than guess, when a field the program must read is missing or has an
// unexpected size: a wrong offset would produce plausible-looking garbage.
//
// IPv4 fields are required (classic shape), or a matching pair of 28-byte
// sockaddr blobs (sockaddr shape). IPv6 arrays, and the protocol field of
// inet_sock_set_state, are optional and marked Absent when the kernel lacks
// them (the program then counts such events as unreadable instead of misreading).
func LayoutFor(tp Tracepoint, f *tpformat.Format) (Layout, error) {
	l := Layout{
		Sport: Absent, Dport: Absent, Family: Absent, Saddr: Absent, Daddr: Absent,
		Saddr6: Absent, Daddr6: Absent, OldState: Absent, NewState: Absent, Protocol: Absent,
		SaSrc: Absent, SaDst: Absent,
	}
	set := func(dst *uint16, name string, size int, required bool) error {
		off, err := f.Offset(name, size)
		if err != nil {
			if required {
				return err
			}
			if f.Has(name) { // present but the wrong size: never guess
				return err
			}
			return nil
		}
		if off >= Absent {
			return fmt.Errorf("tracepoint %q field %q offset %d does not fit", f.Name, name, off)
		}
		*dst = uint16(off)
		return nil
	}
	var errs []error
	if tp.state {
		errs = append(errs,
			set(&l.OldState, "oldstate", 4, true),
			set(&l.NewState, "newstate", 4, true),
			set(&l.Protocol, "protocol", 2, false),
		)
	} else if sa, ok := f.Fields["saddr"]; ok && sa.Size == sockaddrSize && !f.Has("sport") {
		// Sockaddr-style record: the blobs carry family, port and address.
		errs = append(errs,
			set(&l.SaSrc, "saddr", sockaddrSize, true),
			set(&l.SaDst, "daddr", sockaddrSize, true),
		)
	} else {
		errs = append(errs,
			set(&l.Sport, "sport", 2, true),
			set(&l.Dport, "dport", 2, true),
			set(&l.Family, "family", 2, true),
			set(&l.Saddr, "saddr", 4, true),
			set(&l.Daddr, "daddr", 4, true),
			set(&l.Saddr6, "saddr_v6", 16, false),
			set(&l.Daddr6, "daddr_v6", 16, false),
		)
	}
	if err := errors.Join(errs...); err != nil {
		return Layout{}, err
	}
	l.Valid = 1
	return l, nil
}

// TCP state numbers as reported by inet_sock_set_state (include/net/tcp_states.h).
var stateNames = map[uint8]string{
	1: "ESTABLISHED", 2: "SYN_SENT", 3: "SYN_RECV", 4: "FIN_WAIT1", 5: "FIN_WAIT2",
	6: "TIME_WAIT", 7: "CLOSE", 8: "CLOSE_WAIT", 9: "LAST_ACK", 10: "LISTEN",
	11: "CLOSING", 12: "NEW_SYN_RECV", 13: "BOUND_INACTIVE",
}

// StateName names a TCP state number.
func StateName(n uint8) string {
	if s, ok := stateNames[n]; ok {
		return s
	}
	return fmt.Sprintf("STATE_%d", n)
}

// Transition is a count of sockets moving From one TCP state To another.
type Transition struct {
	From  string `json:"from"`
	To    string `json:"to"`
	Count uint64 `json:"count"`
}

// Flow is one TCP tuple's retransmit and reset counts.
type Flow struct {
	Family      string `json:"family"` // ipv4 or ipv6
	Src         string `json:"src"`
	Dst         string `json:"dst"`
	SrcPort     uint16 `json:"srcPort"`
	DstPort     uint16 `json:"dstPort"`
	Retransmits uint64 `json:"retransmits,omitempty"`
	RSTSent     uint64 `json:"rstSent,omitempty"`
	RSTReceived uint64 `json:"rstReceived,omitempty"`
	LastSeenNS  uint64 `json:"lastSeenNs,omitempty"`
}

// Totals are the node-wide counters, including the sensor's own health.
type Totals struct {
	Retransmits      uint64 `json:"retransmits"`
	RSTSent          uint64 `json:"rstSent"`
	RSTReceived      uint64 `json:"rstReceived"`
	StateTransitions uint64 `json:"stateTransitions"`
	// ReadErrors counts records the program could not read; BadFamily counts
	// records of neither IPv4 nor IPv6; MapFull counts flows it could not
	// insert. Non-zero values mean the numbers above are an undercount.
	ReadErrors uint64 `json:"readErrors,omitempty"`
	BadFamily  uint64 `json:"badFamily,omitempty"`
	MapFull    uint64 `json:"mapFull,omitempty"`
}

// Snapshot is one node's cumulative TCP event state.
type Snapshot struct {
	Attached    []string          `json:"attached"`
	Skipped     map[string]string `json:"skipped,omitempty"`
	Totals      Totals            `json:"totals"`
	Transitions []Transition      `json:"transitions,omitempty"`
	Flows       []Flow            `json:"flows,omitempty"`
}
