// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

// Package dropinfo loads and reads bpf/netra_dropinfo.c: per-connection
// attribution of kernel packet drops (5-tuple, reason, and the kernel code that
// dropped it) from the skb:kfree_skb tracepoint.
//
// The kernel side aggregates. This package supplies the tracepoint's record
// layout (from the running kernel's format file), attaches the program, and
// turns the maps back into a Snapshot with reason names taken from the same
// kernel and locations resolved through kallsyms.
package dropinfo

import (
	"errors"
	"fmt"

	"github.com/zyvorai/netra/internal/tpformat"
)

// Absent is the offset meaning "this field does not exist on this kernel"
// (bpf/netra_dropinfo.c: TPL_ABSENT).
const Absent = 0xFFFF

// Layout mirrors struct dropinfo_layout in bpf/netra_dropinfo.c byte for byte
// (four uint16 offsets, valid and a pad byte: 10 bytes, no padding).
type Layout struct {
	SkbAddr, Location, Protocol, Reason uint16
	Valid, Pad                          uint8
}

// Tracepoint is the one event the sensor attaches to.
const (
	TPGroup = "skb"
	TPEvent = "kfree_skb"
)

// LayoutFor derives the Layout from the parsed skb:kfree_skb format.
//
// skbaddr (8 bytes) and protocol (2 bytes) are required: without the skb pointer
// there is nothing to read, and without the ethertype the program cannot tell
// an IP packet from one whose header was never set. location and reason are
// optional (older kernels lack reason): they are marked Absent and the program
// records 0 for them.
func LayoutFor(f *tpformat.Format) (Layout, error) {
	l := Layout{Location: Absent, Reason: Absent}
	var err error
	off := func(name string, size int) (uint16, error) {
		o, err := f.Offset(name, size)
		if err != nil {
			return 0, err
		}
		return uint16(o), nil
	}
	if l.SkbAddr, err = off("skbaddr", 8); err != nil {
		return Layout{}, err
	}
	if l.Protocol, err = off("protocol", 2); err != nil {
		return Layout{}, err
	}
	if o, err := off("location", 8); err == nil {
		l.Location = o
	}
	if o, err := off("reason", 4); err == nil {
		l.Reason = o
	}
	l.Valid = 1
	return l, nil
}

// ReasonNames returns the value→name table the running kernel's own print fmt
// gives for the drop reason. Numbering changes between kernels, so this is the
// only correct source. Nil when the kernel gives none (pre-5.17).
func ReasonNames(f *tpformat.Format) map[int]string {
	return f.Symbols("reason")
}

// ReasonName names a reason value, falling back to a stable placeholder.
func ReasonName(names map[int]string, reason uint32) string {
	if n, ok := names[int(reason)]; ok {
		return n
	}
	if reason == 0 && names == nil {
		return "unknown"
	}
	return fmt.Sprintf("reason_%d", reason)
}

// Flow is one (tuple, reason) that was dropped.
type Flow struct {
	Family     string `json:"family"` // ipv4, ipv6, or "" when the packet had no readable IP header
	Proto      string `json:"proto,omitempty"`
	Src        string `json:"src,omitempty"`
	Dst        string `json:"dst,omitempty"`
	SrcPort    uint16 `json:"srcPort,omitempty"`
	DstPort    uint16 `json:"dstPort,omitempty"`
	Reason     string `json:"reason"`
	Count      uint64 `json:"count"`
	Location   string `json:"location,omitempty"` // kernel function that last dropped it
	LastSeenNS uint64 `json:"lastSeenNs,omitempty"`
}

// Site is one (reason, dropping function) with its count.
type Site struct {
	Reason   string `json:"reason"`
	Location string `json:"location"`
	Count    uint64 `json:"count"`
}

// Totals are the kernel-side counters.
type Totals struct {
	Drops     uint64 `json:"drops"`
	WithTuple uint64 `json:"withTuple"`
	NoTuple   uint64 `json:"noTuple,omitempty"`    // not IP, or the headers disagreed
	NoHeader  uint64 `json:"noHeader,omitempty"`   // network header not set when dropped
	ReadError uint64 `json:"readErrors,omitempty"` // a kernel read failed; counts undercount
	MapFull   uint64 `json:"mapFull,omitempty"`
}

// Snapshot is the cumulative state since the sensor attached.
type Snapshot struct {
	Attached bool
	Totals   Totals
	Reasons  map[string]uint64 // total drops per reason name
	Sites    []Site
	Flows    []Flow
}

var errClosed = errors.New("drop info sensor is closed")
