// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package l7sample

import (
	"encoding/binary"
	"errors"
	"net"
)

// EventSize and CopyMax mirror struct l7s_event and L7S_COPY in
// bpf/netra_l7sample.c. The struct is packed: 8+8+4+2+2+16+16+2+2 = 60 header
// bytes, then the payload.
const (
	CopyMax   = 128
	headerLen = 60
	EventSize = headerLen + CopyMax
)

// Sample is one decoded kernel event: a payload fragment and where it flowed.
type Sample struct {
	TSNS     uint64
	CgroupID uint64
	Egress   bool // false: ingress, relative to this host
	Proto    Protocol
	ToServer bool // the destination port is the service port: a request direction
	SrcPort  uint16
	DstPort  uint16
	Src, Dst net.IP
	Data     []byte // the copied payload, a view into the event buffer
}

// ErrShortEvent is returned for an event smaller than the fixed layout.
var ErrShortEvent = errors.New("l7sample: short event")

// DecodeEvent decodes a ring-buffer record. The payload is a view into b; a
// caller that keeps it must copy it.
func DecodeEvent(b []byte) (Sample, error) {
	if len(b) < EventSize {
		return Sample{}, ErrShortEvent
	}
	n := int(binary.LittleEndian.Uint16(b[56:58]))
	if n <= 0 || n > CopyMax {
		return Sample{}, errors.New("l7sample: bad payload length")
	}
	s := Sample{
		TSNS:     binary.LittleEndian.Uint64(b[0:8]),
		CgroupID: binary.LittleEndian.Uint64(b[8:16]),
		Egress:   b[17] == 0,
		Proto:    Protocol(b[18]),
		ToServer: b[19] == 1,
		SrcPort:  binary.LittleEndian.Uint16(b[20:22]),
		DstPort:  binary.LittleEndian.Uint16(b[22:24]),
		Data:     b[headerLen : headerLen+n],
	}
	switch b[16] {
	case 4:
		s.Src, s.Dst = net.IP(append([]byte(nil), b[24:28]...)), net.IP(append([]byte(nil), b[40:44]...))
	case 6:
		s.Src, s.Dst = net.IP(append([]byte(nil), b[24:40]...)), net.IP(append([]byte(nil), b[40:56]...))
	default:
		return Sample{}, errors.New("l7sample: bad address family")
	}
	return s, nil
}
