// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

// Package sslprobe observes application-protocol metadata for TLS traffic by
// attaching uprobes to OpenSSL's SSL_write and SSL_read (bpf/netra_ssl.c).
//
// This is the one place Netra sees plaintext: the bytes an application hands to
// SSL_write before they are encrypted, and the bytes SSL_read returns after they
// are decrypted. It is strictly opt-in, and what leaves the agent is exactly what
// the packet-level sampler exports (internal/l7sample): an operation name and a
// coarse outcome from allowlists, never a path, query string, header, cookie,
// token or body. docs/tls-plaintext.md is the honest account of what that means.
package sslprobe

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/zyvorai/netra/internal/l7sample"
)

// CopyMax, headerLen and EventSize mirror struct ssl_event in bpf/netra_ssl.c
// (packed): 8+8+8+8 + 1+3 + 2+2 + 16 = 56 header bytes, then the payload.
const (
	CopyMax   = 128
	headerLen = 56
	EventSize = headerLen + CopyMax
)

// Event is one decoded kernel event: a plaintext fragment and who handled it.
type Event struct {
	TSNS     uint64
	PID, TID uint32
	CgroupID uint64
	SSL      uint64 // the SSL* value: identifies the connection within the process
	Write    bool   // true: handed to SSL_write; false: returned by SSL_read
	Comm     string
	Data     []byte // a view into the record buffer
}

// ErrShortEvent is returned for a record smaller than the fixed layout.
var ErrShortEvent = errors.New("sslprobe: short event")

// DecodeEvent decodes a ring-buffer record. Data is a view into b.
func DecodeEvent(b []byte) (Event, error) {
	if len(b) < EventSize {
		return Event{}, ErrShortEvent
	}
	n := int(binary.LittleEndian.Uint16(b[36:38]))
	if n <= 0 || n > CopyMax {
		return Event{}, errors.New("sslprobe: bad payload length")
	}
	pt := binary.LittleEndian.Uint64(b[8:16])
	comm := b[40:56]
	end := 0
	for end < len(comm) && comm[end] != 0 {
		end++
	}
	return Event{
		TSNS:     binary.LittleEndian.Uint64(b[0:8]),
		PID:      uint32(pt >> 32),
		TID:      uint32(pt),
		CgroupID: binary.LittleEndian.Uint64(b[16:24]),
		SSL:      binary.LittleEndian.Uint64(b[24:32]),
		Write:    b[32] == 0,
		Comm:     string(comm[:end]),
		Data:     b[headerLen : headerLen+n],
	}, nil
}

// Layout mirrors struct ssl_layout in bpf/netra_ssl.c: byte offsets of the
// argument and return registers within the saved struct pt_regs (five uint16, then
// valid and a pad byte: 12 bytes).
type Layout struct {
	Arg1, Arg2, Arg3, Arg4, Ret uint16
	Valid, Pad                  uint8
}

// LayoutFor returns the register offsets for a GOARCH. The kernel's pt_regs
// layout is part of its ABI, so these are constants of the architecture:
//
//	amd64: r15,r14,r13,r12,rbp,rbx,r11,r10,r9,r8,rax,rcx,rdx,rsi,rdi,... (8 bytes
//	       each) so rdi=112 (arg1), rsi=104, rdx=96, rcx=88 (arg4), rax=80 (return);
//	arm64: struct user_pt_regs { u64 regs[31]; ... } so x0..x3 = 0,8,16,24 and the
//	       return value is x0.
func LayoutFor(goarch string) (Layout, error) {
	switch goarch {
	case "amd64":
		return Layout{Arg1: 112, Arg2: 104, Arg3: 96, Arg4: 88, Ret: 80, Valid: 1}, nil
	case "arm64":
		return Layout{Arg1: 0, Arg2: 8, Arg3: 16, Arg4: 24, Ret: 0, Valid: 1}, nil
	}
	return Layout{}, fmt.Errorf("unsupported architecture %q (amd64 and arm64)", goarch)
}

// Classify turns one plaintext fragment into a bounded observation and the role
// this process played. HTTP/1 and HTTP/2 (including gRPC) are recognised; what a
// fragment classifies as decides the role: a process that writes a request or
// reads a response is a client ("issued"); one that reads a request or writes a
// response is a server ("served"). Unrecognised plaintext is not counted.
func Classify(write bool, data []byte) (l7sample.Obs, string, bool) {
	o, ok := l7sample.Parse(l7sample.ProtoHTTP1, write, data)
	if !ok {
		if o, ok = l7sample.Parse(l7sample.ProtoHTTP2, true, data); !ok {
			o, ok = l7sample.Parse(l7sample.ProtoHTTP2, false, data)
		}
	}
	if !ok {
		return l7sample.Obs{}, "", false
	}
	role := l7sample.RoleServed
	if (write && o.Kind == l7sample.KindRequest) || (!write && o.Kind == l7sample.KindResponse) {
		role = l7sample.RoleIssued
	}
	return o, role, true
}
