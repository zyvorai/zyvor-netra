// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package afcapture

import (
	"encoding/binary"

	"golang.org/x/net/bpf"

	"github.com/zyvorai/netra/internal/capture"
)

// Family/protocol byte values, matching bpf/netra_capture.c's own
// #defines exactly (CAP_FAMILY_V4/V6) and the raw IP protocol numbers
// buildCaptureSpecValue already writes into SpecValue.Protocol.
const (
	familyV4 = 4
	familyV6 = 6

	ipprotoTCP = 6
	ipprotoUDP = 17

	etherTypeIPv4 = 0x0800
	etherTypeIPv6 = 0x86dd
)

// compileFilter hand-assembles a classic-BPF (cBPF) program implementing
// the same filter semantics as bpf/netra_capture.c's spec_matches(): family
// and protocol are each independently optional (0 = any); host and port
// are each matched against source OR destination (mirroring addr_matches'
// OR logic); an unset (all-zero) host or port field is a wildcard. This is
// a from-scratch reimplementation for a userspace socket filter, not a
// wrapper around the eBPF program — cBPF long predates eBPF and is a
// completely different (much simpler, kernel-hardened-but-far-less-
// rigorously-verified) instruction set; see docs/capture.md for why no
// bpf/*.c changes were needed for this feature.
//
// v1 scoping note: like bpf/netra_capture.c's own parse_headers, this does
// not walk IPv6 extension headers — a packet with extension headers before
// its L4 header will not have its port matched (protocol/host still match
// off the fixed IPv6 header, since nexthdr/addresses don't require walking
// extension headers). Matches the existing eBPF path's behavior exactly,
// not a new limitation introduced here.
//
// A disabled spec (Enabled == 0) compiles to "reject everything" as
// defense-in-depth alongside internal/api/capture.go's own "at least one
// of protocol/host/port is required" validation — a filter this permissive
// should never actually be assembled in practice, but must never
// accidentally mean "capture everything" if it somehow is.
func compileFilter(spec capture.SpecValue) ([]bpf.RawInstruction, error) {
	if spec.Enabled == 0 {
		return bpf.Assemble([]bpf.Instruction{bpf.RetConstant{Val: 0}})
	}

	b := newAsm()
	reject := b.newLabel()
	accept := b.newLabel()
	ipv4 := b.newLabel()
	ipv6 := b.newLabel()

	// --- EtherType dispatch (offset 12, 2 bytes) ---
	b.emit(bpf.LoadAbsolute{Off: 12, Size: 2})
	b.jumpIfTo(bpf.JumpEqual, etherTypeIPv4, ipv4, fallthroughLabel)
	b.jumpIfTo(bpf.JumpEqual, etherTypeIPv6, ipv6, fallthroughLabel)
	b.jumpTo(reject) // anything else (ARP, etc.) never matches, same as parse_headers returning 0

	// --- IPv4 block ---
	b.mark(ipv4)
	if spec.Family == familyV6 {
		b.jumpTo(reject)
	}
	b.emit(bpf.LoadAbsolute{Off: 23, Size: 1}) // ip->protocol
	if spec.Protocol != 0 {
		b.jumpIfTo(bpf.JumpEqual, uint32(spec.Protocol), fallthroughLabel, reject)
	}
	if hostSetV4(spec.Host) {
		want := binary.BigEndian.Uint32(spec.Host[:4])
		hostOK := b.newLabel()
		b.emit(bpf.LoadAbsolute{Off: 26, Size: 4}) // src addr
		b.jumpIfTo(bpf.JumpEqual, want, hostOK, fallthroughLabel)
		b.emit(bpf.LoadAbsolute{Off: 30, Size: 4}) // dst addr
		b.jumpIfTo(bpf.JumpEqual, want, hostOK, reject)
		b.mark(hostOK)
	}
	if spec.Port != 0 {
		isTCPUDP := b.newLabel()
		b.emit(bpf.LoadAbsolute{Off: 23, Size: 1})
		b.jumpIfTo(bpf.JumpEqual, ipprotoTCP, isTCPUDP, fallthroughLabel)
		b.jumpIfTo(bpf.JumpEqual, ipprotoUDP, isTCPUDP, reject)
		b.mark(isTCPUDP)
		b.emit(bpf.LoadMemShift{Off: 14}) // X = IP header length (ip->ihl * 4)
		portOK := b.newLabel()
		b.emit(bpf.LoadIndirect{Off: 14, Size: 2}) // src port, at [14+X : 16+X]
		b.jumpIfTo(bpf.JumpEqual, uint32(spec.Port), portOK, fallthroughLabel)
		b.emit(bpf.LoadIndirect{Off: 16, Size: 2}) // dst port
		b.jumpIfTo(bpf.JumpEqual, uint32(spec.Port), portOK, reject)
		b.mark(portOK)
	}
	b.jumpTo(accept)

	// --- IPv6 block --- (fixed 40-byte header, no extension-header walk — see doc comment above)
	b.mark(ipv6)
	if spec.Family == familyV4 {
		b.jumpTo(reject)
	}
	b.emit(bpf.LoadAbsolute{Off: 20, Size: 1}) // ip6->nexthdr
	if spec.Protocol != 0 {
		b.jumpIfTo(bpf.JumpEqual, uint32(spec.Protocol), fallthroughLabel, reject)
	}
	if hostSetV6(spec.Host) {
		hostOK6 := b.newLabel()
		dstCheck := b.newLabel()
		emitWordChain(b, spec.Host, 22, hostOK6, dstCheck) // src: 22,26,30,34
		b.mark(dstCheck)
		emitWordChain(b, spec.Host, 38, hostOK6, reject) // dst: 38,42,46,50
		b.mark(hostOK6)
	}
	if spec.Port != 0 {
		isTCPUDP6 := b.newLabel()
		b.emit(bpf.LoadAbsolute{Off: 20, Size: 1})
		b.jumpIfTo(bpf.JumpEqual, ipprotoTCP, isTCPUDP6, fallthroughLabel)
		b.jumpIfTo(bpf.JumpEqual, ipprotoUDP, isTCPUDP6, reject)
		b.mark(isTCPUDP6)
		portOK6 := b.newLabel()
		b.emit(bpf.LoadAbsolute{Off: 54, Size: 2}) // src port (fixed offset: 14 eth + 40 ipv6)
		b.jumpIfTo(bpf.JumpEqual, uint32(spec.Port), portOK6, fallthroughLabel)
		b.emit(bpf.LoadAbsolute{Off: 56, Size: 2}) // dst port
		b.jumpIfTo(bpf.JumpEqual, uint32(spec.Port), portOK6, reject)
		b.mark(portOK6)
	}
	b.jumpTo(accept)

	// --- terminals ---
	b.mark(reject)
	b.emit(bpf.RetConstant{Val: 0})
	b.mark(accept)
	snap := uint32(spec.SnapLen)
	if snap == 0 {
		snap = 0xffff // full frame; internal/afcapture's own read loop applies the real MaxCapLen-equivalent bound
	}
	b.emit(bpf.RetConstant{Val: snap})

	insts, err := b.assemble()
	if err != nil {
		return nil, err
	}
	return bpf.Assemble(insts)
}

// emitWordChain emits a 4-word (16-byte) AND-chain starting at byte offset
// off comparing against spec.Host[0:16]: all four 32-bit words must match
// for the chain to jump to onMatch; any mismatch jumps to onMismatch. Used
// once for the source address and once for the destination address to
// build addr_matches' OR-of-two-AND-chains semantics.
func emitWordChain(b *asmBuilder, host [16]byte, off uint32, onMatch, onMismatch label) {
	for i := range 4 {
		want := binary.BigEndian.Uint32(host[i*4 : i*4+4])
		b.emit(bpf.LoadAbsolute{Off: off + uint32(i*4), Size: 4})
		if i < 3 {
			b.jumpIfTo(bpf.JumpEqual, want, fallthroughLabel, onMismatch)
		} else {
			b.jumpIfTo(bpf.JumpEqual, want, onMatch, onMismatch)
		}
	}
}

func hostSetV4(h [16]byte) bool {
	for _, b := range h[:4] {
		if b != 0 {
			return true
		}
	}
	return false
}

func hostSetV6(h [16]byte) bool {
	for _, b := range h {
		if b != 0 {
			return true
		}
	}
	return false
}
