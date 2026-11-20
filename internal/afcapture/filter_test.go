// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package afcapture

import (
	"encoding/binary"
	"net"
	"testing"

	"golang.org/x/net/bpf"

	"github.com/zyvorai/netra/internal/capture"
)

// runFilter compiles spec and runs the resulting cBPF program against pkt
// via golang.org/x/net/bpf's pure-Go VM interpreter — no live kernel
// needed. Returns the number of bytes the filter says to keep (0 = drop).
func runFilter(t *testing.T, spec capture.SpecValue, pkt []byte) int {
	t.Helper()
	raw, err := compileFilter(spec)
	if err != nil {
		t.Fatalf("compileFilter: %v", err)
	}
	// bpf.NewVM type-switches on the concrete Instruction implementations
	// (Jump, JumpIf, RetConstant, ...), which RawInstruction itself isn't —
	// Disassemble recovers the typed form the VM actually understands.
	insts, allDecoded := bpf.Disassemble(raw)
	if !allDecoded {
		t.Fatalf("compileFilter produced a RawInstruction the disassembler couldn't decode: %+v", insts)
	}
	vm, err := bpf.NewVM(insts)
	if err != nil {
		t.Fatalf("bpf.NewVM: %v", err)
	}
	n, err := vm.Run(pkt)
	if err != nil {
		t.Fatalf("vm.Run: %v", err)
	}
	return n
}

// buildIPv4TCP builds a minimal Ethernet+IPv4(no options)+TCP frame with
// the given addresses/ports, enough bytes for the filter's own field
// reads (payload is a few filler bytes, not a real TCP header beyond the
// port fields the filter actually inspects).
func buildIPv4TCP(t *testing.T, src, dst string, sport, dport uint16, proto uint8) []byte {
	t.Helper()
	buf := make([]byte, 14+20+8)
	binary.BigEndian.PutUint16(buf[12:14], etherTypeIPv4)
	buf[14] = 0x45 // version 4, IHL 5 (20-byte header, no options)
	buf[14+9] = proto
	copy(buf[14+12:14+16], net.ParseIP(src).To4())
	copy(buf[14+16:14+20], net.ParseIP(dst).To4())
	binary.BigEndian.PutUint16(buf[14+20:14+22], sport)
	binary.BigEndian.PutUint16(buf[14+22:14+24], dport)
	return buf
}

func buildIPv6TCP(t *testing.T, src, dst string, sport, dport uint16, nexthdr uint8) []byte {
	t.Helper()
	buf := make([]byte, 14+40+8)
	binary.BigEndian.PutUint16(buf[12:14], etherTypeIPv6)
	buf[14+6] = nexthdr
	copy(buf[14+8:14+24], net.ParseIP(src).To16())
	copy(buf[14+24:14+40], net.ParseIP(dst).To16())
	binary.BigEndian.PutUint16(buf[14+40:14+42], sport)
	binary.BigEndian.PutUint16(buf[14+42:14+44], dport)
	return buf
}

func hostV4(spec *capture.SpecValue, ip string) {
	spec.Family = familyV4
	copy(spec.Host[:4], net.ParseIP(ip).To4())
}

func hostV6(spec *capture.SpecValue, ip string) {
	spec.Family = familyV6
	copy(spec.Host[:], net.ParseIP(ip).To16())
}

func TestCompileFilter_DisabledRejectsEverything(t *testing.T) {
	pkt := buildIPv4TCP(t, "10.0.0.1", "10.0.0.2", 1234, 443, ipprotoTCP)
	n := runFilter(t, capture.SpecValue{Enabled: 0, Protocol: ipprotoTCP}, pkt)
	if n != 0 {
		t.Errorf("disabled spec should reject everything, got n=%d", n)
	}
}

func TestCompileFilter_ProtocolOnly(t *testing.T) {
	spec := capture.SpecValue{Enabled: 1, Protocol: ipprotoTCP}
	tcpPkt := buildIPv4TCP(t, "10.0.0.1", "10.0.0.2", 1234, 443, ipprotoTCP)
	udpPkt := buildIPv4TCP(t, "10.0.0.1", "10.0.0.2", 1234, 443, ipprotoUDP)
	if n := runFilter(t, spec, tcpPkt); n == 0 {
		t.Error("expected TCP packet to match protocol=tcp filter")
	}
	if n := runFilter(t, spec, udpPkt); n != 0 {
		t.Error("expected UDP packet to be rejected by protocol=tcp filter")
	}
}

func TestCompileFilter_HostMatchesSrcOrDst(t *testing.T) {
	spec := capture.SpecValue{Enabled: 1}
	hostV4(&spec, "10.0.0.2")

	asSrc := buildIPv4TCP(t, "10.0.0.2", "10.0.0.9", 1234, 443, ipprotoTCP)
	asDst := buildIPv4TCP(t, "10.0.0.9", "10.0.0.2", 1234, 443, ipprotoTCP)
	neither := buildIPv4TCP(t, "10.0.0.5", "10.0.0.9", 1234, 443, ipprotoTCP)

	if n := runFilter(t, spec, asSrc); n == 0 {
		t.Error("expected match when host is the source address")
	}
	if n := runFilter(t, spec, asDst); n == 0 {
		t.Error("expected match when host is the destination address")
	}
	if n := runFilter(t, spec, neither); n != 0 {
		t.Error("expected no match when host is neither src nor dst")
	}
}

func TestCompileFilter_PortMatchesSrcOrDst(t *testing.T) {
	spec := capture.SpecValue{Enabled: 1, Port: 443}
	asSport := buildIPv4TCP(t, "10.0.0.1", "10.0.0.2", 443, 5000, ipprotoTCP)
	asDport := buildIPv4TCP(t, "10.0.0.1", "10.0.0.2", 5000, 443, ipprotoTCP)
	neither := buildIPv4TCP(t, "10.0.0.1", "10.0.0.2", 5000, 5001, ipprotoTCP)

	if n := runFilter(t, spec, asSport); n == 0 {
		t.Error("expected match when port is the source port")
	}
	if n := runFilter(t, spec, asDport); n == 0 {
		t.Error("expected match when port is the destination port")
	}
	if n := runFilter(t, spec, neither); n != 0 {
		t.Error("expected no match when neither port matches")
	}
}

func TestCompileFilter_PortFilterRejectsNonTCPUDP(t *testing.T) {
	spec := capture.SpecValue{Enabled: 1, Port: 443}
	icmpPkt := buildIPv4TCP(t, "10.0.0.1", "10.0.0.2", 443, 443, 1) // proto=ICMP, "port" bytes are garbage payload
	if n := runFilter(t, spec, icmpPkt); n != 0 {
		t.Error("a port filter should never match a non-TCP/UDP packet, even with coincidentally-matching bytes")
	}
}

func TestCompileFilter_FamilyRestrictsToV4OrV6(t *testing.T) {
	v4Spec := capture.SpecValue{Enabled: 1, Family: familyV4}
	v6Spec := capture.SpecValue{Enabled: 1, Family: familyV6}
	v4Pkt := buildIPv4TCP(t, "10.0.0.1", "10.0.0.2", 1234, 443, ipprotoTCP)
	v6Pkt := buildIPv6TCP(t, "fd00::1", "fd00::2", 1234, 443, ipprotoTCP)

	if n := runFilter(t, v4Spec, v4Pkt); n == 0 {
		t.Error("family=v4 filter should match a v4 packet")
	}
	if n := runFilter(t, v4Spec, v6Pkt); n != 0 {
		t.Error("family=v4 filter should reject a v6 packet")
	}
	if n := runFilter(t, v6Spec, v6Pkt); n == 0 {
		t.Error("family=v6 filter should match a v6 packet")
	}
	if n := runFilter(t, v6Spec, v4Pkt); n != 0 {
		t.Error("family=v6 filter should reject a v4 packet")
	}
}

func TestCompileFilter_IPv6HostAndPort(t *testing.T) {
	spec := capture.SpecValue{Enabled: 1, Port: 8080}
	hostV6(&spec, "fd00::2")

	match := buildIPv6TCP(t, "fd00::1", "fd00::2", 1234, 8080, ipprotoTCP)
	wrongHost := buildIPv6TCP(t, "fd00::1", "fd00::9", 1234, 8080, ipprotoTCP)
	wrongPort := buildIPv6TCP(t, "fd00::1", "fd00::2", 1234, 9090, ipprotoTCP)

	if n := runFilter(t, spec, match); n == 0 {
		t.Error("expected match on host+port for v6")
	}
	if n := runFilter(t, spec, wrongHost); n != 0 {
		t.Error("expected no match: wrong v6 host")
	}
	if n := runFilter(t, spec, wrongPort); n != 0 {
		t.Error("expected no match: wrong v6 port")
	}
}

func TestCompileFilter_ArpNeverMatches(t *testing.T) {
	spec := capture.SpecValue{Enabled: 1, Protocol: ipprotoTCP}
	arp := make([]byte, 14+28)
	binary.BigEndian.PutUint16(arp[12:14], 0x0806) // ETH_P_ARP
	if n := runFilter(t, spec, arp); n != 0 {
		t.Error("a non-IP EtherType should never match")
	}
}

func TestCompileFilter_SnapLenBoundsReturnValue(t *testing.T) {
	spec := capture.SpecValue{Enabled: 1, Protocol: ipprotoTCP, SnapLen: 40}
	pkt := buildIPv4TCP(t, "10.0.0.1", "10.0.0.2", 1234, 443, ipprotoTCP)
	n := runFilter(t, spec, pkt)
	if n != 40 {
		t.Errorf("expected the filter's return value to equal SnapLen=40, got %d", n)
	}
}
