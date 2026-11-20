// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

// Package nodeiso loads bpf/netra_nodeiso.c, the node-scoped allow-only
// egress filter, and reconciles a models.NodeIsolationSpec into its maps.
// See docs/node-isolation.md.
package nodeiso

import (
	"fmt"
	"net/netip"
	"sort"

	"github.com/zyvorai/netra/internal/models"
)

// MaxRules mirrors NODEISO_MAX_RULES: 64 operator rules plus agent-added ones.
const MaxRules = 80

// Modes, mirroring NODEISO_MODE_*.
const (
	ModeOff     uint32 = 0
	ModeShadow  uint32 = 1
	ModeEnforce uint32 = 2
)

// Stat slots, mirroring NODEISO_STAT_*.
const (
	statAllowed = iota
	statWouldBlock
	statBlocked
	statExempt
	statWouldBlockBytes
	statBlockedBytes
	statSlots
)

const (
	afInet  = 4
	afInet6 = 6
	ipTCP   = 6
	ipUDP   = 17
)

// The structs below mirror the C ABI byte for byte (see the _Static_asserts).
type config struct {
	Generation uint32
	Mode       uint32
	RuleCount  uint32
	_          uint32
}

type ruleKey struct {
	Generation uint32
	Index      uint32
}

type rule struct {
	Family    uint8
	Protocol  uint8
	PrefixLen uint8
	_         uint8
	PortStart uint16
	PortEnd   uint16
	Address   [16]byte
}

type exemptKey struct {
	Generation uint32
	Protocol   uint8
	_          uint8
	Port       uint16
}

type destKey struct {
	Family   uint8
	Protocol uint8
	Port     uint16
	Address  [16]byte
}

type destValue struct {
	Packets uint64
	Bytes   uint64
}

// ModeFor maps a spec mode to the kernel mode, demoting enforce to shadow
// when demoted is non-empty.
func ModeFor(spec *models.NodeIsolationSpec, demoted string) uint32 {
	switch {
	case spec == nil:
		return ModeOff
	case spec.Mode == models.NodeIsolationEnforce && demoted == "":
		return ModeEnforce
	default:
		return ModeShadow
	}
}

func protocolNumber(p string) (uint8, error) {
	switch p {
	case "", "any":
		return 0, nil
	case "tcp":
		return ipTCP, nil
	case "udp":
		return ipUDP, nil
	}
	return 0, fmt.Errorf("unsupported protocol %q", p)
}

func protocolName(n uint8) string {
	switch n {
	case ipTCP:
		return "tcp"
	case ipUDP:
		return "udp"
	case 1:
		return "icmp"
	case 58:
		return "icmpv6"
	}
	return fmt.Sprintf("ip-%d", n)
}

// encodeRule turns one API rule into the kernel layout.
func encodeRule(r models.NodeIsolationRule) (rule, error) {
	p, err := netip.ParsePrefix(r.CIDR)
	if err != nil {
		return rule{}, fmt.Errorf("cidr %q: %w", r.CIDR, err)
	}
	p = p.Masked()
	proto, err := protocolNumber(r.Protocol)
	if err != nil {
		return rule{}, err
	}
	out := rule{Protocol: proto, PrefixLen: uint8(p.Bits()), PortStart: r.PortFrom, PortEnd: r.PortTo}
	if out.PortEnd == 0 {
		out.PortEnd = out.PortStart
	}
	if p.Addr().Is4() {
		out.Family = afInet
		a := p.Addr().As4()
		copy(out.Address[:], a[:])
	} else {
		out.Family = afInet6
		a := p.Addr().As16()
		copy(out.Address[:], a[:])
	}
	return out, nil
}

// compile produces the rule list (operator rules first, then implicit ones)
// and the exempt-port keys for one generation.
func compile(spec *models.NodeIsolationSpec, implicit []models.NodeIsolationRule, gen uint32) ([]rule, []exemptKey, error) {
	if spec == nil {
		return nil, nil, nil
	}
	all := append(append([]models.NodeIsolationRule(nil), spec.Rules...), implicit...)
	if len(all) > MaxRules {
		return nil, nil, fmt.Errorf("%d rules exceed the kernel limit of %d", len(all), MaxRules)
	}
	rules := make([]rule, 0, len(all))
	for _, r := range all {
		k, err := encodeRule(r)
		if err != nil {
			return nil, nil, err
		}
		rules = append(rules, k)
	}
	var exempt []exemptKey
	for _, port := range spec.ExemptLocalPorts {
		if port == 0 {
			continue
		}
		exempt = append(exempt, exemptKey{Generation: gen, Protocol: ipTCP, Port: port}, exemptKey{Generation: gen, Protocol: ipUDP, Port: port})
	}
	return rules, exempt, nil
}

// nextGeneration never returns 0, which the program reads as "no policy".
func nextGeneration(g uint32) uint32 {
	g++
	if g == 0 {
		g = 1
	}
	return g
}

func destAddress(k destKey) string {
	if k.Family == afInet {
		return netip.AddrFrom4([4]byte(k.Address[:4])).String()
	}
	return netip.AddrFrom16(k.Address).String()
}

// topDests orders destinations by bytes, then packets, and keeps n.
func topDests(in []models.NodeIsolationDest, n int) []models.NodeIsolationDest {
	sort.Slice(in, func(i, j int) bool {
		if in[i].Bytes != in[j].Bytes {
			return in[i].Bytes > in[j].Bytes
		}
		if in[i].Packets != in[j].Packets {
			return in[i].Packets > in[j].Packets
		}
		return in[i].Address < in[j].Address
	})
	if len(in) > n {
		in = in[:n]
	}
	return in
}
