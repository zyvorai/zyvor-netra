// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package counterfactual

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"
)

// PolicyFromEmergencyDeny builds a non-lockdown Policy with a single
// Deny rule matching a proposed emergency deny (ip, cidr, port, dns, sni).
// Kind "process" is not representable against flow history and returns an error.
func PolicyFromEmergencyDeny(kind, value, direction, protocol string, port uint16) (*Policy, error) {
	kind = strings.ToLower(strings.TrimSpace(kind))
	value = strings.TrimSpace(value)
	direction = strings.ToLower(strings.TrimSpace(direction))
	protocol = strings.ToLower(strings.TrimSpace(protocol))
	if direction == "" {
		direction = "both"
	}
	switch direction {
	case "egress", "ingress", "both":
	default:
		return nil, fmt.Errorf("direction must be egress, ingress, or both")
	}
	if value == "" {
		return nil, fmt.Errorf("value is required")
	}
	var rule Rule
	rule.Direction = direction
	switch kind {
	case "ip":
		addr, err := netip.ParseAddr(value)
		if err != nil {
			return nil, fmt.Errorf("value is not an IP address")
		}
		bits := 32
		if addr.Is6() {
			bits = 128
		}
		rule.Kind = RuleCIDR
		rule.CIDRs = []string{netip.PrefixFrom(addr, bits).String()}
	case "cidr":
		if _, err := netip.ParsePrefix(value); err != nil {
			return nil, fmt.Errorf("value is not a CIDR prefix")
		}
		rule.Kind = RuleCIDR
		rule.CIDRs = []string{value}
	case "port":
		p := int(port)
		if p == 0 {
			n, err := strconv.Atoi(value)
			if err != nil || n <= 0 || n > 65535 {
				return nil, fmt.Errorf("port value must be a positive integer")
			}
			p = n
		}
		rule.Kind = RulePort
		rule.Port = p
		switch protocol {
		case "", "any":
			rule.Protocol = "any"
		case "tcp", "udp":
			rule.Protocol = protocol
		default:
			return nil, fmt.Errorf("invalid protocol %q", protocol)
		}
	case "dns":
		rule.Kind = RuleDNS
		rule.Names = []string{strings.ToLower(value)}
	case "sni":
		rule.Kind = RuleSNI
		rule.Names = []string{strings.ToLower(value)}
	case "process":
		return nil, fmt.Errorf("process deny preview against flow history is not supported; use live deny-preview")
	default:
		return nil, fmt.Errorf("kind must be ip, cidr, port, dns, or sni")
	}
	return &Policy{
		Name: "deny-preview-history:" + kind + ":" + value,
		Deny: []Rule{rule},
	}, nil
}
