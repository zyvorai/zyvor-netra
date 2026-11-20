// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package netlinkwatch

import (
	"fmt"
	"net"
	"strings"
)

// Address families and neighbor cache states as the kernel numbers them. They
// are restated here (not imported from the netlink library) so the helpers
// build and are tested on every OS.
const (
	familyV4 = 2
	familyV6 = 10

	nudIncomplete = 0x01
	nudReachable  = 0x02
	nudStale      = 0x04
	nudDelay      = 0x08
	nudProbe      = 0x10
	nudFailed     = 0x20
	nudNoARP      = 0x40
	nudPermanent  = 0x80
)

func familyName(f int) string {
	switch f {
	case familyV4:
		return "ipv4"
	case familyV6:
		return "ipv6"
	default:
		return fmt.Sprintf("family-%d", f)
	}
}

// familyOfIPs names the family from the first address present. Route updates
// do not always carry a family, but their destination or gateway does.
func familyOfIPs(ips ...net.IP) string {
	for _, ip := range ips {
		if ip == nil {
			continue
		}
		if ip.To4() != nil {
			return "ipv4"
		}
		if ip.To16() != nil {
			return "ipv6"
		}
	}
	return ""
}

func routeDestination(dst *net.IPNet) string {
	if dst == nil {
		return "default"
	}
	return dst.String()
}

func ipString(ip net.IP) string {
	if len(ip) == 0 {
		return ""
	}
	return ip.String()
}

func ipNetString(n *net.IPNet) string {
	if n == nil {
		return ""
	}
	return n.String()
}

func hardwareString(hw net.HardwareAddr) string {
	if len(hw) == 0 {
		return ""
	}
	return hw.String()
}

// neighborState names every set NUD bit, so a combined state reads the way
// `ip neigh` shows it.
func neighborState(state int) string {
	if state == 0 {
		return "none"
	}
	names := []struct {
		bit  int
		name string
	}{
		{nudIncomplete, "incomplete"}, {nudReachable, "reachable"}, {nudStale, "stale"},
		{nudDelay, "delay"}, {nudProbe, "probe"}, {nudFailed, "failed"},
		{nudNoARP, "noarp"}, {nudPermanent, "permanent"},
	}
	var out []string
	for _, n := range names {
		if state&n.bit != 0 {
			out = append(out, n.name)
		}
	}
	if len(out) == 0 {
		return fmt.Sprintf("state-%d", state)
	}
	return strings.Join(out, ",")
}
