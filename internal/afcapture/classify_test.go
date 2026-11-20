// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package afcapture

import "testing"

func TestClassify(t *testing.T) {
	t.Run("ipv4 tcp", func(t *testing.T) {
		pkt := buildIPv4TCP(t, "10.0.0.1", "10.0.0.2", 1234, 443, ipprotoTCP)
		family, proto := classify(pkt)
		if family != familyV4 || proto != ipprotoTCP {
			t.Errorf("got family=%d proto=%d, want family=%d proto=%d", family, proto, familyV4, ipprotoTCP)
		}
	})
	t.Run("ipv6 udp", func(t *testing.T) {
		pkt := buildIPv6TCP(t, "fd00::1", "fd00::2", 1234, 443, ipprotoUDP)
		family, proto := classify(pkt)
		if family != familyV6 || proto != ipprotoUDP {
			t.Errorf("got family=%d proto=%d, want family=%d proto=%d", family, proto, familyV6, ipprotoUDP)
		}
	})
	t.Run("too short", func(t *testing.T) {
		family, proto := classify([]byte{1, 2, 3})
		if family != 0 || proto != 0 {
			t.Errorf("expected zero values for a too-short frame, got family=%d proto=%d", family, proto)
		}
	})
	t.Run("non-ip ethertype", func(t *testing.T) {
		arp := make([]byte, 14+28)
		arp[12], arp[13] = 0x08, 0x06
		family, proto := classify(arp)
		if family != 0 || proto != 0 {
			t.Errorf("expected zero values for ARP, got family=%d proto=%d", family, proto)
		}
	})
}
