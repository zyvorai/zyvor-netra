// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package tlsfp

import (
	"encoding/binary"
)

// ExtractClientHello finds a TLS ClientHello record inside a single
// Ethernet (or raw IP) frame. No stream reassembly — the hello must fit
// in one skb/frame, matching Netra's L7 metadata boundary.
func ExtractClientHello(frame []byte) []byte {
	if len(frame) < 14 {
		return nil
	}
	off := 0
	// Ethernet II
	if len(frame) >= 14 {
		etype := binary.BigEndian.Uint16(frame[12:14])
		off = 14
		if etype == 0x8100 && len(frame) >= 18 { // 802.1Q
			etype = binary.BigEndian.Uint16(frame[16:18])
			off = 18
		}
		// Do not return on a miss: a raw IP packet whose source address
		// bytes 12-13 look like an ethertype (8.0.x.x, 134.221.x.x) must
		// still reach the raw-IP fallback below.
		var out []byte
		switch etype {
		case 0x0800: // IPv4
			out = extractFromIPv4(frame[off:])
		case 0x86dd: // IPv6
			out = extractFromIPv6(frame[off:])
		}
		if out != nil {
			return out
		}
	}
	// Raw IP fallback (no Ethernet)
	if frame[0]>>4 == 4 {
		return extractFromIPv4(frame)
	}
	if frame[0]>>4 == 6 {
		return extractFromIPv6(frame)
	}
	return nil
}

func extractFromIPv4(pkt []byte) []byte {
	if len(pkt) < 20 {
		return nil
	}
	ihl := int(pkt[0]&0x0f) * 4
	if ihl < 20 || len(pkt) < ihl {
		return nil
	}
	if pkt[9] != 6 { // TCP
		return nil
	}
	return extractFromTCP(pkt[ihl:])
}

func extractFromIPv6(pkt []byte) []byte {
	if len(pkt) < 40 {
		return nil
	}
	if pkt[6] != 6 { // next header TCP (no ext-hdr walk — single-skb best-effort)
		return nil
	}
	return extractFromTCP(pkt[40:])
}

func extractFromTCP(seg []byte) []byte {
	if len(seg) < 20 {
		return nil
	}
	dataOff := int(seg[12]>>4) * 4
	if dataOff < 20 || len(seg) < dataOff {
		return nil
	}
	payload := seg[dataOff:]
	if len(payload) < 6 || payload[0] != recordTypeHandshake {
		return nil
	}
	return payload
}
