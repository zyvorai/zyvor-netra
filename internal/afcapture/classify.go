// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package afcapture

import "encoding/binary"

// classify stamps Family/Protocol on a captured frame the same way
// bpf/netra_capture.c's parse_headers does, for the dashboard's rendering
// — it does not affect filtering (already done in-kernel by the time this
// runs), only the frame's own metadata fields. Portable (no Linux-specific
// code) so it's unit-testable without a real socket.
func classify(data []byte) (family, protocol uint8) {
	if len(data) < 14 {
		return 0, 0
	}
	switch binary.BigEndian.Uint16(data[12:14]) {
	case etherTypeIPv4:
		if len(data) < 14+10 {
			return familyV4, 0
		}
		return familyV4, data[14+9]
	case etherTypeIPv6:
		if len(data) < 14+7 {
			return familyV6, 0
		}
		return familyV6, data[14+6]
	default:
		return 0, 0
	}
}
