// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package afcapture

import "testing"

// Available's real behavior is platform- and privilege-dependent (it needs
// CAP_NET_RAW on Linux, and is hardcoded false off Linux) — this just
// confirms the call never panics and returns a plain bool, the contract
// internal/agent's dispatch code relies on.
func TestAvailable_DoesNotPanic(t *testing.T) {
	_ = Available()
}
