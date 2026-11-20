//go:build linux

// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package agent

import (
	"testing"

	"github.com/cilium/ebpf"
	"github.com/zyvorai/netra/internal/models"
)

// TestApplyCapabilityGateUnavailableWhenMapMissing runs only on Linux
// (this package's other tests run everywhere; procmeta itself is
// Linux-only) — CI covers it even though it can't be run on a non-Linux
// development machine.
func TestApplyCapabilityGateUnavailableWhenMapMissing(t *testing.T) {
	a := &Agent{collection: &ebpf.Collection{Maps: map[string]*ebpf.Map{}}}
	if err := a.applyCapabilityGate(models.EBPFFastPathConfig{DeniedCapabilities: []string{"CAP_NET_RAW"}}); err == nil {
		t.Fatal("expected an error for a missing capgate_pids map")
	}
}
