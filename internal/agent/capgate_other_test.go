//go:build !linux

// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package agent

import (
	"testing"

	"github.com/cilium/ebpf"
	"github.com/zyvorai/netra/internal/models"
)

// TestApplyCapabilityGateNoopOnNonLinux guards the non-Linux stub's
// contract: it must never error, even with a missing map and a non-empty
// deny list — internal/procmeta is Linux-only, so there is nothing this
// platform can do but no-op, matching readProcessMeta's own stub.
func TestApplyCapabilityGateNoopOnNonLinux(t *testing.T) {
	a := &Agent{collection: &ebpf.Collection{Maps: map[string]*ebpf.Map{}}}
	if err := a.applyCapabilityGate(models.EBPFFastPathConfig{DeniedCapabilities: []string{"CAP_NET_RAW"}}); err != nil {
		t.Fatalf("expected the non-Linux stub to no-op, got %v", err)
	}
}
