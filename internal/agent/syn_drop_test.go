// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package agent

import (
	"testing"

	"github.com/cilium/ebpf"
	"github.com/zyvorai/netra/internal/models"
)

func TestApplySynDropUnavailableWhenMapMissing(t *testing.T) {
	a := &Agent{collection: &ebpf.Collection{Maps: map[string]*ebpf.Map{}}}
	if err := a.applySynDrop([]models.EBPFSynDropEntry{{Address: "10.0.0.1", Direction: "egress"}}); err == nil {
		t.Fatal("expected an error for missing syndrop_v4/v6 maps")
	}
}

func TestApplySynDropCIDRUnavailableWhenMapMissing(t *testing.T) {
	a := &Agent{collection: &ebpf.Collection{Maps: map[string]*ebpf.Map{}}}
	if err := a.applySynDropCIDR([]models.EBPFSynDropCIDR{{CIDR: "10.0.0.0/24", Direction: "egress"}}); err == nil {
		t.Fatal("expected an error for missing syndrop_cidr_v4/v6 maps")
	}
}
