// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package agent

import (
	"testing"

	"github.com/cilium/ebpf"
	"github.com/zyvorai/netra/internal/models"
)

func TestReplaceByteRatesUnavailableWhenMapMissing(t *testing.T) {
	a := &Agent{collection: &ebpf.Collection{Maps: map[string]*ebpf.Map{}}}
	if err := a.replaceByteRates([]models.EBPFRateLimit{{Destination: "10.0.0.1", BPS: 1000}}); err == nil {
		t.Fatal("expected an error for a missing rate_bps_v4 map")
	}
}

func TestReadByteRateDropsUnavailableWhenMapMissing(t *testing.T) {
	a := &Agent{collection: &ebpf.Collection{Maps: map[string]*ebpf.Map{}}}
	rows, err := a.readByteRateDrops()
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 0 {
		t.Fatalf("expected no rows when both maps are missing, got %v", rows)
	}
}
