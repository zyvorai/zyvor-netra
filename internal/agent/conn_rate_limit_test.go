// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package agent

import (
	"testing"

	"github.com/cilium/ebpf"
	"github.com/zyvorai/netra/internal/models"
)

func TestEffectiveConnRateLimitsMatchesSelector(t *testing.T) {
	byCgroup := map[uint64]models.WorkloadIdentity{
		1: {CgroupID: 1, Namespace: "payments", Pod: "api-1"},
		2: {CgroupID: 2, Namespace: "checkout", Pod: "worker-1"},
	}
	rules := []models.EBPFConnRateLimit{
		{Selector: models.EBPFWorkloadScope{Namespace: "payments"}, PerSecond: 50},
	}
	got := effectiveConnRateLimits(byCgroup, rules)
	if len(got) != 1 || got[1] != 50 {
		t.Fatalf("expected only cgroup 1 capped at 50, got %+v", got)
	}
	if _, ok := got[2]; ok {
		t.Fatalf("non-matching cgroup 2 should not appear: %+v", got)
	}
}

// TestEffectiveConnRateLimitsPicksStrictest guards the "caps, not quotas
// that sum" semantics: when two rules match the same cgroup, the lower
// PerSecond must win.
func TestEffectiveConnRateLimitsPicksStrictest(t *testing.T) {
	byCgroup := map[uint64]models.WorkloadIdentity{
		1: {CgroupID: 1, Namespace: "payments", Pod: "api-1", Labels: map[string]string{"tier": "hot"}},
	}
	rules := []models.EBPFConnRateLimit{
		{Selector: models.EBPFWorkloadScope{Namespace: "payments"}, PerSecond: 100},
		{Selector: models.EBPFWorkloadScope{Labels: map[string]string{"tier": "hot"}}, PerSecond: 20},
	}
	got := effectiveConnRateLimits(byCgroup, rules)
	if got[1] != 20 {
		t.Fatalf("expected the strictest cap (20) to win, got %+v", got)
	}
}

func TestEffectiveConnRateLimitsIgnoresZeroPerSecond(t *testing.T) {
	byCgroup := map[uint64]models.WorkloadIdentity{1: {CgroupID: 1, Namespace: "payments"}}
	rules := []models.EBPFConnRateLimit{{Selector: models.EBPFWorkloadScope{Namespace: "payments"}, PerSecond: 0}}
	got := effectiveConnRateLimits(byCgroup, rules)
	if len(got) != 0 {
		t.Fatalf("expected no entries for a zero-PerSecond rule, got %+v", got)
	}
}

func TestApplyConnRateLimitsUnavailableWhenMapMissing(t *testing.T) {
	a := &Agent{collection: &ebpf.Collection{Maps: map[string]*ebpf.Map{}}}
	if err := a.applyConnRateLimits(models.EBPFFastPathConfig{}); err == nil {
		t.Fatal("expected an error for a missing conn_rate_limits map")
	}
}

func TestReadConnRateDropsUnavailableWhenMapMissing(t *testing.T) {
	a := &Agent{collection: &ebpf.Collection{Maps: map[string]*ebpf.Map{}}}
	rows, err := a.readConnRateDrops()
	if err == nil || rows != nil {
		t.Fatalf("expected an error and nil rows for a missing map, got %v %v", rows, err)
	}
}
