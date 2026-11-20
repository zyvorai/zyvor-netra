// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package capdrift

import (
	"testing"
	"time"

	"github.com/zyvorai/netra/internal/models"
)

func TestBuildGainedCapabilityIsWarning(t *testing.T) {
	resp := Build([]models.AgentStatus{{AgentReport: models.AgentReport{Node: "n1", CapChanges: []models.CapChangeEvent{
		{PID: 100, Comm: "curl", Namespace: "prod", Pod: "api-1", PreviousCapEff: 0, CurrentCapEff: 1 << 12}, // gained CAP_NET_ADMIN
	}}}}, 10)
	if len(resp.Events) != 1 {
		t.Fatalf("expected 1 event, got %+v", resp.Events)
	}
	found := false
	for _, a := range resp.Anomalies {
		if a.Kind == "capdrift-gained" {
			found = true
			if a.Severity != "warning" || a.Subject != "prod/api-1" {
				t.Fatalf("unexpected anomaly: %+v", a)
			}
		}
	}
	if !found {
		t.Fatalf("expected capdrift-gained anomaly, got %+v", resp.Anomalies)
	}
}

func TestBuildLostCapabilityIsInfo(t *testing.T) {
	resp := Build([]models.AgentStatus{{AgentReport: models.AgentReport{Node: "n1", CapChanges: []models.CapChangeEvent{
		{PID: 200, Comm: "nginx", PreviousCapEff: 1 << 13, CurrentCapEff: 0}, // lost CAP_NET_RAW
	}}}}, 10)
	found := false
	for _, a := range resp.Anomalies {
		if a.Kind == "capdrift-lost" {
			found = true
			if a.Severity != "info" {
				t.Fatalf("expected info severity, got %+v", a)
			}
		}
		if a.Kind == "capdrift-gained" {
			t.Fatalf("did not expect a gained anomaly for a pure loss: %+v", a)
		}
	}
	if !found {
		t.Fatalf("expected capdrift-lost anomaly, got %+v", resp.Anomalies)
	}
}

func TestBuildOtherBitChangeIsUnnamed(t *testing.T) {
	// Bit 0 (CAP_CHOWN) is outside the tracked CAP_NET_ADMIN/CAP_NET_RAW pair.
	resp := Build([]models.AgentStatus{{AgentReport: models.AgentReport{Node: "n1", CapChanges: []models.CapChangeEvent{
		{PID: 300, PreviousCapEff: 0, CurrentCapEff: 1},
	}}}}, 10)
	if len(resp.Anomalies) != 1 || resp.Anomalies[0].Kind != "capdrift-other" {
		t.Fatalf("expected a single capdrift-other anomaly, got %+v", resp.Anomalies)
	}
}

func TestBuildCoverageGapOnRecentRestart(t *testing.T) {
	now := time.Now()
	resp := Build([]models.AgentStatus{{AgentReport: models.AgentReport{
		Node: "n1", AgentStartedAt: now.Add(-30 * time.Second), ObservedAt: now,
	}}}, 10)
	found := false
	for _, a := range resp.Anomalies {
		if a.Kind == "capdrift-coverage-gap" {
			found = true
			if a.Subject != "n1" {
				t.Fatalf("unexpected subject: %+v", a)
			}
		}
	}
	if !found {
		t.Fatalf("expected a capdrift-coverage-gap anomaly for a recently-restarted agent, got %+v", resp.Anomalies)
	}
}

func TestBuildNoCoverageGapWhenAgentHasBeenUpAWhile(t *testing.T) {
	now := time.Now()
	resp := Build([]models.AgentStatus{{AgentReport: models.AgentReport{
		Node: "n1", AgentStartedAt: now.Add(-1 * time.Hour), ObservedAt: now,
	}}}, 10)
	for _, a := range resp.Anomalies {
		if a.Kind == "capdrift-coverage-gap" {
			t.Fatalf("unexpected coverage-gap anomaly for a long-lived agent: %+v", a)
		}
	}
}

func TestBuildSkipsStaleAgents(t *testing.T) {
	resp := Build([]models.AgentStatus{{Stale: true, AgentReport: models.AgentReport{Node: "n1", CapChanges: []models.CapChangeEvent{
		{PID: 1, PreviousCapEff: 0, CurrentCapEff: 1 << 12},
	}}}}, 10)
	if len(resp.Events) != 0 || len(resp.Anomalies) != 0 {
		t.Fatalf("expected a stale agent's events/anomalies to be skipped, got %+v", resp)
	}
}

func TestBuildTopNTruncates(t *testing.T) {
	var changes []models.CapChangeEvent
	for i := 0; i < 5; i++ {
		changes = append(changes, models.CapChangeEvent{PID: uint32(i + 1), PreviousCapEff: 0, CurrentCapEff: 1 << 12})
	}
	resp := Build([]models.AgentStatus{{AgentReport: models.AgentReport{Node: "n1", CapChanges: changes}}}, 2)
	if len(resp.Events) != 2 {
		t.Fatalf("expected topN=2 events, got %d", len(resp.Events))
	}
}
