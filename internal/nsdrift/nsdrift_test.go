// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package nsdrift

import (
	"testing"
	"time"

	"github.com/zyvorai/netra/internal/models"
)

func TestBuildNamespaceChangeIsWarning(t *testing.T) {
	resp := Build([]models.AgentStatus{{AgentReport: models.AgentReport{Node: "n1", NamespaceChanges: []models.NamespaceChangeEvent{
		{PID: 100, Comm: "curl", Namespace: "prod", Pod: "api-1", PreviousNetNS: 4026531840, CurrentNetNS: 4026532000},
	}}}}, 10)
	if len(resp.Events) != 1 {
		t.Fatalf("expected 1 event, got %+v", resp.Events)
	}
	found := false
	for _, a := range resp.Anomalies {
		if a.Kind == "nsdrift-netns-changed" {
			found = true
			if a.Severity != "warning" || a.Subject != "prod/api-1" {
				t.Fatalf("unexpected anomaly: %+v", a)
			}
		}
	}
	if !found {
		t.Fatalf("expected nsdrift-netns-changed anomaly, got %+v", resp.Anomalies)
	}
}

func TestBuildCoverageGapOnRecentRestart(t *testing.T) {
	now := time.Now()
	resp := Build([]models.AgentStatus{{AgentReport: models.AgentReport{
		Node: "n1", AgentStartedAt: now.Add(-30 * time.Second), ObservedAt: now,
	}}}, 10)
	found := false
	for _, a := range resp.Anomalies {
		if a.Kind == "nsdrift-coverage-gap" {
			found = true
			if a.Subject != "n1" {
				t.Fatalf("unexpected subject: %+v", a)
			}
		}
	}
	if !found {
		t.Fatalf("expected a nsdrift-coverage-gap anomaly for a recently-restarted agent, got %+v", resp.Anomalies)
	}
}

func TestBuildNoCoverageGapWhenAgentHasBeenUpAWhile(t *testing.T) {
	now := time.Now()
	resp := Build([]models.AgentStatus{{AgentReport: models.AgentReport{
		Node: "n1", AgentStartedAt: now.Add(-1 * time.Hour), ObservedAt: now,
	}}}, 10)
	for _, a := range resp.Anomalies {
		if a.Kind == "nsdrift-coverage-gap" {
			t.Fatalf("unexpected coverage-gap anomaly for a long-lived agent: %+v", a)
		}
	}
}

func TestBuildSkipsStaleAgents(t *testing.T) {
	resp := Build([]models.AgentStatus{{Stale: true, AgentReport: models.AgentReport{Node: "n1", NamespaceChanges: []models.NamespaceChangeEvent{
		{PID: 1, PreviousNetNS: 1, CurrentNetNS: 2},
	}}}}, 10)
	if len(resp.Events) != 0 || len(resp.Anomalies) != 0 {
		t.Fatalf("expected a stale agent's events/anomalies to be skipped, got %+v", resp)
	}
}

func TestBuildTopNTruncates(t *testing.T) {
	var changes []models.NamespaceChangeEvent
	for i := 0; i < 5; i++ {
		changes = append(changes, models.NamespaceChangeEvent{PID: uint32(i + 1), PreviousNetNS: 1, CurrentNetNS: uint64(i + 2)})
	}
	resp := Build([]models.AgentStatus{{AgentReport: models.AgentReport{Node: "n1", NamespaceChanges: changes}}}, 2)
	if len(resp.Events) != 2 {
		t.Fatalf("expected topN=2 events, got %d", len(resp.Events))
	}
}
