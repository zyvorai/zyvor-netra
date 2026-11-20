// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package exehash

import (
	"testing"
	"time"

	"github.com/zyvorai/netra/internal/models"
)

func TestBuildExeHashChangeIsWarning(t *testing.T) {
	resp := Build([]models.AgentStatus{{AgentReport: models.AgentReport{Node: "n1", ExeHashChanges: []models.ExeHashChangeEvent{
		{PID: 100, Comm: "curl", Exe: "/usr/bin/curl", Namespace: "prod", Pod: "api-1", PreviousExeHash: "aaa", CurrentExeHash: "bbb"},
	}}}}, 10)
	if len(resp.Events) != 1 {
		t.Fatalf("expected 1 event, got %+v", resp.Events)
	}
	found := false
	for _, a := range resp.Anomalies {
		if a.Kind == "exehash-changed" {
			found = true
			if a.Severity != "warning" || a.Subject != "prod/api-1" {
				t.Fatalf("unexpected anomaly: %+v", a)
			}
		}
	}
	if !found {
		t.Fatalf("expected exehash-changed anomaly, got %+v", resp.Anomalies)
	}
}

func TestBuildCoverageGapOnRecentRestart(t *testing.T) {
	now := time.Now()
	resp := Build([]models.AgentStatus{{AgentReport: models.AgentReport{
		Node: "n1", AgentStartedAt: now.Add(-30 * time.Second), ObservedAt: now,
	}}}, 10)
	found := false
	for _, a := range resp.Anomalies {
		if a.Kind == "exehash-coverage-gap" {
			found = true
			if a.Subject != "n1" {
				t.Fatalf("unexpected subject: %+v", a)
			}
		}
	}
	if !found {
		t.Fatalf("expected an exehash-coverage-gap anomaly for a recently-restarted agent, got %+v", resp.Anomalies)
	}
}

func TestBuildNoCoverageGapWhenAgentHasBeenUpAWhile(t *testing.T) {
	now := time.Now()
	resp := Build([]models.AgentStatus{{AgentReport: models.AgentReport{
		Node: "n1", AgentStartedAt: now.Add(-1 * time.Hour), ObservedAt: now,
	}}}, 10)
	for _, a := range resp.Anomalies {
		if a.Kind == "exehash-coverage-gap" {
			t.Fatalf("unexpected coverage-gap anomaly for a long-lived agent: %+v", a)
		}
	}
}

func TestBuildSkipsStaleAgents(t *testing.T) {
	resp := Build([]models.AgentStatus{{Stale: true, AgentReport: models.AgentReport{Node: "n1", ExeHashChanges: []models.ExeHashChangeEvent{
		{PID: 1, PreviousExeHash: "a", CurrentExeHash: "b"},
	}}}}, 10)
	if len(resp.Events) != 0 || len(resp.Anomalies) != 0 {
		t.Fatalf("expected a stale agent's events/anomalies to be skipped, got %+v", resp)
	}
}

func TestBuildTopNTruncates(t *testing.T) {
	var changes []models.ExeHashChangeEvent
	for i := range 5 {
		changes = append(changes, models.ExeHashChangeEvent{PID: uint32(i + 1), PreviousExeHash: "a", CurrentExeHash: "b"})
	}
	resp := Build([]models.AgentStatus{{AgentReport: models.AgentReport{Node: "n1", ExeHashChanges: changes}}}, 2)
	if len(resp.Events) != 2 {
		t.Fatalf("expected topN=2 events, got %d", len(resp.Events))
	}
}
