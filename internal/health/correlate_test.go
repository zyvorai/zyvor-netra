// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package health

import (
	"testing"

	"github.com/zyvorai/netra/internal/models"
)

func TestWorkloadKeyStripsRemoteSuffix(t *testing.T) {
	if got := workloadKey("payments/api-1 → 10.0.0.8:443"); got != "payments/api-1" {
		t.Fatalf("got %q", got)
	}
	if got := workloadKey("payments/api-1 → db.internal:53"); got != "payments/api-1" {
		t.Fatalf("got %q", got)
	}
	if got := workloadKey("node-1"); got != "node-1" {
		t.Fatalf("got %q", got)
	}
}

func TestCorrelateAnomaliesGroupsAcrossDifferentRemotes(t *testing.T) {
	in := []models.NetworkHealthAnomaly{
		{Severity: "warning", Kind: "dns-failure", Subject: "payments/api-1 → db.internal:53", Value: 3},
		{Severity: "critical", Kind: "tcp-retransmit", Subject: "payments/api-1 → 10.0.0.8:443", Value: 22},
	}
	out := correlateAnomalies(in)
	if len(out) != 3 {
		t.Fatalf("expected 2 originals + 1 composite, got %d: %+v", len(out), out)
	}
	composite := out[2]
	if composite.Kind != "correlated-degradation" || composite.Subject != "payments/api-1" || composite.Severity != "critical" {
		t.Fatalf("unexpected composite: %+v", composite)
	}
	if len(composite.RelatedKinds) != 2 || composite.RelatedKinds[0] != "dns-failure" || composite.RelatedKinds[1] != "tcp-retransmit" {
		t.Fatalf("unexpected related kinds: %+v", composite.RelatedKinds)
	}
}

func TestCorrelateAnomaliesIgnoresSingleKindSubjects(t *testing.T) {
	in := []models.NetworkHealthAnomaly{
		{Severity: "warning", Kind: "tcp-latency", Subject: "payments/api-1 → 10.0.0.8:443"},
		{Severity: "warning", Kind: "tcp-latency", Subject: "payments/api-1 → 10.0.0.9:443"},
	}
	out := correlateAnomalies(in)
	if len(out) != 2 {
		t.Fatalf("same kind repeated should not produce a composite: %+v", out)
	}
}

func TestCorrelateAnomaliesGroupsNodeLevelFindings(t *testing.T) {
	in := []models.NetworkHealthAnomaly{
		{Severity: "warning", Kind: "bpf-maps-missing", Subject: "node-1"},
		{Severity: "warning", Kind: "icmp-echo", Subject: "node-1"},
	}
	out := correlateAnomalies(in)
	if len(out) != 3 || out[2].Subject != "node-1" || out[2].Kind != "correlated-degradation" {
		t.Fatalf("expected node-level composite: %+v", out)
	}
}

func TestBuildEmitsCorrelatedDegradation(t *testing.T) {
	a := models.AgentStatus{AgentReport: models.AgentReport{
		Node:        "node-1",
		MissingMaps: []string{"allowed_ports"},
		ICMPTypes:   []models.NamedCount{{Name: "echo-request", Count: 20000}},
	}}
	r := Build([]models.AgentStatus{a}, 10)
	var found bool
	for _, an := range r.Summary.Anomalies {
		if an.Kind == "correlated-degradation" && an.Subject == "node-1" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected a correlated-degradation anomaly: %+v", r.Summary.Anomalies)
	}
}
