// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package insights

import (
	"testing"
	"time"

	"github.com/zyvorai/netra/internal/models"
)

func downgradeFixtureAgent(tlsHandshakes, httpRequests uint64) []models.AgentStatus {
	return []models.AgentStatus{{AgentReport: models.AgentReport{
		TLSMetadata:  []models.TLSMetadataStat{{Namespace: "prod", Pod: "api-1", WorkloadKind: "Deployment", WorkloadName: "api", SNI: "svc.example.com", Handshakes: tlsHandshakes}},
		HTTPMetadata: []models.HTTPMetadataStat{{Namespace: "prod", Pod: "api-1", WorkloadKind: "Deployment", WorkloadName: "api", Host: "svc.example.com", Method: "GET", Requests: httpRequests}},
	}}}
}

func capturedBaselineWithTLSOnly() models.BehaviorBaseline {
	baseAgents := []models.AgentStatus{{AgentReport: models.AgentReport{
		TLSMetadata: []models.TLSMetadataStat{{Namespace: "prod", Pod: "api-1", WorkloadKind: "Deployment", WorkloadName: "api", SNI: "svc.example.com", Handshakes: 5}},
	}}}
	return CaptureBaseline(baseAgents, time.Unix(1000, 0))
}

func TestProtocolDowngradesWarningWhenTLSStopped(t *testing.T) {
	b := capturedBaselineWithTLSOnly()
	agents := downgradeFixtureAgent(0, 4) // no current TLS, cleartext HTTP present
	out := ProtocolDowngrades(b, agents)
	if len(out.Findings) != 1 {
		t.Fatalf("findings=%d, want 1: %#v", len(out.Findings), out.Findings)
	}
	f := out.Findings[0]
	if f.Severity != "warning" || f.TLSStillActive {
		t.Fatalf("finding=%#v, want warning/tlsStillActive=false", f)
	}
}

func TestProtocolDowngradesInfoWhenTLSStillActive(t *testing.T) {
	b := capturedBaselineWithTLSOnly()
	agents := downgradeFixtureAgent(3, 4) // TLS still active concurrently
	out := ProtocolDowngrades(b, agents)
	if len(out.Findings) != 1 {
		t.Fatalf("findings=%d, want 1", len(out.Findings))
	}
	f := out.Findings[0]
	if f.Severity != "info" || !f.TLSStillActive {
		t.Fatalf("finding=%#v, want info/tlsStillActive=true", f)
	}
}

func TestProtocolDowngradesNeverSuppressesInfoFindings(t *testing.T) {
	// The weaker (info) signal must still be surfaced, never dropped —
	// this project's non-suppression convention.
	b := capturedBaselineWithTLSOnly()
	agents := downgradeFixtureAgent(1, 1)
	out := ProtocolDowngrades(b, agents)
	if len(out.Findings) != 1 {
		t.Fatalf("info-severity finding must still be present, got %d findings", len(out.Findings))
	}
}

func TestProtocolDowngradesNoBaselineNoFindings(t *testing.T) {
	agents := downgradeFixtureAgent(0, 4)
	out := ProtocolDowngrades(models.BehaviorBaseline{}, agents)
	if len(out.Findings) != 0 {
		t.Fatalf("findings=%d, want 0 with no captured baseline", len(out.Findings))
	}
}

func TestProtocolDowngradesExcludesNodeScopedSource(t *testing.T) {
	b := CaptureBaseline([]models.AgentStatus{{AgentReport: models.AgentReport{
		TLSMetadata: []models.TLSMetadataStat{{SNI: "svc.example.com", Handshakes: 5}}, // no ns/pod/cgroup -> source "node"
	}}}, time.Unix(1000, 0))
	agents := []models.AgentStatus{{AgentReport: models.AgentReport{
		HTTPMetadata: []models.HTTPMetadataStat{{Host: "svc.example.com", Method: "GET", Requests: 4}},
	}}}
	out := ProtocolDowngrades(b, agents)
	if len(out.Findings) != 0 {
		t.Fatalf("expected node-scoped sources to be excluded, got %#v", out.Findings)
	}
}

func TestProtocolDowngradesHostNotInBaselineIsNotFlagged(t *testing.T) {
	b := capturedBaselineWithTLSOnly()
	agents := []models.AgentStatus{{AgentReport: models.AgentReport{
		HTTPMetadata: []models.HTTPMetadataStat{{Namespace: "prod", Pod: "api-1", WorkloadKind: "Deployment", WorkloadName: "api", Host: "unrelated.example.com", Method: "GET", Requests: 4}},
	}}}
	out := ProtocolDowngrades(b, agents)
	if len(out.Findings) != 0 {
		t.Fatalf("a host with no baseline TLS history must not be flagged, got %#v", out.Findings)
	}
}

func TestProtocolDowngradesSurfacesL7Degraded(t *testing.T) {
	b := capturedBaselineWithTLSOnly()
	agents := downgradeFixtureAgent(0, 4)
	agents[0].Node = "node-1"
	agents[0].Programs = []models.BPFProgramStat{{Name: "netra_l7_cgroup_ingress", Attached: true}} // egress missing
	out := ProtocolDowngrades(b, agents)
	if !out.L7Degraded || len(out.L7DegradedNodes) != 1 || out.L7DegradedNodes[0] != "node-1" {
		t.Fatalf("l7Degraded=%v nodes=%v, want true/[node-1]", out.L7Degraded, out.L7DegradedNodes)
	}
}
