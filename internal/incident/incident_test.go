// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package incident

import (
	"testing"
	"time"

	"github.com/zyvorai/netra/internal/detective"
	"github.com/zyvorai/netra/internal/models"
)

func TestBuildJoinsHealthAndDriftBySameSourceKey(t *testing.T) {
	now := time.Now()
	health := []models.NetworkHealthAnomaly{{SourceKey: "workload:prod:deployment:api", Subject: "prod/api-1", Severity: "critical", Kind: "tcp-latency", Message: "high RTT"}}
	drift := []models.DriftFinding{{Source: "workload:prod:deployment:api", Severity: "warning", Message: "new destination"}}
	out := Build(health, drift, nil, nil, nil, models.DependencyGraph{}, nil, now)
	if len(out) != 1 {
		t.Fatalf("clusters=%d, want 1", len(out))
	}
	if out[0].SourceKey != "workload:prod:deployment:api" || out[0].Severity != "critical" {
		t.Fatalf("cluster=%#v", out[0])
	}
	if len(out[0].Findings) != 2 {
		t.Fatalf("findings=%d, want 2", len(out[0].Findings))
	}
}

func TestBuildDropsSingleKindClusters(t *testing.T) {
	health := []models.NetworkHealthAnomaly{{SourceKey: "workload:a", Subject: "a", Severity: "warning", Kind: "tcp-latency", Message: "m"}}
	out := Build(health, nil, nil, nil, nil, models.DependencyGraph{}, nil, time.Now())
	if len(out) != 0 {
		t.Fatalf("expected single-kind cluster to be dropped, got %d", len(out))
	}
}

func TestBuildResolvesDetectiveFindingByIPAndTagsProbable(t *testing.T) {
	graph := models.DependencyGraph{Nodes: []models.DependencyNode{{ID: "workload:prod:deployment:api", Kind: "workload", Namespace: "prod", Name: "api", IP: "10.0.0.5"}}}
	health := []models.NetworkHealthAnomaly{{SourceKey: "workload:prod:deployment:api", Subject: "prod/api-1", Severity: "warning", Kind: "tcp-latency", Message: "m"}}
	drops := []models.DropDetectiveFinding{{Dst: "10.0.0.5:443", Explanation: "denied by rule x"}}
	out := Build(health, nil, nil, nil, drops, graph, nil, time.Now())
	if len(out) != 1 {
		t.Fatalf("clusters=%d, want 1", len(out))
	}
	var found bool
	for _, f := range out[0].Findings {
		if f.Kind == "detective" {
			found = true
			if f.JoinConfidence != detective.ConfidenceProbable {
				t.Fatalf("joinConfidence=%q, want probable", f.JoinConfidence)
			}
		}
	}
	if !found {
		t.Fatal("expected a detective finding in the cluster")
	}
}

func TestBuildUnresolvableFindingsGoToControlPlaneNeverDropped(t *testing.T) {
	// An unresolvable detective finding and an unresolvable audit event
	// both land under the control-plane pseudo-key — together they form a
	// legitimate 2-kind cross-signal cluster (never silently dropped,
	// matching this project's general "surface uncertain evidence rather
	// than discard it" convention), even though neither could be
	// attributed to a specific workload.
	drops := []models.DropDetectiveFinding{{Dst: "203.0.113.9:443", Explanation: "denied"}} // no matching graph node
	audit := []models.AuditEvent{{At: time.Now(), Actor: "a", Action: "ebpf.mode", Target: "enforce"}}
	out := Build(nil, nil, nil, nil, drops, models.DependencyGraph{}, audit, time.Now())
	if len(out) != 1 {
		t.Fatalf("clusters=%d, want 1", len(out))
	}
	if out[0].SourceKey != controlPlaneSourceKey {
		t.Fatalf("expected the control-plane cluster, got %#v", out[0])
	}
	var sawDetective, sawAudit bool
	for _, f := range out[0].Findings {
		if f.Kind == "detective" {
			sawDetective = true
			if f.JoinConfidence != "" {
				t.Fatalf("unresolved detective finding must have empty joinConfidence, got %q", f.JoinConfidence)
			}
		}
		if f.Kind == "audit" {
			sawAudit = true
		}
	}
	if !sawDetective || !sawAudit {
		t.Fatalf("expected both kinds in the control-plane cluster, got %#v", out[0].Findings)
	}
}

func TestBuildSingleUnresolvableAuditEventAloneIsDropped(t *testing.T) {
	// One control-plane-only audit event with no other kind alongside it
	// is not cross-signal correlation — same single-kind filter as any
	// other cluster.
	audit := []models.AuditEvent{{At: time.Now(), Actor: "a", Action: "ebpf.mode", Target: "enforce"}}
	out := Build(nil, nil, nil, nil, nil, models.DependencyGraph{}, audit, time.Now())
	if len(out) != 0 {
		t.Fatalf("expected a lone control-plane audit event to be dropped, got %#v", out)
	}
}

func TestBuildAuditIPTargetResolvesToWorkload(t *testing.T) {
	graph := models.DependencyGraph{Nodes: []models.DependencyNode{{ID: "workload:prod:deployment:api", Kind: "workload", Namespace: "prod", Name: "api", IP: "10.0.0.5"}}}
	health := []models.NetworkHealthAnomaly{{SourceKey: "workload:prod:deployment:api", Subject: "prod/api-1", Severity: "warning", Kind: "tcp-latency", Message: "m"}}
	audit := []models.AuditEvent{{At: time.Now(), Actor: "alice", Action: "ebpf.deny.add", Target: "10.0.0.5"}}
	out := Build(health, nil, nil, nil, nil, graph, audit, time.Now())
	if len(out) != 1 {
		t.Fatalf("clusters=%d, want 1", len(out))
	}
	if out[0].SourceKey != "workload:prod:deployment:api" {
		t.Fatalf("expected the audit event joined to the workload cluster, got %#v", out[0])
	}
}

func TestBuildSortsClustersBySeverityThenSize(t *testing.T) {
	health := []models.NetworkHealthAnomaly{
		{SourceKey: "a", Subject: "a", Severity: "warning", Kind: "tcp-latency", Message: "m"},
		{SourceKey: "b", Subject: "b", Severity: "critical", Kind: "tcp-latency", Message: "m"},
	}
	drift := []models.DriftFinding{
		{Source: "a", Severity: "warning", Message: "m2"},
		{Source: "b", Severity: "critical", Message: "m2"},
	}
	out := Build(health, drift, nil, nil, nil, models.DependencyGraph{}, nil, time.Now())
	if len(out) != 2 {
		t.Fatalf("clusters=%d, want 2", len(out))
	}
	if out[0].SourceKey != "b" {
		t.Fatalf("expected the critical cluster first, got %#v", out[0])
	}
}

func TestBuildFindingsSortedChronologically(t *testing.T) {
	t0 := time.Now()
	health := []models.NetworkHealthAnomaly{{SourceKey: "a", Subject: "a", Severity: "warning", Kind: "tcp-latency", Message: "current"}}
	audit := []models.AuditEvent{{At: t0.Add(-time.Hour), Actor: "x", Action: "unknown.action", Target: "a"}}
	// unknown.action with no IP/policy shape falls to control-plane, so use
	// a direct SourceKey match instead by giving the audit event a matching
	// resolvable IP via graph.
	graph := models.DependencyGraph{Nodes: []models.DependencyNode{{ID: "a", Kind: "workload", Namespace: "ns", Name: "n", IP: "10.0.0.1"}}}
	audit[0].Action = "ebpf.deny.add"
	audit[0].Target = "10.0.0.1"
	out := Build(health, nil, nil, nil, nil, graph, audit, t0)
	if len(out) != 1 {
		t.Fatalf("clusters=%d, want 1", len(out))
	}
	if out[0].Findings[0].Kind != "audit" {
		t.Fatalf("expected the older audit finding first, got %#v", out[0].Findings)
	}
}
