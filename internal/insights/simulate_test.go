// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package insights

import (
	"testing"

	"github.com/zyvorai/netra/internal/models"
)

func simAgent() []models.AgentStatus {
	return []models.AgentStatus{{AgentReport: models.AgentReport{Workloads: []models.WorkloadIdentity{
		{Namespace: "prod", Pod: "api-1", WorkloadKind: "Deployment", WorkloadName: "api", Labels: map[string]string{"app": "api"}, CgroupID: 7},
	}}}}
}

func simGraph(edges ...models.DependencyEdge) models.DependencyGraph {
	return models.DependencyGraph{
		Nodes: []models.DependencyNode{
			{ID: "workload:prod:deployment:api", Kind: "workload", Namespace: "prod", Name: "api"},
			{ID: "external:203.0.113.10", Kind: "external", Name: "203.0.113.10", IP: "203.0.113.10"},
			{ID: "external:198.51.100.5", Kind: "external", Name: "198.51.100.5", IP: "198.51.100.5"},
			{ID: "service:prod:redis", Kind: "service", Namespace: "prod", Name: "redis", IP: "10.96.0.5"},
			{ID: "workload:prod:deployment:db", Kind: "workload", Namespace: "prod", Name: "db", IP: "10.0.0.9"},
		},
		Edges: edges,
	}
}

func candidateJSON(ns string, egress string) []byte {
	return []byte(`{"apiVersion":"cilium.io/v2","kind":"CiliumNetworkPolicy","metadata":{"name":"eg","namespace":"` + ns + `"},"spec":{"endpointSelector":{"matchLabels":{"app":"api"}},"egress":[` + egress + `]}}`)
}

func TestSimulateAllowsCIDRMatch(t *testing.T) {
	candidate := candidateJSON("prod", `{"toCIDR":["203.0.113.0/24"],"toPorts":[{"ports":[{"port":443,"protocol":"TCP"}]}]}`)
	graph := simGraph(models.DependencyEdge{Source: "workload:prod:deployment:api", Target: "external:203.0.113.10", Protocol: "TCP", Port: 443})
	out, err := Simulate(candidate, graph, simAgent())
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Results) != 1 || out.Results[0].Verdict != "allowed" {
		t.Fatalf("results=%#v", out.Results)
	}
}

func TestSimulateDeniesUncoveredEdgeWithNoFQDNRules(t *testing.T) {
	candidate := candidateJSON("prod", `{"toCIDR":["203.0.113.0/24"]}`)
	graph := simGraph(models.DependencyEdge{Source: "workload:prod:deployment:api", Target: "external:198.51.100.5", Protocol: "TCP", Port: 443})
	out, err := Simulate(candidate, graph, simAgent())
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Results) != 1 || out.Results[0].Verdict != "denied" {
		t.Fatalf("results=%#v, want denied (no FQDN rules present, so absence is confident)", out.Results)
	}
}

// TestSimulateFQDNEdgeNeverFalselyDenied is the single most important
// correctness property: once a candidate policy has any toFQDNs rule, no
// edge this policy governs may ever come back "denied" — only "allowed" (if
// some other rule confirms it) or "unverified". A false "denied" could make
// an operator wrongly trust a policy is safe to apply.
func TestSimulateFQDNEdgeNeverFalselyDenied(t *testing.T) {
	candidate := candidateJSON("prod", `{"toFQDNs":[{"matchName":"api.example.com"}],"toPorts":[{"ports":[{"port":443,"protocol":"TCP"}]}]}`)
	graph := simGraph(models.DependencyEdge{Source: "workload:prod:deployment:api", Target: "external:198.51.100.5", Protocol: "TCP", Port: 443})
	out, err := Simulate(candidate, graph, simAgent())
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Results) != 1 {
		t.Fatalf("results=%#v", out.Results)
	}
	if out.Results[0].Verdict == "denied" {
		t.Fatalf("an edge under a toFQDNs-containing policy must never be denied, got %#v", out.Results[0])
	}
	if out.Results[0].Verdict != "unverified" {
		t.Fatalf("verdict=%q, want unverified", out.Results[0].Verdict)
	}
}

func TestSimulateFQDNPolicyStillAllowsExplicitCIDRMatch(t *testing.T) {
	// A policy can have both toFQDNs and toCIDR rules — an edge that
	// matches the CIDR rule directly should still be "allowed", not
	// downgraded to "unverified" just because the policy also has FQDN
	// rules elsewhere.
	candidate := candidateJSON("prod", `{"toFQDNs":[{"matchName":"api.example.com"}]},{"toCIDR":["203.0.113.0/24"]}`)
	graph := simGraph(models.DependencyEdge{Source: "workload:prod:deployment:api", Target: "external:203.0.113.10", Protocol: "TCP", Port: 443})
	out, err := Simulate(candidate, graph, simAgent())
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Results) != 1 || out.Results[0].Verdict != "allowed" {
		t.Fatalf("results=%#v", out.Results)
	}
}

func TestSimulateEntitiesWorldAndCluster(t *testing.T) {
	candidate := candidateJSON("prod", `{"toEntities":["world"]}`)
	graph := simGraph(
		models.DependencyEdge{Source: "workload:prod:deployment:api", Target: "external:203.0.113.10", Protocol: "TCP", Port: 443},
		models.DependencyEdge{Source: "workload:prod:deployment:api", Target: "workload:prod:deployment:db", Protocol: "TCP", Port: 5432},
	)
	out, err := Simulate(candidate, graph, simAgent())
	if err != nil {
		t.Fatal(err)
	}
	var external, internal string
	for _, r := range out.Results {
		if r.Target == "external:203.0.113.10" {
			external = r.Verdict
		}
		if r.Target == "workload:prod:deployment:db" {
			internal = r.Verdict
		}
	}
	if external != "allowed" {
		t.Fatalf("external verdict=%q, want allowed (toEntities: world)", external)
	}
	if internal != "denied" {
		t.Fatalf("internal verdict=%q, want denied (world doesn't cover cluster-internal)", internal)
	}
}

func TestSimulateToServicesMatch(t *testing.T) {
	candidate := candidateJSON("prod", `{"toServices":[{"k8sService":{"serviceName":"redis","namespace":"prod"}}]}`)
	graph := simGraph(models.DependencyEdge{Source: "workload:prod:deployment:api", Target: "service:prod:redis", Protocol: "TCP", Port: 6379})
	out, err := Simulate(candidate, graph, simAgent())
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Results) != 1 || out.Results[0].Verdict != "allowed" {
		t.Fatalf("results=%#v", out.Results)
	}
}

func TestSimulateToEndpointsMatchAndUnverifiedWithoutLabels(t *testing.T) {
	candidate := candidateJSON("prod", `{"toEndpoints":[{"matchLabels":{"app":"db"}}]}`)
	graph := simGraph(models.DependencyEdge{Source: "workload:prod:deployment:api", Target: "workload:prod:deployment:db", Protocol: "TCP", Port: 5432})
	// No agent reports db's own labels — must be "unverified", not "denied".
	out, err := Simulate(candidate, graph, simAgent())
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Results) != 1 || out.Results[0].Verdict != "unverified" {
		t.Fatalf("results=%#v, want unverified (target labels unknown)", out.Results)
	}

	agentsWithDBLabels := append(simAgent(), models.AgentStatus{AgentReport: models.AgentReport{Workloads: []models.WorkloadIdentity{
		{Namespace: "prod", Pod: "db-1", WorkloadKind: "Deployment", WorkloadName: "db", Labels: map[string]string{"app": "db"}},
	}}})
	out2, err := Simulate(candidate, graph, agentsWithDBLabels)
	if err != nil {
		t.Fatal(err)
	}
	if len(out2.Results) != 1 || out2.Results[0].Verdict != "allowed" {
		t.Fatalf("results=%#v, want allowed once target labels are known", out2.Results)
	}
}

func TestSimulateNoGovernedSourcesProducesNote(t *testing.T) {
	candidate := candidateJSON("prod", `{"toCIDR":["203.0.113.0/24"]}`)
	agents := []models.AgentStatus{{AgentReport: models.AgentReport{Workloads: []models.WorkloadIdentity{
		{Namespace: "prod", Pod: "other-1", WorkloadKind: "Deployment", WorkloadName: "other", Labels: map[string]string{"app": "other"}},
	}}}}
	out, err := Simulate(candidate, simGraph(), agents)
	if err != nil {
		t.Fatal(err)
	}
	if out.GovernedSources != 0 || out.Note == "" {
		t.Fatalf("out=%#v, want 0 governed sources and an explanatory note", out)
	}
}

func TestSimulateEmptyEgressIsFullDeny(t *testing.T) {
	candidate := candidateJSON("prod", ``)
	graph := simGraph(models.DependencyEdge{Source: "workload:prod:deployment:api", Target: "external:203.0.113.10", Protocol: "TCP", Port: 443})
	out, err := Simulate(candidate, graph, simAgent())
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Results) != 1 || out.Results[0].Verdict != "denied" {
		t.Fatalf("results=%#v, want denied (no egress rules at all -> default-deny)", out.Results)
	}
}

func TestSimulateRejectsInvalidJSON(t *testing.T) {
	if _, err := Simulate([]byte("not json"), models.DependencyGraph{}, nil); err == nil {
		t.Fatal("expected an error for invalid candidate JSON")
	}
}
