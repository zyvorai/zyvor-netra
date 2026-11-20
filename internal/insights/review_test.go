// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package insights

import (
	"testing"

	"github.com/zyvorai/netra/internal/models"
	"github.com/zyvorai/netra/internal/policy"
)

func TestPolicyBlastRadiusMatchesActiveCIDRTraffic(t *testing.T) {
	graph := models.DependencyGraph{
		Nodes: []models.DependencyNode{
			{ID: "workload:prod:deployment:api", Kind: "workload", IP: ""},
			{ID: "external:203.0.113.10", Kind: "external", IP: "203.0.113.10"},
		},
		Edges: []models.DependencyEdge{
			{Source: "workload:prod:deployment:api", Target: "external:203.0.113.10", Packets: 100, Bytes: 5000},
		},
	}
	plan := policy.ChangePlan{RemovedDestinations: []string{"cidr:203.0.113.0/24"}}
	out := PolicyBlastRadius(plan, "workload:prod:deployment:api", graph)
	if len(out) != 1 {
		t.Fatalf("items=%d, want 1", len(out))
	}
	if !out[0].Correlated || !out[0].ActiveTraffic {
		t.Fatalf("item=%#v, want correlated+active", out[0])
	}
}

func TestPolicyBlastRadiusNoTrafficStillCorrelated(t *testing.T) {
	graph := models.DependencyGraph{}
	plan := policy.ChangePlan{RemovedDestinations: []string{"cidr:203.0.113.0/24"}}
	out := PolicyBlastRadius(plan, "workload:a", graph)
	if len(out) != 1 || !out[0].Correlated || out[0].ActiveTraffic {
		t.Fatalf("item=%#v, want correlated but not active", out[0])
	}
}

func TestPolicyBlastRadiusFQDNNeverFalselyDenied(t *testing.T) {
	// The single most important correctness property: an FQDN-only-covered
	// destination must never report ActiveTraffic:false as if it were a
	// confirmed "no traffic" finding the way a CIDR miss legitimately is.
	graph := models.DependencyGraph{}
	plan := policy.ChangePlan{RemovedDestinations: []string{"fqdn:api.example.com", "fqdn-pattern:*.example.com", "entity:world"}}
	out := PolicyBlastRadius(plan, "workload:a", graph)
	if len(out) != 3 {
		t.Fatalf("items=%d, want 3", len(out))
	}
	for _, item := range out {
		if item.Correlated {
			t.Fatalf("non-CIDR destination must never be marked correlated: %#v", item)
		}
		if item.ActiveTraffic {
			t.Fatalf("non-CIDR destination must never be marked active traffic: %#v", item)
		}
		if item.Note == "" {
			t.Fatalf("expected an explanatory note, got none: %#v", item)
		}
	}
}

func TestPolicyBlastRadiusUnparseableCIDR(t *testing.T) {
	plan := policy.ChangePlan{RemovedDestinations: []string{"cidr:not-a-cidr"}}
	out := PolicyBlastRadius(plan, "workload:a", models.DependencyGraph{})
	if len(out) != 1 || out[0].Correlated {
		t.Fatalf("item=%#v, want uncorrelated on parse failure", out[0])
	}
}

func TestPolicyBlastRadiusOnlyChecksMatchingSource(t *testing.T) {
	graph := models.DependencyGraph{
		Nodes: []models.DependencyNode{{ID: "external:203.0.113.10", Kind: "external", IP: "203.0.113.10"}},
		Edges: []models.DependencyEdge{{Source: "workload:other", Target: "external:203.0.113.10", Packets: 100}},
	}
	plan := policy.ChangePlan{RemovedDestinations: []string{"cidr:203.0.113.0/24"}}
	out := PolicyBlastRadius(plan, "workload:a", graph)
	if out[0].ActiveTraffic {
		t.Fatalf("must not attribute another source's traffic to this workload: %#v", out[0])
	}
}
