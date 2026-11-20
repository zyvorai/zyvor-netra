// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package insights

import (
	"testing"

	"github.com/zyvorai/netra/internal/models"
)

func chainGraph(n int) models.DependencyGraph {
	g := models.DependencyGraph{}
	for i := 0; i <= n; i++ {
		g.Nodes = append(g.Nodes, models.DependencyNode{ID: nodeID(i)})
	}
	for i := range n {
		g.Edges = append(g.Edges, models.DependencyEdge{Source: nodeID(i), Target: nodeID(i + 1), Protocol: "TCP", Port: 443, Packets: uint64(n - i)})
	}
	return g
}

func nodeID(i int) string {
	return "n" + string(rune('a'+i))
}

func TestBlastRadiusDefaultHops(t *testing.T) {
	g := chainGraph(5)
	resp, err := BlastRadius(g, nodeID(0), 0)
	if err != nil {
		t.Fatalf("err=%v", err)
	}
	if resp.MaxHops != DefaultBlastRadiusHops {
		t.Fatalf("maxHops=%d want %d", resp.MaxHops, DefaultBlastRadiusHops)
	}
	if len(resp.Nodes) != DefaultBlastRadiusHops+1 {
		t.Fatalf("nodes=%d want %d", len(resp.Nodes), DefaultBlastRadiusHops+1)
	}
	if !resp.Truncated {
		t.Fatalf("expected truncated=true, chain extends past default hop ceiling")
	}
	if resp.Caveat == "" {
		t.Fatalf("caveat must always be set")
	}
}

func TestBlastRadiusHopsClampedToCeiling(t *testing.T) {
	g := chainGraph(10)
	resp, err := BlastRadius(g, nodeID(0), 999)
	if err != nil {
		t.Fatalf("err=%v", err)
	}
	if resp.MaxHops != MaxBlastRadiusHops {
		t.Fatalf("maxHops=%d want %d", resp.MaxHops, MaxBlastRadiusHops)
	}
	if !resp.Truncated {
		t.Fatalf("expected truncated=true, chain of 10 exceeds ceiling of %d", MaxBlastRadiusHops)
	}
}

func TestBlastRadiusFullyExploredIsNotTruncated(t *testing.T) {
	g := chainGraph(2)
	resp, err := BlastRadius(g, nodeID(0), 5)
	if err != nil {
		t.Fatalf("err=%v", err)
	}
	if resp.Truncated {
		t.Fatalf("chain of 2 fully fits within 5 hops, should not be truncated")
	}
	if len(resp.Nodes) != 3 {
		t.Fatalf("nodes=%d want 3", len(resp.Nodes))
	}
}

func TestBlastRadiusUnknownRoot(t *testing.T) {
	g := chainGraph(2)
	if _, err := BlastRadius(g, "does-not-exist", 3); err == nil {
		t.Fatalf("expected error for unknown root")
	}
}

func TestBlastRadiusHandlesCycles(t *testing.T) {
	g := models.DependencyGraph{
		Nodes: []models.DependencyNode{{ID: "a"}, {ID: "b"}, {ID: "c"}},
		Edges: []models.DependencyEdge{
			{Source: "a", Target: "b", Protocol: "TCP", Port: 80},
			{Source: "b", Target: "c", Protocol: "TCP", Port: 80},
			{Source: "c", Target: "a", Protocol: "TCP", Port: 80},
		},
	}
	resp, err := BlastRadius(g, "a", 6)
	if err != nil {
		t.Fatalf("err=%v", err)
	}
	if len(resp.Nodes) != 3 {
		t.Fatalf("nodes=%d want 3 (cycle must not infinite-loop or duplicate)", len(resp.Nodes))
	}
	if resp.Truncated {
		t.Fatalf("a 3-node cycle is fully explorable, should not report truncated")
	}
}

func TestBlastRadiusDedupesParallelEdges(t *testing.T) {
	g := models.DependencyGraph{
		Nodes: []models.DependencyNode{{ID: "a"}, {ID: "b"}},
		Edges: []models.DependencyEdge{
			{Source: "a", Target: "b", Protocol: "TCP", Port: 80},
			{Source: "a", Target: "b", Protocol: "TCP", Port: 80},
		},
	}
	resp, err := BlastRadius(g, "a", 3)
	if err != nil {
		t.Fatalf("err=%v", err)
	}
	if len(resp.Edges) != 1 {
		t.Fatalf("edges=%d want 1", len(resp.Edges))
	}
}
