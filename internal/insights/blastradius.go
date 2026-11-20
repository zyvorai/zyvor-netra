// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package insights

import (
	"fmt"
	"sort"
	"strconv"
	"time"

	"github.com/zyvorai/netra/internal/models"
)

const (
	DefaultBlastRadiusHops = 3
	MaxBlastRadiusHops     = 6

	// BlastRadiusCaveat must accompany every BlastRadius result surfaced to a
	// user, verbatim or paraphrased no more loosely than this. This graph is
	// built from observed packets, not evaluated policy, so it must never be
	// described as what traffic is "permitted" or "allowed" to reach.
	BlastRadiusCaveat = "Observed traffic reachability only, derived from packets Netra has seen — not a policy allow/deny determination; a node with no edges here may still be permitted to reach further destinations that simply weren't observed in this window. Edges may be stale relative to the currently applied policy. Traversal reports a shortest hop-count path, not necessarily the most significant one."
)

// BlastRadius walks the dependency graph outward from root, breadth-first, up
// to maxHops (clamped to [1, MaxBlastRadiusHops], defaulting to
// DefaultBlastRadiusHops when <= 0). Edges are directed source->target, same
// as the underlying DependencyGraph; a cycle simply stops expanding once a
// node is revisited.
func BlastRadius(graph models.DependencyGraph, root string, maxHops int) (models.BlastRadiusResponse, error) {
	if maxHops <= 0 {
		maxHops = DefaultBlastRadiusHops
	}
	if maxHops > MaxBlastRadiusHops {
		maxHops = MaxBlastRadiusHops
	}

	known := make(map[string]bool, len(graph.Nodes))
	for _, n := range graph.Nodes {
		known[n.ID] = true
	}
	if root == "" || !known[root] {
		return models.BlastRadiusResponse{}, fmt.Errorf("unknown root node %q", root)
	}

	adj := map[string][]models.DependencyEdge{}
	for _, e := range graph.Edges {
		adj[e.Source] = append(adj[e.Source], e)
	}

	visited := map[string]int{root: 0}
	edgeSeen := map[string]bool{}
	var edgesUsed []models.DependencyEdge
	frontier := []string{root}

	for hop := 1; hop <= maxHops && len(frontier) > 0; hop++ {
		var next []string
		for _, src := range frontier {
			for _, e := range adj[src] {
				key := e.Source + "\x00" + e.Target + "\x00" + e.Protocol + "\x00" + strconv.Itoa(int(e.Port))
				if !edgeSeen[key] {
					edgeSeen[key] = true
					edgesUsed = append(edgesUsed, e)
				}
				if _, ok := visited[e.Target]; !ok {
					visited[e.Target] = hop
					next = append(next, e.Target)
				}
			}
		}
		frontier = next
	}

	// frontier now holds the last hop's newly-reached nodes (or is empty if
	// the graph was fully explored before maxHops). If any of them still has
	// an edge to a node this traversal never reached, the radius was cut off
	// by the hop ceiling rather than by the graph actually ending.
	truncated := false
	for _, src := range frontier {
		for _, e := range adj[src] {
			if _, ok := visited[e.Target]; !ok {
				truncated = true
			}
		}
	}

	nodes := make([]models.BlastRadiusNode, 0, len(visited))
	for id, hops := range visited {
		nodes = append(nodes, models.BlastRadiusNode{ID: id, Hops: hops})
	}
	sort.Slice(nodes, func(i, j int) bool {
		if nodes[i].Hops != nodes[j].Hops {
			return nodes[i].Hops < nodes[j].Hops
		}
		return nodes[i].ID < nodes[j].ID
	})
	sort.Slice(edgesUsed, func(i, j int) bool {
		if edgesUsed[i].Packets != edgesUsed[j].Packets {
			return edgesUsed[i].Packets > edgesUsed[j].Packets
		}
		if edgesUsed[i].Source != edgesUsed[j].Source {
			return edgesUsed[i].Source < edgesUsed[j].Source
		}
		return edgesUsed[i].Target < edgesUsed[j].Target
	})

	return models.BlastRadiusResponse{
		GeneratedAt: time.Now().UTC(),
		Root:        root,
		MaxHops:     maxHops,
		Nodes:       nodes,
		Edges:       edgesUsed,
		Truncated:   truncated,
		Caveat:      BlastRadiusCaveat,
	}, nil
}
