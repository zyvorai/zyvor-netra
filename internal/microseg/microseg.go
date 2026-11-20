// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

// Package microseg produces east-west microsegmentation guidance.
// Durable policy prefers PacketWolf/Cilium; Netra offers only
// review-only lease-scoped emergency drafts.
package microseg

import (
	"fmt"
	"strings"
	"time"

	"github.com/zyvorai/netra/internal/insights"
	"github.com/zyvorai/netra/internal/models"
)

// Guidance is GET /api/v1/insights/microseg.
type Guidance struct {
	GeneratedAt      time.Time                 `json:"generatedAt"`
	CiliumDetected   bool                      `json:"ciliumDetected"`
	Recommendation   string                    `json:"recommendation"`
	PreferPacketWolf bool                      `json:"preferPacketWolf"`
	EastWestEdges    int                       `json:"eastWestEdges"`
	ExternalEdges    int                       `json:"externalEdges"`
	LeaseDrafts      []insights.ZeroTrustDraft `json:"leaseDrafts,omitempty"`
	Steps            []string                  `json:"steps"`
	Note             string                    `json:"note"`
}

// Build inspects the dependency graph and agent hooks for Cilium signals.
func Build(graph models.DependencyGraph, agents []models.AgentStatus, ciliumEnabled bool, ztLimit int) Guidance {
	now := time.Now().UTC()
	if ztLimit <= 0 {
		ztLimit = 20
	}
	ew, ext := 0, 0
	for _, e := range graph.Edges {
		if e.External {
			ext++
		} else {
			ew++
		}
	}
	cilium := ciliumEnabled || detectCilium(agents)
	g := Guidance{
		GeneratedAt: now, CiliumDetected: cilium, PreferPacketWolf: cilium,
		EastWestEdges: ew, ExternalEdges: ext,
		Note: "Deeper east-west microseg is suite-owned on Cilium (PacketWolf). Netra stays observe-first + leased emergency deny.",
	}
	if cilium {
		g.Recommendation = "Use PacketWolf / Cilium NetworkPolicy for durable east-west microsegmentation. Keep Netra for CNI-independent diagnostics and short-lease emergency containment."
		g.Steps = []string{
			"Author / learn CiliumNetworkPolicy (or PacketWolf AutoPolicy) for standing allow-lists",
			"Use Netra insights zero-trust / recommendations as review input only",
			"Reserve Netra mode=enforce leases for incidents; do not replace CNI policy with standing Netra denies",
			"See docs/packetwolf.md for co-existence rules",
		}
	} else {
		g.Recommendation = "No Cilium detected — Netra can suggest review-only east-west allow drafts and leased emergency denies. Prefer introducing Cilium+PacketWolf for durable microseg when ready."
		g.Steps = []string{
			"Review GET /api/v1/insights/zero-trust drafts for private destinations",
			"Apply Netra allow-cidr / deny only behind an enforce lease when containing an incident",
			"Plan Cilium + PacketWolf for standing east-west policy if the cluster standardizes on Cilium",
		}
		g.LeaseDrafts = insights.ZeroTrust(graph, agents, ztLimit)
		// Prefer only allow_cidr (east-west) drafts in this view.
		filtered := g.LeaseDrafts[:0]
		for _, d := range g.LeaseDrafts {
			if d.Kind == "allow_cidr" {
				filtered = append(filtered, d)
			}
		}
		g.LeaseDrafts = filtered
	}
	if ew == 0 && ext == 0 {
		g.Steps = append([]string{fmt.Sprintf("No dependency edges yet (%d agents)", len(agents))}, g.Steps...)
	}
	return g
}

func detectCilium(agents []models.AgentStatus) bool {
	for _, a := range agents {
		if a.Stale {
			continue
		}
		for _, h := range a.Hooks {
			if strings.Contains(strings.ToLower(h), "cilium") {
				return true
			}
		}
		for _, p := range a.Programs {
			if strings.Contains(strings.ToLower(p.Name), "cilium") {
				return true
			}
		}
	}
	return false
}
