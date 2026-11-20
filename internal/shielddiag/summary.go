// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

// Package shielddiag breaks the XDP Shield's aggregate allowed/dropped/
// audited counters out by traffic class and surfaces the top offending
// sources, using data the shield already computes (class_id, per-source
// token-bucket state) but previously only kept as an unbroken-out total.
package shielddiag

import (
	"fmt"
	"sort"

	"github.com/zyvorai/netra/internal/models"
)

// sourceFloodThreshold is the per-source denied-hit count above which a
// single source is worth calling out individually, distinct from the
// aggregate class-level drop rate.
const sourceFloodThreshold = 10000

// connectionAttemptRateThreshold is the per-source new-connection-attempt
// (SYN) count above which fan-in is worth calling out — independent of
// sourceFloodThreshold, since Attempts is recorded regardless of Shield's
// pass/drop verdict (unlike Denied, so this can fire in audit mode, or for
// a source Shield is allowing through entirely, e.g. syn_pps disabled).
const connectionAttemptRateThreshold = 10000

// Build aggregates per-node Shield class breakdowns and merges/re-sorts
// per-source hit counts (already bounded and pre-sorted agent-side) into
// a cluster-wide top-N — no in-kernel top-K, just a periodic-snapshot
// merge, matching internal/observability's existing top-N pattern.
func Build(agents []models.AgentStatus, topN int) models.ShieldDiagnosticsResponse {
	if topN <= 0 {
		topN = 50
	}
	out := models.ShieldDiagnosticsResponse{}
	var allSources []models.ShieldSourceStat
	for _, a := range agents {
		if a.Stale {
			continue
		}
		n := models.NodeShieldDiagnostics{Node: a.Node, Classes: append([]models.ShieldClassStat(nil), a.ShieldClasses...)}
		sort.Slice(n.Classes, func(i, j int) bool { return n.Classes[i].Dropped > n.Classes[j].Dropped })
		out.Nodes = append(out.Nodes, n)
		for _, c := range a.ShieldClasses {
			out.Summary.Allowed += c.Allowed
			out.Summary.Dropped += c.Dropped
			out.Summary.Audited += c.Audited
		}
		allSources = append(allSources, a.ShieldSources...)
	}
	// Sort by Attempts, not Denied: Attempts >= Denied always, so this never
	// loses a high-Denied source and also surfaces high-Attempts/low-Denied
	// sources (audit mode, or a disabled pps threshold) a Denied-only sort
	// would truncate away.
	sort.Slice(allSources, func(i, j int) bool { return allSources[i].Attempts > allSources[j].Attempts })
	if len(allSources) > topN {
		allSources = allSources[:topN]
	}
	out.TopSources = allSources
	out.Summary.Anomalies = anomalies(out)
	sort.Slice(out.Nodes, func(i, j int) bool { return nodeScore(out.Nodes[i]) > nodeScore(out.Nodes[j]) })
	return out
}

func nodeScore(n models.NodeShieldDiagnostics) uint64 {
	var x uint64
	for _, c := range n.Classes {
		x += c.Dropped
	}
	return x
}

func anomalies(r models.ShieldDiagnosticsResponse) []models.NetworkHealthAnomaly {
	out := make([]models.NetworkHealthAnomaly, 0, 32)
	for _, n := range r.Nodes {
		for _, c := range n.Classes {
			total := c.Allowed + c.Dropped + c.Audited
			if total == 0 || c.Dropped == 0 {
				continue
			}
			rate := float64(c.Dropped) / float64(total)
			if rate < 0.10 {
				continue
			}
			sev := "warning"
			if rate >= 0.50 {
				sev = "critical"
			}
			out = append(out, models.NetworkHealthAnomaly{
				Severity: sev, Kind: "shield-class-drop-rate", Subject: n.Node + "/" + c.Class,
				Message: fmt.Sprintf("XDP Shield is dropping %.1f%% of %s-class traffic (%d of %d)", rate*100, c.Class, c.Dropped, total),
				Value:   rate * 100,
			})
		}
	}
	for _, s := range r.TopSources {
		if s.Denied < sourceFloodThreshold {
			continue
		}
		out = append(out, models.NetworkHealthAnomaly{
			Severity: "critical", Kind: "shield-source-flood", Subject: fmt.Sprintf("%s (%s)", s.Address, s.Class),
			Message: fmt.Sprintf("a single source has been denied %d times by XDP Shield", s.Denied),
			Value:   float64(s.Denied),
		})
	}
	for _, s := range r.TopSources {
		if s.Attempts < connectionAttemptRateThreshold {
			continue
		}
		out = append(out, models.NetworkHealthAnomaly{
			Severity: "warning", Kind: "shield-connection-rate", Subject: fmt.Sprintf("%s (%s)", s.Address, s.Class),
			Message: fmt.Sprintf("a single source has attempted %d new connections observed by XDP Shield, regardless of verdict", s.Attempts),
			Value:   float64(s.Attempts),
		})
	}
	order := map[string]int{"critical": 3, "warning": 2, "info": 1}
	sort.SliceStable(out, func(i, j int) bool {
		if order[out[i].Severity] != order[out[j].Severity] {
			return order[out[i].Severity] > order[out[j].Severity]
		}
		return out[i].Value > out[j].Value
	})
	if len(out) > 100 {
		out = out[:100]
	}
	return out
}
