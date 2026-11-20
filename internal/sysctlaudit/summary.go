// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package sysctlaudit

import (
	"sort"

	"github.com/zyvorai/netra/internal/models"
)

// Build classifies every fresh agent's sysctl-audit snapshot against
// Baseline and computes a cluster-wide summary and outlier list. Unlike
// internal/kerneldiag, there are no cumulative counters here — every value
// is a current setting — so this is a pure function with no store/window
// dependency, called fresh on every request.
func Build(agents []models.AgentStatus, topN int) models.SysctlAuditResponse {
	if topN <= 0 {
		topN = 50
	}
	out := models.SysctlAuditResponse{
		Limitations: []string{
			"Node-level only: sysctls are host/namespace-wide, not attributed to a workload.",
			"Per-interface enumeration reflects whatever interfaces exist on each node at collection time.",
			"Most sysctls outside security/TCP-lifecycle hardening are informational: no universal baseline exists.",
			"Netra never writes sysctls; findings are for operator review only.",
		},
	}

	type groupKey struct{ name, iface, category string }
	valueCounts := map[groupKey]map[string][]string{} // value -> node names

	for _, a := range agents {
		if a.Stale {
			continue
		}
		n := models.NodeSysctlAudit{Node: a.Node, Snapshot: a.SysctlNetworkAudit}
		for _, e := range a.SysctlNetworkAudit.Entries {
			f := Classify(e)
			n.Findings = append(n.Findings, f)
			switch f.Severity {
			case SeverityCritical:
				out.Summary.Critical++
			case SeverityWarning:
				out.Summary.Warnings++
			default:
				out.Summary.Informational++
			}
			out.Summary.Findings++

			key := groupKey{baselineName(e), e.Interface, e.Category}
			if valueCounts[key] == nil {
				valueCounts[key] = map[string][]string{}
			}
			valueCounts[key][e.Value] = append(valueCounts[key][e.Value], a.Node)
		}
		sort.Slice(n.Findings, func(i, j int) bool {
			return severityRank(n.Findings[i].Severity) > severityRank(n.Findings[j].Severity)
		})
		// Summary.Findings/Critical/Warnings/Informational above are true
		// cluster-wide totals; only the per-node display list is capped.
		if len(n.Findings) > topN {
			n.Findings = n.Findings[:topN]
		}
		out.Nodes = append(out.Nodes, n)
	}
	out.Summary.Nodes = len(out.Nodes)

	for key, counts := range valueCounts {
		if len(counts) < 2 {
			continue // every node agrees
		}
		majorityValue, majorityNodes := "", 0
		for v, nodes := range counts {
			if len(nodes) > majorityNodes {
				majorityValue, majorityNodes = v, len(nodes)
			}
		}
		var outlierNodes []string
		for v, nodes := range counts {
			if v == majorityValue {
				continue
			}
			outlierNodes = append(outlierNodes, nodes...)
		}
		sort.Strings(outlierNodes)
		out.Outliers = append(out.Outliers, models.SysctlAuditOutlier{
			Name: key.name, Interface: key.iface, Category: key.category,
			MajorityValue: majorityValue, OutlierNodes: outlierNodes,
		})
	}
	sort.Slice(out.Outliers, func(i, j int) bool {
		return len(out.Outliers[i].OutlierNodes) > len(out.Outliers[j].OutlierNodes)
	})
	if len(out.Outliers) > topN {
		out.Outliers = out.Outliers[:topN]
	}
	out.Summary.Outliers = len(out.Outliers)

	sort.Slice(out.Nodes, func(i, j int) bool { return nodeScore(out.Nodes[i]) > nodeScore(out.Nodes[j]) })
	return out
}

// baselineName strips the interface segment from a per-interface sysctl's
// display name so nodes with different interface counts still group on the
// same (suffix, interface, category) key for outlier detection.
func baselineName(e models.SysctlAuditEntry) string {
	if e.Interface == "" {
		return e.Name
	}
	for _, s := range append(append(append([]string{}, SecuritySuffixes...), ARPSuffixes...), IPv6Suffixes...) {
		if len(e.Name) >= len(s) && e.Name[len(e.Name)-len(s):] == s {
			return s
		}
	}
	return e.Name
}

func severityRank(sev string) int {
	switch sev {
	case SeverityCritical:
		return 3
	case SeverityWarning:
		return 2
	default:
		return 1
	}
}

func nodeScore(n models.NodeSysctlAudit) int {
	score := 0
	for _, f := range n.Findings {
		score += severityRank(f.Severity)
	}
	return score
}
