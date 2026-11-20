// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package sysres

import (
	"sort"
	"time"

	"github.com/zyvorai/netra/internal/models"
)

// Build assembles the per-node/per-workload resource response from the
// latest agent snapshot. Unlike internal/sysctlaudit.Build (which skips
// stale agents entirely — a settings audit has nothing useful to say
// about a node it can't currently see), this follows internal/fleet's
// convention instead: every node still appears in Nodes with a Stale
// flag, since this is an inventory view, not a findings view — but a
// stale node's frozen last-known CPU%/memory is excluded from Summary's
// cluster aggregates and from TopWorkloadsByCPU, so a disconnected node
// can never skew a live ranking or average.
func Build(agents []models.AgentStatus, now time.Time, topWorkloads int) models.NodeResourcesResponse {
	if topWorkloads <= 0 {
		topWorkloads = 20
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	out := models.NodeResourcesResponse{
		GeneratedAt: now.UTC(),
		Limitations: []string{
			"Workload rows cover cgroup v2-attributed workloads (Kubernetes pods/containers) only, not raw host processes — this is not a full ps/top process list.",
			"CPUPercent is 0 on an agent's first report after (re)start; there is no prior sample to diff against yet.",
			"Host CPUPercent is not per-core normalized and can exceed 100 on a multi-core node under full load.",
			"A stale node's numbers are its last-known values, frozen at disconnect — excluded from cluster averages and the top-CPU ranking below.",
		},
	}

	var freshCPUSum float64
	var freshCount int
	var highestCPU, highestMem float64
	for _, a := range agents {
		n := models.NodeResources{
			Node: a.Node, Stale: a.Stale, AgeSeconds: a.AgeSeconds,
			Host: a.NodeResources.Host, Workloads: a.NodeResources.Workloads,
		}
		out.Nodes = append(out.Nodes, n)

		out.Summary.TotalCPUCores += n.Host.CPUCores
		out.Summary.TotalMemoryBytes += n.Host.MemoryTotalBytes
		if a.Stale {
			continue
		}
		freshCount++
		freshCPUSum += n.Host.CPUPercent
		out.Summary.UsedMemoryBytes += n.Host.MemoryUsedBytes
		if n.Host.CPUPercent > highestCPU || out.Summary.HighestCPUNode == "" {
			highestCPU, out.Summary.HighestCPUNode = n.Host.CPUPercent, a.Node
		}
		if n.Host.MemoryUsedBytes > 0 && (float64(n.Host.MemoryUsedBytes) > highestMem || out.Summary.HighestMemoryNode == "") {
			highestMem, out.Summary.HighestMemoryNode = float64(n.Host.MemoryUsedBytes), a.Node
		}
		out.TopWorkloadsByCPU = append(out.TopWorkloadsByCPU, n.Workloads...)
	}
	out.Summary.Nodes = len(out.Nodes)
	if freshCount > 0 {
		out.Summary.AvgCPUPercent = freshCPUSum / float64(freshCount)
	}

	sort.Slice(out.Nodes, func(i, j int) bool { return out.Nodes[i].Node < out.Nodes[j].Node })
	sort.Slice(out.TopWorkloadsByCPU, func(i, j int) bool {
		return out.TopWorkloadsByCPU[i].CPUPercent > out.TopWorkloadsByCPU[j].CPUPercent
	})
	if len(out.TopWorkloadsByCPU) > topWorkloads {
		out.TopWorkloadsByCPU = out.TopWorkloadsByCPU[:topWorkloads]
	}
	return out
}
