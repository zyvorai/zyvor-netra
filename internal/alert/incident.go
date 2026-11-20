// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package alert

import (
	"sort"
	"time"

	"github.com/zyvorai/netra/internal/dropreason"
	"github.com/zyvorai/netra/internal/models"
	"github.com/zyvorai/netra/internal/notify"
)

const incidentTopN = 10

// dropContextLimitations is copied onto every frozen snapshot so an
// operator reading the JSON later sees the same bounds the collector has.
var dropContextLimitations = []string{
	"CPU and memory pressure are the last agent sample (about 3s), not a multi-minute baseline.",
	"Host process rows are pid, comm, CPU percent, and RSS only — no argv, cmdline, or environment.",
	"Policy-drop process identity applies to egress TCP only; ingress and non-TCP drops stay unattributable.",
	"Workload rows are cgroup v2 pods/containers, not a full process list.",
}

// BuildDropContext freezes node, process, and pressure context from the
// agent snapshot the alert poller already holds. It does not read /proc.
func BuildDropContext(now time.Time, ev notify.Event, agent models.AgentStatus) models.DropIncidentContext {
	if now.IsZero() {
		now = time.Now().UTC()
	}
	now = now.UTC()
	host := agent.NodeResources.Host
	cpuHot, memHot := hostPressure(host)
	return models.DropIncidentContext{
		CapturedAt: now,
		Trigger: models.DropIncidentTrigger{
			Source:    ev.Source,
			Kind:      ev.Kind,
			Severity:  ev.Severity,
			Subject:   ev.Subject,
			Message:   ev.Message,
			Value:     ev.Value,
			Timestamp: ev.Timestamp.UTC(),
		},
		Node: models.DropIncidentNode{
			Name:          agent.Node,
			Hostname:      host.Hostname,
			KernelRelease: host.KernelRelease,
			Stale:         agent.Stale,
			AgeSeconds:    agent.AgeSeconds,
		},
		Host:                 host,
		CPUHot:               cpuHot,
		MemoryHot:            memHot,
		TopWorkloadsByCPU:    topWorkloads(agent.NodeResources.Workloads, incidentTopN, func(a, b models.WorkloadResourceStat) bool { return a.CPUPercent > b.CPUPercent }),
		TopWorkloadsByMemory: topWorkloads(agent.NodeResources.Workloads, incidentTopN, func(a, b models.WorkloadResourceStat) bool { return a.MemoryUsedBytes > b.MemoryUsedBytes }),
		PolicyDropProcesses:  topPolicyDrops(agent.PolicyDrops, incidentTopN),
		TopProcessesByCPU:    capHostProcesses(agent.HostProcesses.ByCPU, incidentTopN),
		TopProcessesByMemory: capHostProcesses(agent.HostProcesses.ByMemory, incidentTopN),
		Stack:                agent.Stack,
		QdiscStats:           topQdiscs(agent.QdiscStats, incidentTopN),
		KernelDrops:          topKernelDrops(agent.KernelDrops, incidentTopN),
		Limitations:          append([]string(nil), dropContextLimitations...),
	}
}

// hostPressure marks a hot CPU when utilization is at least 80% of
// capacity. Host CPUPercent is not per-core normalized, so the threshold
// is 80 * cores (a fully busy 8-core node reads about 800). Memory is hot
// at 90% of MemTotal used.
func hostPressure(h models.HostResourceSnapshot) (cpuHot, memHot bool) {
	if h.CPUCores > 0 && h.CPUPercent >= 80*float64(h.CPUCores) {
		cpuHot = true
	}
	if h.MemoryTotalBytes > 0 && float64(h.MemoryUsedBytes) >= 0.9*float64(h.MemoryTotalBytes) {
		memHot = true
	}
	return cpuHot, memHot
}

func topWorkloads(in []models.WorkloadResourceStat, n int, less func(a, b models.WorkloadResourceStat) bool) []models.WorkloadResourceStat {
	if len(in) == 0 || n <= 0 {
		return nil
	}
	cp := append([]models.WorkloadResourceStat(nil), in...)
	sort.SliceStable(cp, func(i, j int) bool { return less(cp[i], cp[j]) })
	if len(cp) > n {
		cp = cp[:n]
	}
	return cp
}

func topPolicyDrops(in []models.PolicyDropStat, n int) []models.PolicyDropStat {
	if len(in) == 0 || n <= 0 {
		return nil
	}
	cp := append([]models.PolicyDropStat(nil), in...)
	sort.SliceStable(cp, func(i, j int) bool { return cp[i].Packets > cp[j].Packets })
	if len(cp) > n {
		cp = cp[:n]
	}
	return cp
}

func topQdiscs(in []models.QdiscStat, n int) []models.QdiscStat {
	if len(in) == 0 || n <= 0 {
		return nil
	}
	cp := append([]models.QdiscStat(nil), in...)
	sort.SliceStable(cp, func(i, j int) bool { return cp[i].Drops > cp[j].Drops })
	if len(cp) > n {
		cp = cp[:n]
	}
	return cp
}

func capHostProcesses(in []models.HostProcessStat, n int) []models.HostProcessStat {
	if len(in) == 0 || n <= 0 {
		return nil
	}
	if len(in) > n {
		in = in[:n]
	}
	return append([]models.HostProcessStat(nil), in...)
}

func topKernelDrops(in []models.KernelDropStat, n int) []models.KernelDropStat {
	if len(in) == 0 || n <= 0 {
		return nil
	}
	cp := append([]models.KernelDropStat(nil), in...)
	sort.SliceStable(cp, func(i, j int) bool { return cp[i].Count > cp[j].Count })
	if len(cp) > n {
		cp = cp[:n]
	}
	for i := range cp {
		if cp[i].ReasonName == "" {
			cp[i].ReasonName = dropreason.Name(cp[i].Reason)
		}
	}
	return cp
}
