//go:build linux

package agent

import (
	"sort"
	"time"

	"github.com/zyvorai/netra/internal/models"
	"github.com/zyvorai/netra/internal/sysres"
)

// readNodeResources samples host CPU/memory/load average plus every
// currently-known workload's cgroup v2 CPU/memory usage. CPU percentages
// are computed here, against the agent's own previous-tick sample
// (prevHostCPU/prevWorkloadCPU) — see those fields' doc comments on the
// Agent struct — rather than in internal/sysres.Build, which is
// stateless and has no prior sample to diff against.
func (a *Agent) readNodeResources() (models.NodeResourceSnapshot, models.HostProcessTops) {
	cur := sysres.Sample("/")
	now := time.Now()
	hadPrev := !a.prevResourceSampleAt.IsZero()
	host := sysres.HostSnapshot(a.prevHostCPU, cur, a.prevResourceSampleAt, now)
	elapsed := now.Sub(a.prevResourceSampleAt).Seconds()

	if a.prevWorkloadCPU == nil {
		a.prevWorkloadCPU = map[uint64]uint64{}
	}
	seen := make(map[uint64]struct{})
	var stats []models.WorkloadResourceStat
	for _, w := range a.workloadSnapshot() {
		if w.CgroupPath == "" {
			continue
		}
		ws, ok := sysres.SampleWorkload(w.CgroupPath)
		if !ok {
			continue
		}
		seen[w.CgroupID] = struct{}{}
		prevUsec, had := a.prevWorkloadCPU[w.CgroupID]
		a.prevWorkloadCPU[w.CgroupID] = ws.UsageUsec

		stat := models.WorkloadResourceStat{
			Node: a.node, Namespace: w.Namespace, Pod: w.Pod, WorkloadKind: w.WorkloadKind,
			WorkloadName: w.WorkloadName, ContainerID: w.ContainerID, CgroupID: w.CgroupID, CgroupPath: w.CgroupPath,
			MemoryUsedBytes: ws.MemoryUsedBytes, MemoryLimitBytes: ws.MemoryLimitBytes,
		}
		if had && elapsed > 0 && ws.UsageUsec >= prevUsec {
			stat.CPUPercent = float64(ws.UsageUsec-prevUsec) / 1e6 / elapsed * 100
		}
		stats = append(stats, stat)
	}
	// Prune cgroups for workloads that no longer exist so prevWorkloadCPU
	// doesn't grow unbounded across pod churn.
	for id := range a.prevWorkloadCPU {
		if _, ok := seen[id]; !ok {
			delete(a.prevWorkloadCPU, id)
		}
	}
	a.prevHostCPU, a.prevResourceSampleAt = cur, now

	procElapsed := 0.0
	if hadPrev && elapsed > 0 {
		procElapsed = elapsed
	}
	procs := sysres.SampleProcesses("/")
	byCPU, byRSS, nextProcs := sysres.TopHostProcesses(a.prevProcJiffies, procs, procElapsed)
	a.prevProcJiffies = nextProcs

	sort.Slice(stats, func(i, j int) bool { return stats[i].CPUPercent > stats[j].CPUPercent })
	return models.NodeResourceSnapshot{Host: host, Workloads: stats}, models.HostProcessTops{ByCPU: byCPU, ByMemory: byRSS}
}
