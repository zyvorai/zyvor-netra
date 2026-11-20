// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package models

import "time"

// HostResourceSnapshot is one node's host-level "top" header-line
// equivalent: load average, CPU utilization, memory, and uptime.
//
// CPUPercent is a value the agent has already computed as a delta between
// two of its own 3s report ticks (see internal/agent's prevHostCPU) —
// unlike a sysctl setting, /proc/stat only exposes cumulative jiffies
// since boot, and internal/sysres.Build (the stateless, per-request
// aggregator) has no store/window access to diff them itself. It is 0 on
// an agent's first report after (re)start, since there is no prior
// sample yet. It is not per-core normalized, so it can exceed 100 on a
// multi-core node under full load.
type HostResourceSnapshot struct {
	LoadAvg1             float64 `json:"loadAvg1"`
	LoadAvg5             float64 `json:"loadAvg5"`
	LoadAvg15            float64 `json:"loadAvg15"`
	CPUCores             int     `json:"cpuCores"`
	CPUPercent           float64 `json:"cpuPercent"`
	MemoryTotalBytes     uint64  `json:"memoryTotalBytes"`
	MemoryUsedBytes      uint64  `json:"memoryUsedBytes"`
	MemoryAvailableBytes uint64  `json:"memoryAvailableBytes"`
	MemoryCachedBytes    uint64  `json:"memoryCachedBytes"`
	UptimeSeconds        uint64  `json:"uptimeSeconds"`
	Hostname             string  `json:"hostname,omitempty"`
	KernelRelease        string  `json:"kernelRelease,omitempty"`
}

// WorkloadResourceStat is one workload's cgroup v2 resource usage,
// attributed via the same identity WorkloadIdentity already carries — no
// new attribution join. CPUPercent is delta-computed the same way as
// HostResourceSnapshot.CPUPercent, from the workload's own previous
// cpu.stat usage_usec sample, keyed by CgroupID.
type WorkloadResourceStat struct {
	Node         string `json:"node,omitempty"`
	Namespace    string `json:"namespace,omitempty"`
	Pod          string `json:"pod,omitempty"`
	WorkloadKind string `json:"workloadKind,omitempty"`
	WorkloadName string `json:"workloadName,omitempty"`
	ContainerID  string `json:"containerId,omitempty"`
	CgroupID     uint64 `json:"cgroupId,omitempty"`
	CgroupPath   string `json:"cgroupPath,omitempty"`

	CPUPercent       float64 `json:"cpuPercent"`
	MemoryUsedBytes  uint64  `json:"memoryUsedBytes"`
	MemoryLimitBytes uint64  `json:"memoryLimitBytes,omitempty"` // 0 = unlimited ("max")
}

// NodeResourceSnapshot is the per-agent-report payload: this node's host
// snapshot plus every attributed workload's cgroup usage. This is the
// AgentReport field; NodeResources below is the API response's per-node
// row, which adds staleness/age on top of this same data.
type NodeResourceSnapshot struct {
	Host      HostResourceSnapshot   `json:"host"`
	Workloads []WorkloadResourceStat `json:"workloads,omitempty"`
}

// NodeResources is one node's row in NodeResourcesResponse.
type NodeResources struct {
	Node       string                 `json:"node"`
	Stale      bool                   `json:"stale"`
	AgeSeconds int64                  `json:"ageSeconds"`
	Host       HostResourceSnapshot   `json:"host"`
	Workloads  []WorkloadResourceStat `json:"workloads,omitempty"`
}

// NodeResourcesSummary is the cluster-wide aggregate across fresh
// (non-stale) nodes only — a stale node's frozen last-known CPU%/memory
// must not skew a live cluster average or a "highest" ranking.
type NodeResourcesSummary struct {
	Nodes             int     `json:"nodes"`
	TotalCPUCores     int     `json:"totalCpuCores"`
	AvgCPUPercent     float64 `json:"avgCpuPercent"`
	TotalMemoryBytes  uint64  `json:"totalMemoryBytes"`
	UsedMemoryBytes   uint64  `json:"usedMemoryBytes"`
	HighestCPUNode    string  `json:"highestCpuNode,omitempty"`
	HighestMemoryNode string  `json:"highestMemoryNode,omitempty"`
}

// NodeResourcesResponse is GET /api/v1/node-resources's shape.
type NodeResourcesResponse struct {
	GeneratedAt       time.Time              `json:"generatedAt"`
	Summary           NodeResourcesSummary   `json:"summary"`
	Nodes             []NodeResources        `json:"nodes"`
	TopWorkloadsByCPU []WorkloadResourceStat `json:"topWorkloadsByCpu,omitempty"`
	Limitations       []string               `json:"limitations"`
}
