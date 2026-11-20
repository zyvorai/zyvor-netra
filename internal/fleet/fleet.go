package fleet

import (
	"sort"
	"time"

	"github.com/zyvorai/netra/internal/models"
)

type Node struct {
	Node         string    `json:"node"`
	Mode         string    `json:"mode,omitempty"`
	Stale        bool      `json:"stale"`
	AgeSeconds   int64     `json:"ageSeconds"`
	ObservedAt   time.Time `json:"observedAt,omitempty"`
	Hooks        int       `json:"hooks"`
	Programs     int       `json:"programs"`
	Attached     int       `json:"attached"`
	Workloads    int       `json:"workloads"`
	Destinations int       `json:"destinations"`
	Events       int       `json:"events"`

	// Resource fields are an at-a-glance summary from internal/sysres —
	// see docs/node-resources.md for the full per-workload breakdown.
	// Zero-valued (and omitted from JSON) if the agent hasn't reported a
	// sample yet, which is indistinguishable here from "genuinely idle";
	// callers wanting to tell those apart should use GET
	// /api/v1/node-resources directly.
	CPUPercent       float64 `json:"cpuPercent,omitempty"`
	MemoryUsedBytes  uint64  `json:"memoryUsedBytes,omitempty"`
	MemoryTotalBytes uint64  `json:"memoryTotalBytes,omitempty"`
	LoadAvg1         float64 `json:"loadAvg1,omitempty"`
}

type Inventory struct {
	GeneratedAt time.Time `json:"generatedAt"`
	Nodes       []Node    `json:"nodes"`
	AgentCount  int       `json:"agentCount"`
	StaleAgents int       `json:"staleAgents"`
	Workloads   int       `json:"workloads"`
}

func Build(agents []models.AgentStatus, now time.Time) Inventory {
	if now.IsZero() {
		now = time.Now().UTC()
	}
	inv := Inventory{GeneratedAt: now.UTC(), Nodes: make([]Node, 0, len(agents))}
	for _, a := range agents {
		n := Node{
			Node: a.Node, Mode: a.Mode, Stale: a.Stale, AgeSeconds: a.AgeSeconds, ObservedAt: a.ObservedAt,
			Hooks: len(a.Hooks), Programs: len(a.Programs), Workloads: len(a.Workloads), Destinations: len(a.Stats), Events: len(a.Events),
			CPUPercent: a.NodeResources.Host.CPUPercent, MemoryUsedBytes: a.NodeResources.Host.MemoryUsedBytes,
			MemoryTotalBytes: a.NodeResources.Host.MemoryTotalBytes, LoadAvg1: a.NodeResources.Host.LoadAvg1,
		}
		for _, p := range a.Programs {
			if p.Attached {
				n.Attached++
			}
		}
		if a.Stale {
			inv.StaleAgents++
		}
		inv.Workloads += n.Workloads
		inv.Nodes = append(inv.Nodes, n)
	}
	sort.Slice(inv.Nodes, func(i, j int) bool { return inv.Nodes[i].Node < inv.Nodes[j].Node })
	inv.AgentCount = len(inv.Nodes)
	return inv
}
