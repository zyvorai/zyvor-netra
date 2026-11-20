// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
//
// Package coverage builds a hook/program coverage matrix from already
// reported AgentStatus values. Observe-only: it never attaches or
// detaches anything.
package coverage

import (
	"sort"
	"time"

	"github.com/zyvorai/netra/internal/models"
)

type Program struct {
	Name     string `json:"name"`
	Type     string `json:"type,omitempty"`
	Attached bool   `json:"attached"`
	RunCount uint64 `json:"runCount,omitempty"`
}

type Node struct {
	Node         string    `json:"node"`
	Stale        bool      `json:"stale"`
	Mode         string    `json:"mode,omitempty"`
	AgeSeconds   int64     `json:"ageSeconds"`
	Hooks        []string  `json:"hooks,omitempty"`
	Programs     []Program `json:"programs,omitempty"`
	Attached     int       `json:"attached"`
	Detached     []string  `json:"detached,omitempty"`
	MissingMaps  []string  `json:"missingMaps,omitempty"`
	HookCount    int       `json:"hookCount"`
	ProgramCount int       `json:"programCount"`
}

type Matrix struct {
	GeneratedAt       time.Time `json:"generatedAt"`
	Nodes             []Node    `json:"nodes"`
	AgentCount        int       `json:"agentCount"`
	StaleAgents       int       `json:"staleAgents"`
	DetachedPrograms  int       `json:"detachedPrograms"`
	MissingMapEntries int       `json:"missingMapEntries"`
	Quiet             bool      `json:"quiet"`
}

// Build is deterministic given agents and now.
func Build(agents []models.AgentStatus, now time.Time) Matrix {
	if now.IsZero() {
		now = time.Now().UTC()
	}
	out := Matrix{GeneratedAt: now.UTC(), Nodes: make([]Node, 0, len(agents))}
	for _, a := range agents {
		n := Node{
			Node:        a.Node,
			Stale:       a.Stale,
			Mode:        a.Mode,
			AgeSeconds:  a.AgeSeconds,
			Hooks:       append([]string(nil), a.Hooks...),
			MissingMaps: append([]string(nil), a.MissingMaps...),
			HookCount:   len(a.Hooks),
		}
		for _, p := range a.Programs {
			n.Programs = append(n.Programs, Program{Name: p.Name, Type: p.Type, Attached: p.Attached, RunCount: p.RunCount})
			if p.Attached {
				n.Attached++
			} else if p.Name != "" {
				n.Detached = append(n.Detached, p.Name)
			}
		}
		n.ProgramCount = len(n.Programs)
		sort.Strings(n.Detached)
		if a.Stale {
			out.StaleAgents++
		}
		out.DetachedPrograms += len(n.Detached)
		out.MissingMapEntries += len(n.MissingMaps)
		out.Nodes = append(out.Nodes, n)
	}
	sort.Slice(out.Nodes, func(i, j int) bool { return out.Nodes[i].Node < out.Nodes[j].Node })
	out.AgentCount = len(out.Nodes)
	out.Quiet = out.StaleAgents == 0 && out.DetachedPrograms == 0 && out.MissingMapEntries == 0
	return out
}
