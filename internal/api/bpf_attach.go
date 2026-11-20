// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package api

import (
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/zyvorai/netra/internal/bpfattachdiag"
	"github.com/zyvorai/netra/internal/models"
)

// bpfAttachNode is one node's attachment inventory next to what its agent
// believes it attached.
type bpfAttachNode struct {
	Node         string    `json:"node"`
	ObservedAt   time.Time `json:"observedAt"`
	Stale        bool      `json:"stale"`
	Reporting    bool      `json:"reporting"`
	Unavailable  string    `json:"unavailable,omitempty"`
	Error        string    `json:"error,omitempty"`
	InventoryAt  time.Time `json:"inventoryAt,omitzero"`
	TCXSupported bool      `json:"tcxSupported"`
	// Hooks and Interfaces are what the agent believes; Attached is what the kernel reports.
	Hooks      []string                    `json:"hooks,omitempty"`
	Interfaces []string                    `json:"configuredInterfaces,omitempty"`
	Total      int                         `json:"total"`
	Truncated  int                         `json:"truncated,omitempty"`
	Failed     []string                    `json:"failed,omitempty"`
	Attached   []models.BPFInterfaceAttach `json:"attached,omitempty"`
}

// bpfAttachments serves GET /api/v1/ebpf/attachments?node=NAME: the BPF programs
// the kernel reports on each node's interfaces, and findings where they differ
// from what the agent believes it attached. Read-only; it observes and never
// attaches, detaches or replaces anything.
func (s *Server) bpfAttachments(w http.ResponseWriter, r *http.Request) {
	now := time.Now()
	agents := s.store.AgentStatuses(now, s.agentStaleAfter)
	if node := strings.TrimSpace(r.URL.Query().Get("node")); node != "" {
		agents = slices.DeleteFunc(agents, func(a models.AgentStatus) bool { return a.Node != node })
	}
	nodes := make([]bpfAttachNode, 0, len(agents))
	for _, a := range agents {
		n := bpfAttachNode{Node: a.Node, ObservedAt: a.ObservedAt, Stale: a.Stale, Hooks: a.Hooks, Interfaces: a.Interfaces}
		inv := a.BPFAttach
		switch {
		case inv == nil:
			n.Unavailable = "inventory off (NETRA_BPF_ATTACH=off) or agent predates it"
		case !inv.Available:
			n.Unavailable = inv.Unavailable
		default:
			n.Reporting, n.Error, n.InventoryAt = true, inv.Error, inv.ObservedAt
			n.TCXSupported, n.Total, n.Truncated, n.Failed = inv.TCXSupported, inv.Total, inv.Truncated, inv.Failed
			n.Attached = inv.Interfaces
			if inv.Unchanged {
				n.Unavailable = "the agent sent only a summary and the controller does not hold the list yet; it is re-sent within 5 minutes"
			}
		}
		nodes = append(nodes, n)
	}
	f := bpfattachdiag.Build(agents, now)
	writeJSON(w, http.StatusOK, map[string]any{
		"observedAt": now.UTC(), "nodes": nodes, "findings": f.Findings,
		"evaluated": f.Evaluated, "skipped": f.Skipped,
	})
}

// writeBPFAttachMetrics adds attachment gauges to /metrics. The only label is
// the finding severity, a fixed three-value set; interface and program names
// stay in the JSON API.
func writeBPFAttachMetrics(w http.ResponseWriter, agents []models.AgentStatus) {
	reporting, not, programmed := 0, 0, 0
	for _, a := range agents {
		if a.Stale {
			continue
		}
		if a.BPFAttach == nil || !a.BPFAttach.Available {
			not++
			continue
		}
		reporting++
		programmed += a.BPFAttach.Total
	}
	metricGauge(w, "netra_bpf_attach_nodes_reporting", "Fresh node agents reporting which BPF programs are attached to their interfaces.", float64(reporting))
	metricGauge(w, "netra_bpf_attach_nodes_not_reporting", "Fresh node agents not reporting an attachment inventory (off, older agent, or the kernel could not be read).", float64(not))
	if reporting == 0 {
		return
	}
	metricGauge(w, "netra_bpf_attach_interfaces", "Interfaces with at least one BPF program attached (XDP, TCX or classic tc), summed across reporting nodes.", float64(programmed))
	by := map[string]int{}
	for _, f := range bpfattachdiag.Build(agents, time.Now()).Findings {
		by[f.Severity]++
	}
	fmt.Fprint(w, "# HELP netra_bpf_attach_findings Active BPF attachment findings (a Netra hook the agent believes it has is no longer attached, XDP replaced, no interface hooks configured) by severity. Level-triggered.\n# TYPE netra_bpf_attach_findings gauge\n")
	for _, sev := range []string{"critical", "warning", "info"} {
		fmt.Fprintf(w, "netra_bpf_attach_findings{severity=\"%s\"} %d\n", sev, by[sev])
	}
}
