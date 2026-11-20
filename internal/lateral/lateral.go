// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

// Package lateral turns scan/lateral-movement findings into review-only
// incident→lease playbooks. Never auto-applies.
package lateral

import (
	"fmt"
	"sort"
	"time"

	"github.com/zyvorai/netra/internal/scandetect"
)

// Playbook is one guided containment suggestion.
type Playbook struct {
	ID          string           `json:"id"`
	FindingType string           `json:"findingType"`
	Severity    string           `json:"severity"`
	Namespace   string           `json:"namespace,omitempty"`
	Pod         string           `json:"pod,omitempty"`
	Workload    string           `json:"workload,omitempty"`
	Node        string           `json:"node,omitempty"`
	Title       string           `json:"title"`
	Steps       []string         `json:"steps"`
	LeaseDrafts []map[string]any `json:"leaseDrafts"`
	ExampleDsts []string         `json:"exampleDsts,omitempty"`
	FindingID   string           `json:"findingId,omitempty"`
}

// Result is GET /api/v1/insights/lateral.
type Result struct {
	GeneratedAt time.Time  `json:"generatedAt"`
	Playbooks   []Playbook `json:"playbooks"`
	Count       int        `json:"count"`
	Note        string     `json:"note"`
}

const MaxPlaybooks = 50

// Build maps scandetect findings to playbooks.
func Build(findings []scandetect.Finding, limit int) Result {
	now := time.Now().UTC()
	if limit <= 0 || limit > MaxPlaybooks {
		limit = MaxPlaybooks
	}
	out := Result{
		GeneratedAt: now,
		Playbooks:   []Playbook{},
		Note:        "Review-only lateral-movement playbooks. Open an enforce lease before applying drafts; fails open when lease ends.",
	}
	for _, f := range findings {
		if len(out.Playbooks) >= limit {
			break
		}
		if f.Type != scandetect.FindingLateral && f.Type != scandetect.FindingPortScan &&
			f.Type != scandetect.FindingFanOut && f.Type != scandetect.FindingSYNFlood {
			continue
		}
		pb := Playbook{
			ID: fmt.Sprintf("lat-%s", f.ID), FindingType: string(f.Type), Severity: string(f.Severity),
			Namespace: f.Namespace, Pod: f.Pod, Workload: f.Workload, Node: f.Node,
			FindingID: f.ID, ExampleDsts: f.ExampleDsts,
		}
		switch f.Type {
		case scandetect.FindingSYNFlood:
			pb.Title = "SYN-flood / volumetric pressure"
			pb.Steps = []string{
				"Confirm enforce lease is active (or open a short one)",
				"Apply conn-rate limit on the source workload",
				"Optionally lower Shield SYN PPS ceiling",
				"Watch GET /api/v1/ebpf/scan-findings until clear",
			}
			pb.LeaseDrafts = []map[string]any{
				{"operation": "conn-rate-limit", "perSecond": 10, "namespace": f.Namespace, "pod": f.Pod},
				{"operation": "shield-syn-pps", "hint": "NETRA_AUTOMITIGATE_SHIELD_SYN_PPS or ebpf shield"},
			}
		case scandetect.FindingPortScan:
			pb.Title = "Port-scan pattern"
			pb.Steps = []string{
				"Review example destinations and confirm not a health-prober",
				"Open enforce lease",
				"Apply conn-rate limit; consider deny of scanner source if external",
				"Escalate durable NetPol to PacketWolf if east-west",
			}
			pb.LeaseDrafts = []map[string]any{
				{"operation": "conn-rate-limit", "perSecond": 5, "namespace": f.Namespace, "pod": f.Pod},
			}
		case scandetect.FindingFanOut:
			pb.Title = "Destination fan-out"
			pb.Steps = []string{
				"Compare with insights/exfil for the same workload",
				"Open enforce lease if containment needed",
				"Conn-rate limit; draft SNI/DNS denies for rare hosts after review",
			}
			pb.LeaseDrafts = []map[string]any{
				{"operation": "conn-rate-limit", "perSecond": 8, "namespace": f.Namespace, "pod": f.Pod},
			}
		default: // lateral
			pb.Title = "Lateral-movement pattern"
			pb.Steps = []string{
				"Confirm private-range fan-out is unexpected",
				"Prefer PacketWolf/Cilium for durable east-west deny",
				"Use Netra leased conn-rate / deny only for incident window",
				"Review insights/microseg and zero-trust drafts",
			}
			pb.LeaseDrafts = []map[string]any{
				{"operation": "conn-rate-limit", "perSecond": 5, "namespace": f.Namespace, "pod": f.Pod},
				{"operation": "review", "hint": "GET /api/v1/insights/microseg"},
			}
		}
		out.Playbooks = append(out.Playbooks, pb)
	}
	sort.Slice(out.Playbooks, func(i, j int) bool {
		return out.Playbooks[i].Severity > out.Playbooks[j].Severity
	})
	out.Count = len(out.Playbooks)
	return out
}
