// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

// Package detective correlates Netra policy-drop counters with deny configuration
// into exact vs probable findings (FluxVM Drop Detective pattern, standalone).
package detective

import (
	"fmt"
	"sort"
	"strings"

	"github.com/zyvorai/netra/internal/models"
)

const (
	ConfidenceExact    = "exact"
	ConfidenceProbable = "probable"
)

var reasonNames = map[uint8]string{
	1: "exact-ip-deny",
	2: "cidr-deny",
	3: "port-deny",
	4: "uid-deny",
	5: "rate-limit",
	6: "dns-deny",
	7: "process-deny",
	8: "sni-deny",
	9: "netpol-deny",
}

// ReasonName returns Netra's own name for a policy_drops reason code (1-9),
// or "" for an unrecognized code. Exported so other packages (e.g.
// internal/alert, for spike-alert message text) don't duplicate this table.
func ReasonName(reason uint8) string {
	return reasonNames[reason]
}

// Build correlates agent-reported policy drops into detective findings.
func Build(agents []models.AgentStatus, cfg models.EBPFFastPathConfig, topN int) models.DropDetectiveResponse {
	if topN <= 0 {
		topN = 50
	}
	out := models.DropDetectiveResponse{Findings: make([]models.DropDetectiveFinding, 0, 64)}
	for _, a := range agents {
		if a.Stale {
			continue
		}
		out.Summary.ConntrackEntries += uint64(a.ConntrackEntries)
		for _, d := range a.PolicyDrops {
			out.Summary.PolicyDropPackets += d.Packets
			out.Summary.PolicyDropFlows++
			f := models.DropDetectiveFinding{
				Node:       a.Node,
				Confidence: ConfidenceExact,
				Code:       reasonNames[d.Reason],
				Reason:     d.Reason,
				Family:     d.Family,
				Protocol:   d.Protocol,
				Direction:  d.Direction,
				Src:        formatEndpoint(d.SrcAddr, d.SrcPort),
				Dst:        formatEndpoint(d.DstAddr, d.DstPort),
				Packets:    d.Packets,
				Bytes:      d.Bytes,
				Stage:      "netra-policy/" + reasonNames[d.Reason],

				PID: d.PID, Comm: d.Comm, UID: d.UID,
				Namespace: d.Namespace, Pod: d.Pod,
				AttributionState: d.AttributionState,
			}
			if f.Code == "" {
				f.Code = fmt.Sprintf("reason-%d", d.Reason)
				f.Confidence = ConfidenceProbable
				f.Stage = "netra-policy/unknown"
			}
			f.Explanation = explain(d, cfg)
			f.Suggestion = suggest(d.Reason)
			out.Findings = append(out.Findings, f)
		}
	}
	sort.Slice(out.Findings, func(i, j int) bool {
		if out.Findings[i].Packets != out.Findings[j].Packets {
			return out.Findings[i].Packets > out.Findings[j].Packets
		}
		return out.Findings[i].Code < out.Findings[j].Code
	})
	if len(out.Findings) > topN {
		out.Findings = out.Findings[:topN]
	}
	exact, probable := 0, 0
	for _, f := range out.Findings {
		if f.Confidence == ConfidenceExact {
			exact++
		} else {
			probable++
		}
	}
	out.Summary.ExactFindings = exact
	out.Summary.ProbableFindings = probable
	if len(out.Findings) > 0 {
		out.Summary.Text = fmt.Sprintf("%d policy-drop finding(s); top cause %s (%d packet(s)).",
			len(out.Findings), out.Findings[0].Code, out.Findings[0].Packets)
	} else {
		out.Summary.Text = "No Netra policy-drop findings. Kernel/softnet drops remain on Drop Diagnostics."
	}
	return out
}

func formatEndpoint(addr string, port uint16) string {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return "?"
	}
	if port == 0 {
		return addr
	}
	if strings.Contains(addr, ":") {
		return fmt.Sprintf("[%s]:%d", addr, port)
	}
	return fmt.Sprintf("%s:%d", addr, port)
}

func explain(d models.PolicyDropStat, cfg models.EBPFFastPathConfig) string {
	name := reasonNames[d.Reason]
	dir := "egress"
	if d.Direction == 1 {
		dir = "ingress"
	}
	base := fmt.Sprintf("%s %s traffic matched Netra %s (%d packets).", dir, protoName(d.Protocol), name, d.Packets)
	if d.AttributionState == "attributed" {
		base += fmt.Sprintf(" Attributed to %s (pid %d)%s.", d.Comm, d.PID, podSuffix(d.Pod))
	}
	switch d.Reason {
	case 1:
		return base + " An exact IP deny is configured."
	case 2:
		return base + fmt.Sprintf(" %d CIDR deny rule(s) are staged.", len(cfg.BlockedCIDRs))
	case 3:
		return base + fmt.Sprintf(" %d port deny rule(s) are staged.", len(cfg.BlockedPorts))
	case 5:
		return base + " Destination PPS ceiling rejected the packet."
	case 9:
		return base + " A NetworkPolicy-shaped deny rule (distinct from a manually staged CIDR deny) rejected the packet."
	default:
		return base
	}
}

func suggest(reason uint8) string {
	switch reason {
	case 1, 2:
		return "Confirm the destination still needs containment, or remove the exact/CIDR deny after the incident."
	case 3:
		return "Permit only the required protocol/port pair, or clear the port deny."
	case 5:
		return "Raise the emergency PPS ceiling or narrow the protected destination set."
	case 6, 8:
		return "Review the DNS/SNI deny list for false positives before extending the lease."
	case 9:
		return "Review the NetworkPolicy-shaped deny rules (netpolDenies) for this workload, separate from any manual CIDR deny."
	default:
		return "Inspect eBPF config and recent audit events for the matching deny primitive."
	}
}

func podSuffix(pod string) string {
	if pod == "" {
		return ""
	}
	return fmt.Sprintf(" in pod %s", pod)
}

func protoName(p uint8) string {
	switch p {
	case 6:
		return "tcp"
	case 17:
		return "udp"
	case 1:
		return "icmp"
	case 58:
		return "icmpv6"
	default:
		return fmt.Sprintf("proto-%d", p)
	}
}
