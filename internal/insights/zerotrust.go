// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package insights

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/netip"
	"sort"
	"strings"

	"github.com/zyvorai/netra/internal/models"
	"github.com/zyvorai/netra/internal/policy"
)

// ZeroTrustDraft is a review-only allow-list / deny suggestion keyed by
// workload identity. Never applied automatically.
type ZeroTrustDraft struct {
	ID           string            `json:"id"`
	Namespace    string            `json:"namespace,omitempty"`
	WorkloadKind string            `json:"workloadKind,omitempty"`
	WorkloadName string            `json:"workloadName,omitempty"`
	Pod          string            `json:"pod,omitempty"`
	Selector     map[string]string `json:"selector,omitempty"`
	Kind         string            `json:"kind"` // allow_cidr | allow_sni | deny_external | review
	Title        string            `json:"title"`
	Rationale    []string          `json:"rationale"`
	Draft        map[string]any    `json:"draft"` // operation + args for operator/MCP
	Severity     string            `json:"severity"`
	Packets      uint64            `json:"packets,omitempty"`
}

// ZeroTrust builds identity-aware drafts from live dependency edges + SNI.
// Prefer PacketWolf/Cilium for durable NetPol; these are emergency/review
// drafts for Netra's leased deny / allow primitives.
func ZeroTrust(graph models.DependencyGraph, agents []models.AgentStatus, limit int) []ZeroTrustDraft {
	if limit <= 0 {
		limit = 50
	}
	nodeByID := map[string]models.DependencyNode{}
	for _, n := range graph.Nodes {
		nodeByID[n.ID] = n
	}
	selectorBySource := map[string]map[string]string{}
	sniBySource := map[string]map[string]uint64{}
	for _, a := range agents {
		if a.Stale {
			continue
		}
		for _, w := range a.Workloads {
			src := sourceKey(w.Namespace, w.Pod, w.WorkloadKind, w.WorkloadName, w.CgroupID)
			sel := policy.RecommendedSelector(w.Labels, strings.ToLower(w.WorkloadKind), w.Pod)
			if len(sel) > 0 {
				selectorBySource[src] = sel
			}
		}
		for _, t := range a.TLSMetadata {
			src := sourceKey(t.Namespace, t.Pod, t.WorkloadKind, t.WorkloadName, t.CgroupID)
			if sniBySource[src] == nil {
				sniBySource[src] = map[string]uint64{}
			}
			if t.SNI != "" {
				sniBySource[src][strings.ToLower(t.SNI)] += t.Handshakes
			}
		}
	}
	var out []ZeroTrustDraft
	seen := map[string]bool{}
	for _, e := range graph.Edges {
		src := nodeByID[e.Source]
		if src.ID == "" {
			continue
		}
		sel := selectorBySource[e.Source]
		if len(sel) == 0 {
			continue
		}
		tgt := nodeByID[e.Target]
		ip := tgt.IP
		if ip == "" {
			continue
		}
		addr, err := netip.ParseAddr(ip)
		if err != nil {
			continue
		}
		if !e.External && (addr.IsPrivate() || addr.IsLoopback() || addr.IsLinkLocalUnicast() || tgt.Kind == "workload" || tgt.Kind == "pod" || tgt.Kind == "service") {
			key := "allow|" + e.Source + "|" + addr.String() + "|" + e.Protocol
			if seen[key] {
				continue
			}
			seen[key] = true
			out = append(out, ZeroTrustDraft{
				ID: shortID(key), Namespace: src.Namespace, WorkloadKind: src.WorkloadKind, WorkloadName: src.Name,
				Selector: sel, Kind: "allow_cidr", Severity: "info", Packets: e.Packets,
				Title: fmt.Sprintf("Allow east-west %s → %s", src.Name, addr.String()),
				Rationale: []string{
					"Private/in-cluster destination observed under this workload identity",
					"Review-only draft; durable NetworkPolicy belongs on Cilium/PacketWolf when present",
				},
				Draft: map[string]any{
					"operation": "ebpf.allow-cidr.add",
					"cidr":      addr.String() + hostMask(addr),
					"direction": "egress",
					"selector":  sel,
				},
			})
		} else if e.External {
			key := "deny|" + e.Source + "|" + addr.String()
			if seen[key] {
				continue
			}
			seen[key] = true
			out = append(out, ZeroTrustDraft{
				ID: shortID(key), Namespace: src.Namespace, WorkloadKind: src.WorkloadKind, WorkloadName: src.Name,
				Selector: sel, Kind: "deny_external", Severity: "medium", Packets: e.Packets,
				Title: fmt.Sprintf("Review external egress %s → %s", src.Name, addr.String()),
				Rationale: []string{
					"External destination under this workload identity",
					"Optional leased deny for emergency containment — not a standing allow-list",
				},
				Draft: map[string]any{
					"operation": "ebpf.deny.add",
					"ip":        addr.String(),
					"direction": "egress",
				},
			})
		}
		if len(out) >= limit {
			break
		}
	}
	// SNI allow suggestions per source (top hosts).
	srcs := make([]string, 0, len(sniBySource))
	for s := range sniBySource {
		srcs = append(srcs, s)
	}
	sort.Strings(srcs)
	for _, srcID := range srcs {
		if len(out) >= limit {
			break
		}
		sel := selectorBySource[srcID]
		if len(sel) == 0 {
			continue
		}
		n := nodeByID[srcID]
		type pair struct {
			h string
			c uint64
		}
		var hosts []pair
		for h, c := range sniBySource[srcID] {
			hosts = append(hosts, pair{h, c})
		}
		sort.Slice(hosts, func(i, j int) bool { return hosts[i].c > hosts[j].c })
		if len(hosts) > 3 {
			hosts = hosts[:3]
		}
		for _, h := range hosts {
			key := "sni|" + srcID + "|" + h.h
			if seen[key] {
				continue
			}
			seen[key] = true
			name := n.Name
			if name == "" {
				name = srcID
			}
			out = append(out, ZeroTrustDraft{
				ID: shortID(key), Namespace: n.Namespace, WorkloadKind: n.Kind, WorkloadName: n.Name,
				Selector: sel, Kind: "allow_sni", Severity: "info", Packets: h.c,
				Title: fmt.Sprintf("Document TLS destination %s for %s", h.h, name),
				Rationale: []string{
					"Observed SNI under this workload identity",
					"Use as allow-list documentation or Cilium toFQDNs input — Netra SNI deny is emergency-only",
				},
				Draft: map[string]any{
					"operation": "review.sni.allowlist",
					"name":      h.h,
					"selector":  sel,
				},
			})
			if len(out) >= limit {
				break
			}
		}
	}
	return out
}

func hostMask(a netip.Addr) string {
	if a.Is4() {
		return "/32"
	}
	return "/128"
}

func shortID(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:8])
}
