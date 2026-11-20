// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package insights

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/netip"
	"sort"
	"strconv"
	"strings"

	"github.com/zyvorai/netra/internal/models"
	"github.com/zyvorai/netra/internal/policy"
)

func Recommendations(graph models.DependencyGraph, agents []models.AgentStatus, namespace, workload string, limit int) []models.PolicyRecommendation {
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
	edgesBySource := map[string][]models.DependencyEdge{}
	for _, e := range graph.Edges {
		edgesBySource[e.Source] = append(edgesBySource[e.Source], e)
	}
	sourceIDs := make([]string, 0, len(edgesBySource))
	for src := range edgesBySource {
		sourceIDs = append(sourceIDs, src)
	}
	sort.Strings(sourceIDs)
	out := make([]models.PolicyRecommendation, 0)
	for _, src := range sourceIDs {
		n := nodeByID[src]
		if namespace != "" && n.Namespace != namespace {
			continue
		}
		if workload != "" && n.Name != workload {
			continue
		}
		selector := selectorBySource[src]
		if len(selector) == 0 {
			continue
		}
		egress := make([]any, 0)
		seen := map[string]bool{}
		for _, e := range edgesBySource[src] {
			proto := strings.ToUpper(e.Protocol)
			if e.Port == 0 || (proto != "TCP" && proto != "UDP") {
				continue
			}
			target := nodeByID[e.Target]
			key := e.Target + "|" + e.Protocol + "|" + strconv.Itoa(int(e.Port))
			if seen[key] {
				continue
			}
			seen[key] = true
			portRule := []any{map[string]any{"ports": []any{map[string]any{"port": int(e.Port), "protocol": proto}}}}
			if target.Kind == "service" {
				egress = append(egress, map[string]any{
					"toServices": []any{map[string]any{"k8sService": map[string]any{"serviceName": target.Name, "namespace": target.Namespace}}},
					"toPorts":    portRule,
				})
				continue
			}
			if target.IP == "" {
				continue
			}
			addr, err := netip.ParseAddr(target.IP)
			if err != nil {
				continue
			}
			bits := 128
			if addr.Is4() {
				bits = 32
			}
			egress = append(egress, map[string]any{
				"toCIDR":  []string{netip.PrefixFrom(addr, bits).String()},
				"toPorts": portRule,
			})
		}
		names := make([]string, 0, len(sniBySource[src]))
		for name, count := range sniBySource[src] {
			if count >= 2 {
				names = append(names, name)
			}
		}
		sort.Strings(names)
		for _, name := range names {
			egress = append(egress, map[string]any{
				"toFQDNs": []any{map[string]any{"matchName": name}},
				"toPorts": []any{map[string]any{"ports": []any{map[string]any{"port": 443, "protocol": "TCP"}}}},
			})
		}
		if len(egress) == 0 {
			continue
		}
		// DNS is required for FQDN rules and is usually required by applications even when
		// the observed graph contains only post-resolution IP traffic.
		egress = append(egress, map[string]any{
			"toEndpoints": []any{map[string]any{"matchLabels": map[string]string{"k8s:io.kubernetes.pod.namespace": "kube-system", "k8s:k8s-app": "kube-dns"}}},
			"toPorts":     []any{map[string]any{"ports": []any{map[string]any{"port": 53, "protocol": "UDP"}, map[string]any{"port": 53, "protocol": "TCP"}}}},
		})
		name := "netra-observed-egress-" + sanitizeName(n.Name)
		obj := map[string]any{
			"apiVersion": "cilium.io/v2", "kind": "CiliumNetworkPolicy",
			"metadata": map[string]any{"name": name, "namespace": n.Namespace, "annotations": map[string]string{
				"netra.zyvor.dev/generated": "observed-traffic", "netra.zyvor.dev/review-required": "true",
			}},
			"spec": map[string]any{"endpointSelector": map[string]any{"matchLabels": selector}, "egress": egress},
		}
		manifest, _ := json.MarshalIndent(obj, "", "  ")
		h := sha256.Sum256([]byte(src))
		out = append(out, models.PolicyRecommendation{
			ID: "rec-" + hex.EncodeToString(h[:6]), Kind: "cilium-egress-cnp", Namespace: n.Namespace,
			WorkloadKind: n.WorkloadKind, WorkloadName: n.Name, Confidence: "medium",
			Rationale: []string{
				"drafted from exact Netra eBPF dependency counters and observed TLS SNI",
				"observed traffic is not proof of complete application requirements; review and preflight before apply",
				"service targets use Cilium toServices; direct IP targets use exact CIDRs",
			},
			Manifest: manifest,
		})
		if len(out) >= limit {
			break
		}
	}
	return out
}

func sanitizeName(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	var b strings.Builder
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' {
			b.WriteRune(r)
		} else {
			b.WriteByte('-')
		}
	}
	out := strings.Trim(b.String(), "-")
	if out == "" {
		out = "workload"
	}
	if len(out) > 42 {
		out = out[:42]
	}
	return strings.TrimRight(out, "-")
}
