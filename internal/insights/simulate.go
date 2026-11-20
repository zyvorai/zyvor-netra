// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package insights

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/zyvorai/netra/internal/kube"
	"github.com/zyvorai/netra/internal/models"
	"github.com/zyvorai/netra/internal/policy"
)

// SimulationCaveat must accompany every Simulate result surfaced to a user.
// This evaluates a candidate CNP against the observed dependency graph, not
// a live Cilium admission/eBPF datapath — it is evidence for review, not a
// dry-run through the real enforcement engine. It also only understands
// matchLabels selectors (no matchExpressions) and egress rules (no ingress).
const SimulationCaveat = "Evaluated against the observed dependency graph and live workload labels, not the real Cilium/eBPF datapath — evidence for review, not a substitute for Preflight/dry-run. Only matchLabels selectors and egress rules are understood (no matchExpressions, no ingress)."

// Simulate resolves candidate's endpointSelector against live workload
// labels (reusing policy.PolicyMatchesLabels — no new matching logic) to
// find which observed dependency-graph edges it would govern, then
// evaluates each edge against candidate's egress rules:
//
//   - toCIDR/toCIDRSet and toEntities (world/cluster) are precisely
//     computable from the graph's existing IP/kind data.
//   - toServices/toEndpoints resolve via graph node kind and live labels.
//   - toFQDNs can never be precisely verified — there is no existing
//     correlation from a resolved DNS/SNI name to the specific destination
//     IP that resolved from it — so any edge a policy's other rules don't
//     already cover is marked "unverified", never a false "denied", the
//     moment the candidate contains any toFQDNs rule at all. This matters
//     because Recommendations() itself frequently emits toFQDNs rules, so
//     the simulator will often have to say "unverified" for exactly the
//     kind of rule the recommendation engine likes to produce — ship that
//     honestly rather than hide the gap.
func Simulate(candidate []byte, graph models.DependencyGraph, agents []models.AgentStatus) (models.PolicySimulation, error) {
	ns, name, err := kube.ExtractIdentity(candidate)
	if err != nil {
		return models.PolicySimulation{}, fmt.Errorf("candidate policy must be a JSON CiliumNetworkPolicy: %w", err)
	}
	rules, err := parseEgressRules(candidate)
	if err != nil {
		return models.PolicySimulation{}, err
	}

	labelsBySource := map[string]map[string]string{}
	governedSources := map[string]bool{}
	for _, a := range agents {
		if a.Stale {
			continue
		}
		for _, w := range a.Workloads {
			if len(w.Labels) == 0 {
				continue
			}
			src := sourceKey(w.Namespace, w.Pod, w.WorkloadKind, w.WorkloadName, w.CgroupID)
			labelsBySource[src] = w.Labels
			if policy.PolicyMatchesLabels(candidate, w.Labels) {
				governedSources[src] = true
			}
		}
	}

	nodeByID := make(map[string]models.DependencyNode, len(graph.Nodes))
	for _, n := range graph.Nodes {
		nodeByID[n.ID] = n
	}

	out := models.PolicySimulation{GeneratedAt: time.Now().UTC(), Namespace: ns, Name: name, GovernedSources: len(governedSources), Caveat: SimulationCaveat}
	if len(governedSources) == 0 {
		out.Note = "no live workload's labels matched this policy's endpointSelector — either nothing is exposed to it yet, or the selector uses label keys this cluster's workloads don't carry"
		return out, nil
	}
	for _, e := range graph.Edges {
		if !governedSources[e.Source] {
			continue
		}
		target := nodeByID[e.Target]
		verdict, reason := evaluateEdge(rules, target, labelsBySource[e.Target])
		out.Results = append(out.Results, models.PolicySimulationResult{
			Source: e.Source, Target: e.Target, Protocol: e.Protocol, Port: e.Port, Verdict: verdict, Reason: reason,
		})
	}
	return out, nil
}

type parsedEgressRules struct {
	cidrs     []netip.Prefix
	entities  []string
	fqdns     bool
	services  []serviceRef
	endpoints []map[string]string
}

type serviceRef struct{ namespace, name string }

func parseEgressRules(candidate []byte) (parsedEgressRules, error) {
	var doc struct {
		Spec *struct {
			Egress []map[string]any `json:"egress"`
		} `json:"spec"`
		Specs []struct {
			Egress []map[string]any `json:"egress"`
		} `json:"specs"`
	}
	if err := json.Unmarshal(candidate, &doc); err != nil {
		return parsedEgressRules{}, fmt.Errorf("candidate policy must be JSON: %w", err)
	}
	var rules []map[string]any
	if doc.Spec != nil {
		rules = append(rules, doc.Spec.Egress...)
	}
	for _, s := range doc.Specs {
		rules = append(rules, s.Egress...)
	}

	out := parsedEgressRules{}
	for _, r := range rules {
		for _, raw := range asList(r["toCIDR"]) {
			if s, ok := raw.(string); ok {
				if p, err := netip.ParsePrefix(s); err == nil {
					out.cidrs = append(out.cidrs, p)
				}
			}
		}
		for _, raw := range asList(r["toCIDRSet"]) {
			if m, ok := raw.(map[string]any); ok {
				if s, ok := m["cidr"].(string); ok {
					if p, err := netip.ParsePrefix(s); err == nil {
						out.cidrs = append(out.cidrs, p)
					}
				}
			}
		}
		for _, raw := range asList(r["toEntities"]) {
			if s, ok := raw.(string); ok {
				out.entities = append(out.entities, strings.ToLower(s))
			}
		}
		if len(asList(r["toFQDNs"])) > 0 {
			out.fqdns = true
		}
		for _, raw := range asList(r["toServices"]) {
			m, ok := raw.(map[string]any)
			if !ok {
				continue
			}
			k8sSvc, ok := m["k8sService"].(map[string]any)
			if !ok {
				continue
			}
			ns, _ := k8sSvc["namespace"].(string)
			name, _ := k8sSvc["serviceName"].(string)
			out.services = append(out.services, serviceRef{namespace: ns, name: name})
		}
		for _, raw := range asList(r["toEndpoints"]) {
			m, ok := raw.(map[string]any)
			if !ok {
				continue
			}
			ml, ok := m["matchLabels"].(map[string]any)
			if !ok {
				continue
			}
			set := map[string]string{}
			for k, v := range ml {
				if s, ok := v.(string); ok {
					set[strings.TrimPrefix(k, "k8s:")] = s
				}
			}
			if len(set) > 0 {
				out.endpoints = append(out.endpoints, set)
			}
		}
	}
	return out, nil
}

func asList(v any) []any {
	items, _ := v.([]any)
	return items
}

// evaluateEdge is the single source of truth for the one correctness
// property that matters most here: an edge only reachable through a
// toFQDNs rule (or an unresolvable toEndpoints rule) must come back
// "unverified", never "denied" — a false "denied" could make an operator
// wrongly trust a policy is safe to apply.
func evaluateEdge(rules parsedEgressRules, target models.DependencyNode, targetLabels map[string]string) (verdict, reason string) {
	if target.IP != "" {
		if addr, err := netip.ParseAddr(target.IP); err == nil {
			for _, p := range rules.cidrs {
				if p.Contains(addr) {
					return "allowed", fmt.Sprintf("matches a toCIDR/toCIDRSet rule (%s)", p)
				}
			}
		}
	}
	for _, e := range rules.entities {
		if e == "world" && target.Kind == "external" {
			return "allowed", "matches toEntities: world"
		}
		if e == "cluster" && target.Kind != "external" {
			return "allowed", "matches toEntities: cluster"
		}
	}
	if target.Kind == "service" {
		for _, svc := range rules.services {
			if svc.namespace == target.Namespace && svc.name == target.Name {
				return "allowed", "matches a toServices rule"
			}
		}
	}
	isWorkloadOrPod := target.Kind == "workload" || target.Kind == "pod"
	if isWorkloadOrPod && len(targetLabels) > 0 {
		for _, want := range rules.endpoints {
			if matchLabels(want, targetLabels) {
				return "allowed", "matches a toEndpoints rule"
			}
		}
	}
	if rules.fqdns {
		return "unverified", "could not verify — the policy includes toFQDNs rule(s) and there is no DNS/SNI→IP correlation to confirm or rule out a match against this destination"
	}
	if isWorkloadOrPod && len(targetLabels) == 0 && len(rules.endpoints) > 0 {
		return "unverified", "could not verify — the policy includes toEndpoints rule(s) but this destination's live labels are unknown"
	}
	return "denied", "no egress rule in this policy matches this destination"
}

func matchLabels(want, got map[string]string) bool {
	if len(want) == 0 {
		return false
	}
	for k, v := range want {
		if got[strings.TrimPrefix(k, "k8s:")] != v {
			return false
		}
	}
	return true
}
