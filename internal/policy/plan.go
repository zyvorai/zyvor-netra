// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package policy

import (
	"encoding/json"
	"fmt"
	"reflect"
	"sort"
	"strings"
)

// ChangePlan is a human-oriented summary of a proposed CiliumNetworkPolicy update.
// It deliberately focuses on the parts that most often surprise operators: selector
// scope, egress default-deny activation and destination allow-list removals.
type ChangePlan struct {
	Namespace           string   `json:"namespace"`
	Name                string   `json:"name"`
	Exists              bool     `json:"exists"`
	Risk                string   `json:"risk"`
	Changes             []string `json:"changes"`
	Warnings            []string `json:"warnings"`
	AddedDestinations   []string `json:"addedDestinations"`
	RemovedDestinations []string `json:"removedDestinations"`
	CurrentEgressRules  int      `json:"currentEgressRules"`
	ProposedEgressRules int      `json:"proposedEgressRules"`
	SelectorChanged     bool     `json:"selectorChanged"`
	SpecChanged         bool     `json:"specChanged"`
}

type policyRule struct {
	EndpointSelector map[string]any   `json:"endpointSelector"`
	Egress           []map[string]any `json:"egress"`
}

type policyDoc struct {
	Metadata struct {
		Name      string `json:"name"`
		Namespace string `json:"namespace"`
	} `json:"metadata"`
	Spec  *policyRule  `json:"spec"`
	Specs []policyRule `json:"specs"`
}

// AnalyzeChange compares a live CNP with a candidate. current may be nil when the
// policy does not exist yet. It is intentionally independent from Kubernetes so it
// can be tested deterministically and reused by the API/CLI.
func AnalyzeChange(current, candidate []byte) (ChangePlan, error) {
	var next policyDoc
	if err := json.Unmarshal(candidate, &next); err != nil {
		return ChangePlan{}, fmt.Errorf("candidate policy must be JSON: %w", err)
	}
	if strings.TrimSpace(next.Metadata.Name) == "" {
		return ChangePlan{}, fmt.Errorf("metadata.name is required")
	}
	if next.Metadata.Namespace == "" {
		next.Metadata.Namespace = "default"
	}

	nextRules := rules(next)
	plan := ChangePlan{
		Namespace:           next.Metadata.Namespace,
		Name:                next.Metadata.Name,
		Risk:                "low",
		ProposedEgressRules: egressCount(nextRules),
		// Non-nil so the JSON response always carries "[]" rather than "null" —
		// a nil slice here previously crashed the dashboard's Policies page
		// (Preflight on a brand-new policy left RemovedDestinations nil, and
		// the frontend unconditionally reads .length on these fields).
		Changes:             []string{},
		Warnings:            []string{},
		AddedDestinations:   []string{},
		RemovedDestinations: []string{},
	}
	if len(nextRules) == 0 {
		plan.Warnings = append(plan.Warnings, "policy contains neither spec nor specs; Kubernetes dry-run is expected to reject or normalize it")
		elevate(&plan, "high")
	}
	for _, r := range nextRules {
		if len(r.EndpointSelector) == 0 {
			plan.Risk = "critical"
			plan.Warnings = appendUnique(plan.Warnings, "an endpointSelector is empty; this can select every endpoint in the namespace")
		}
	}

	proposedDest := destinationSet(nextRules)
	if len(current) == 0 {
		plan.Changes = append(plan.Changes, "Create new CiliumNetworkPolicy")
		if plan.ProposedEgressRules > 0 {
			plan.Warnings = append(plan.Warnings, "a new egress-selecting Cilium policy can place matching endpoints into egress default-deny")
			elevate(&plan, "medium")
		}
		plan.AddedDestinations = sortedKeys(proposedDest)
		return plan, nil
	}

	var old policyDoc
	if err := json.Unmarshal(current, &old); err != nil {
		return ChangePlan{}, fmt.Errorf("current policy must be JSON: %w", err)
	}
	oldRules := rules(old)
	plan.Exists = true
	plan.CurrentEgressRules = egressCount(oldRules)
	plan.SelectorChanged = !reflect.DeepEqual(selectorSet(oldRules), selectorSet(nextRules))
	if plan.SelectorChanged {
		plan.Changes = append(plan.Changes, "Endpoint selector set changes")
		plan.Warnings = append(plan.Warnings, "selector changes can move policy enforcement to a different workload set")
		elevate(&plan, "high")
	}

	currentDest := destinationSet(oldRules)
	for d := range proposedDest {
		if _, ok := currentDest[d]; !ok {
			plan.AddedDestinations = append(plan.AddedDestinations, d)
		}
	}
	for d := range currentDest {
		if _, ok := proposedDest[d]; !ok {
			plan.RemovedDestinations = append(plan.RemovedDestinations, d)
		}
	}
	sort.Strings(plan.AddedDestinations)
	sort.Strings(plan.RemovedDestinations)
	if len(plan.AddedDestinations) > 0 {
		plan.Changes = append(plan.Changes, fmt.Sprintf("Add %d destination allowance(s)", len(plan.AddedDestinations)))
	}
	if len(plan.RemovedDestinations) > 0 {
		plan.Changes = append(plan.Changes, fmt.Sprintf("Remove %d destination allowance(s)", len(plan.RemovedDestinations)))
		plan.Warnings = append(plan.Warnings, "removed destination allowances can immediately break existing egress connections")
		elevate(&plan, "high")
	}
	if plan.CurrentEgressRules != plan.ProposedEgressRules {
		plan.Changes = append(plan.Changes, fmt.Sprintf("Egress rule count %d → %d", plan.CurrentEgressRules, plan.ProposedEgressRules))
	}

	var oldRaw, newRaw map[string]any
	_ = json.Unmarshal(current, &oldRaw)
	_ = json.Unmarshal(candidate, &newRaw)
	plan.SpecChanged = !reflect.DeepEqual(policyBody(oldRaw), policyBody(newRaw))
	if !plan.SpecChanged {
		plan.Changes = append(plan.Changes, "No policy rule change detected")
	} else if len(plan.Changes) == 0 {
		plan.Changes = append(plan.Changes, "Policy rules change outside the summarized destination/selector fields")
		elevate(&plan, "medium")
	}
	return plan, nil
}

func rules(doc policyDoc) []policyRule {
	out := make([]policyRule, 0, len(doc.Specs))
	if doc.Spec != nil {
		out = append(out, *doc.Spec)
	}
	out = append(out, doc.Specs...)
	return out
}

func egressCount(rules []policyRule) int {
	n := 0
	for _, r := range rules {
		n += len(r.Egress)
	}
	return n
}

func selectorSet(rules []policyRule) []string {
	out := make([]string, 0, len(rules))
	for _, r := range rules {
		b, _ := json.Marshal(r.EndpointSelector)
		out = append(out, string(b))
	}
	sort.Strings(out)
	return out
}

func policyBody(doc map[string]any) map[string]any {
	return map[string]any{"spec": doc["spec"], "specs": doc["specs"]}
}

func destinationSet(rules []policyRule) map[string]struct{} {
	out := map[string]struct{}{}
	for _, r := range rules {
		for _, rule := range r.Egress {
			collectNamed(out, rule, "toFQDNs", "matchName", "fqdn:")
			collectNamed(out, rule, "toFQDNs", "matchPattern", "fqdn-pattern:")
			collectStringList(out, rule, "toCIDR", "cidr:")
			collectNamed(out, rule, "toCIDRSet", "cidr", "cidr:")
			collectStringList(out, rule, "toEntities", "entity:")
		}
	}
	return out
}

func collectNamed(out map[string]struct{}, rule map[string]any, field, key, prefix string) {
	items, _ := rule[field].([]any)
	for _, raw := range items {
		item, _ := raw.(map[string]any)
		if v, ok := item[key].(string); ok && strings.TrimSpace(v) != "" {
			out[prefix+v] = struct{}{}
		}
	}
}
func collectStringList(out map[string]struct{}, rule map[string]any, field, prefix string) {
	items, _ := rule[field].([]any)
	for _, raw := range items {
		if v, ok := raw.(string); ok && strings.TrimSpace(v) != "" {
			out[prefix+v] = struct{}{}
		}
	}
}
func sortedKeys(m map[string]struct{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
func appendUnique(items []string, value string) []string {
	for _, item := range items {
		if item == value {
			return items
		}
	}
	return append(items, value)
}
func elevate(plan *ChangePlan, risk string) {
	rank := map[string]int{"low": 0, "medium": 1, "high": 2, "critical": 3}
	if rank[risk] > rank[plan.Risk] {
		plan.Risk = risk
	}
}
