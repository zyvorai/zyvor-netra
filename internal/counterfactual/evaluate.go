// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package counterfactual

import (
	"context"
	"fmt"
	"slices"
	"sort"
	"time"
)

// DenialGroup aggregates every observed flow that a policy would have
// denied into one bucket, keyed by the reason it would have been denied
// and the destination it was headed to.
type DenialGroup struct {
	Reason      Reason      `json:"reason"`
	Destination string      `json:"destination"`
	Workload    WorkloadRef `json:"workload"`
	Direction   Direction   `json:"direction"`

	FlowCount    int       `json:"flowCount"`
	FirstSeen    time.Time `json:"firstSeen"`
	LastSeen     time.Time `json:"lastSeen"`
	TotalBytes   uint64    `json:"totalBytes"`
	TotalPackets uint64    `json:"totalPackets"`
}

// BreakageGroup summarizes the denials attributed to a single workload,
// answering "what would this workload have lost."
type BreakageGroup struct {
	Workload     WorkloadRef   `json:"workload"`
	Destinations []string      `json:"destinations"`
	Denials      []DenialGroup `json:"denials"`
}

// Result is the outcome of evaluating a policy against a window of flow
// history.
type Result struct {
	PolicyName  string          `json:"policyName"`
	PolicyHash  string          `json:"policyHash"`
	Window      Query           `json:"window"`
	EvaluatedAt time.Time       `json:"evaluatedAt"`
	FlowsSeen   int             `json:"flowsSeen"`
	Denials     []DenialGroup   `json:"denials"`
	Breakage    []BreakageGroup `json:"breakage"`
}

// Evaluator runs a Policy against flows pulled from a Store.
type Evaluator struct {
	store Store
}

// NewEvaluator returns an Evaluator reading flows from store.
func NewEvaluator(store Store) *Evaluator {
	return &Evaluator{store: store}
}

// Evaluate fetches flows matching q from the evaluator's Store, runs
// policy against each, and groups the denials.
func (e *Evaluator) Evaluate(ctx context.Context, policy *Policy, q Query) (*Result, error) {
	if e.store == nil {
		return nil, fmt.Errorf("counterfactual: evaluator has no store")
	}
	flows, err := e.store.Query(ctx, q)
	if err != nil {
		return nil, fmt.Errorf("query store: %w", err)
	}
	return EvaluateFlows(policy, flows, q)
}

// EvaluateFlows runs policy against an already-fetched slice of flows.
// Exposed directly so callers holding flows in memory (tests, or a
// caller that fetched once and wants several policy comparisons) don't
// need a Store at all.
func EvaluateFlows(policy *Policy, flows []Flow, q Query) (*Result, error) {
	cp, err := policy.Validate()
	if err != nil {
		return nil, fmt.Errorf("validate policy: %w", err)
	}
	hash, err := policy.Hash()
	if err != nil {
		return nil, fmt.Errorf("hash policy: %w", err)
	}

	groups := map[string]*DenialGroup{}
	breakageByWorkload := map[string]*BreakageGroup{}

	for _, f := range flows {
		verdict, reason := cp.Evaluate(f)
		if verdict != VerdictDeny {
			continue
		}

		key := fmt.Sprintf("%s|%s|%s", reason.Describe(), f.Workload.Key(), f.DestinationString())
		g, ok := groups[key]
		if !ok {
			g = &DenialGroup{
				Reason:      reason,
				Destination: f.DestinationString(),
				Workload:    f.Workload,
				Direction:   f.Direction,
				FirstSeen:   f.Timestamp,
				LastSeen:    f.Timestamp,
			}
			groups[key] = g
		}
		g.FlowCount++
		g.TotalBytes += f.Bytes
		g.TotalPackets += f.Packets
		if f.Timestamp.Before(g.FirstSeen) {
			g.FirstSeen = f.Timestamp
		}
		if f.Timestamp.After(g.LastSeen) {
			g.LastSeen = f.Timestamp
		}

		wKey := f.Workload.Key()
		bg, ok := breakageByWorkload[wKey]
		if !ok {
			bg = &BreakageGroup{Workload: f.Workload}
			breakageByWorkload[wKey] = bg
		}
	}

	denials := make([]DenialGroup, 0, len(groups))
	for _, g := range groups {
		denials = append(denials, *g)
	}
	sort.Slice(denials, func(i, j int) bool {
		if denials[i].FlowCount != denials[j].FlowCount {
			return denials[i].FlowCount > denials[j].FlowCount
		}
		return denials[i].Destination < denials[j].Destination
	})

	for i := range denials {
		d := denials[i]
		bg := breakageByWorkload[d.Workload.Key()]
		bg.Denials = append(bg.Denials, d)
		bg.Destinations = appendUnique(bg.Destinations, d.Destination)
	}

	breakage := make([]BreakageGroup, 0, len(breakageByWorkload))
	for _, bg := range breakageByWorkload {
		breakage = append(breakage, *bg)
	}
	sort.Slice(breakage, func(i, j int) bool {
		return breakage[i].Workload.Key() < breakage[j].Workload.Key()
	})

	return &Result{
		PolicyName:  policy.Name,
		PolicyHash:  hash,
		Window:      q,
		EvaluatedAt: time.Now().UTC(),
		FlowsSeen:   len(flows),
		Denials:     denials,
		Breakage:    breakage,
	}, nil
}

func appendUnique(s []string, v string) []string {
	if slices.Contains(s, v) {
		return s
	}
	return append(s, v)
}
