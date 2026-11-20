// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package counterfactual

import (
	"context"
	"fmt"
	"time"
)

// WhenFirstSeen answers "when did this pattern first appear": the
// earliest Timestamp among stored flows attributed to workload that
// match destination (an exact match against Flow.DestinationString()).
// It reports ok=false when no matching flow exists in the store at all
// (not just within a particular query window).
func WhenFirstSeen(ctx context.Context, store Store, workload WorkloadRef, destination string) (t time.Time, ok bool, err error) {
	if store == nil {
		return time.Time{}, false, fmt.Errorf("counterfactual: nil store")
	}
	flows, err := store.Query(ctx, Query{Workload: workload.Key()})
	if err != nil {
		return time.Time{}, false, fmt.Errorf("query store: %w", err)
	}
	for _, f := range flows {
		if f.DestinationString() != destination {
			continue
		}
		if !ok || f.Timestamp.Before(t) {
			t, ok = f.Timestamp, true
		}
	}
	return t, ok, nil
}

// Comparison is the diff between two Results for the same flow window,
// used to show what changed between two candidate policies (or two
// revisions of the same policy).
type Comparison struct {
	Baseline *Result `json:"baseline"`
	Proposed *Result `json:"proposed"`

	// OnlyInProposed holds denial groups present in Proposed but not in
	// Baseline: newly introduced denials. Keyed the same way as
	// EvaluateFlows groups them (reason+workload+destination), compared
	// by Reason.Describe()+Workload.Key()+Destination.
	OnlyInProposed []DenialGroup `json:"onlyInProposed"`
	// OnlyInBaseline holds denial groups present in Baseline but not in
	// Proposed: denials the proposed policy would lift.
	OnlyInBaseline []DenialGroup `json:"onlyInBaseline"`
}

// Compare evaluates both policies against the same flows and window,
// returning the two Results plus the set difference between their
// denial groups.
func Compare(baseline, proposed *Policy, flows []Flow, q Query) (*Comparison, error) {
	baseRes, err := EvaluateFlows(baseline, flows, q)
	if err != nil {
		return nil, fmt.Errorf("evaluate baseline: %w", err)
	}
	propRes, err := EvaluateFlows(proposed, flows, q)
	if err != nil {
		return nil, fmt.Errorf("evaluate proposed: %w", err)
	}

	baseKeys := denialGroupKeys(baseRes.Denials)
	propKeys := denialGroupKeys(propRes.Denials)

	var onlyProposed, onlyBaseline []DenialGroup
	for i, k := range denialGroupKeySlice(propRes.Denials) {
		if _, ok := baseKeys[k]; !ok {
			onlyProposed = append(onlyProposed, propRes.Denials[i])
		}
	}
	for i, k := range denialGroupKeySlice(baseRes.Denials) {
		if _, ok := propKeys[k]; !ok {
			onlyBaseline = append(onlyBaseline, baseRes.Denials[i])
		}
	}

	return &Comparison{
		Baseline:       baseRes,
		Proposed:       propRes,
		OnlyInProposed: onlyProposed,
		OnlyInBaseline: onlyBaseline,
	}, nil
}

func denialGroupKeySlice(groups []DenialGroup) []string {
	keys := make([]string, len(groups))
	for i, g := range groups {
		keys[i] = fmt.Sprintf("%s|%s|%s", g.Reason.Describe(), g.Workload.Key(), g.Destination)
	}
	return keys
}

func denialGroupKeys(groups []DenialGroup) map[string]struct{} {
	out := make(map[string]struct{}, len(groups))
	for _, k := range denialGroupKeySlice(groups) {
		out[k] = struct{}{}
	}
	return out
}
