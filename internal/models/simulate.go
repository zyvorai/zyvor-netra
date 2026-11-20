// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package models

import "time"

// PolicySimulationResult is one observed dependency-graph edge evaluated
// against a candidate policy's egress rules. Verdict is "allowed",
// "denied", or "unverified" — "unverified" must be used whenever a
// toFQDNs (or an unresolvable toEndpoints) rule means the true answer
// can't be confirmed, never a guessed "denied".
type PolicySimulationResult struct {
	Source   string `json:"source"`
	Target   string `json:"target"`
	Protocol string `json:"protocol"`
	Port     uint16 `json:"port,omitempty"`
	Verdict  string `json:"verdict"`
	Reason   string `json:"reason"`
}

// PolicySimulation is internal/insights.Simulate's result: every observed
// edge from a workload the candidate's endpointSelector governs, each
// evaluated against the candidate's egress rules.
type PolicySimulation struct {
	GeneratedAt     time.Time                `json:"generatedAt"`
	Namespace       string                   `json:"namespace"`
	Name            string                   `json:"name"`
	GovernedSources int                      `json:"governedSources"`
	Results         []PolicySimulationResult `json:"results"`
	Caveat          string                   `json:"caveat"`
	Note            string                   `json:"note,omitempty"`
}
