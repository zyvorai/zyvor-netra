// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package models

import (
	"encoding/json"
	"time"
)

// GitOpsManifestStatus is internal/gitops.Reconcile's per-manifest result.
type GitOpsManifestStatus struct {
	Path      string          `json:"path"`
	Namespace string          `json:"namespace"`
	Name      string          `json:"name"`
	Manifest  json.RawMessage `json:"manifest,omitempty"`
	// Plan is nil when Error is set (the manifest itself, or resolving its
	// identity, failed before a plan could be computed).
	Plan *ChangePlanRef `json:"plan,omitempty"`
	// Drifted is true when the live policy differs from the last
	// GitOps-applied revision (a hand-edit happened outside Git) — GitOps
	// never auto-applies over a drifted policy; POST
	// /api/v1/policies/gitops/resync is required to resolve it either way.
	Drifted bool   `json:"drifted"`
	Applied bool   `json:"applied"`
	Error   string `json:"error,omitempty"`
	Note    string `json:"note,omitempty"`
}

// ChangePlanRef mirrors internal/policy.ChangePlan's JSON shape without
// internal/models importing internal/policy (which itself imports models,
// so the reverse import would cycle). Field-for-field identical on the
// wire; internal/gitops converts.
type ChangePlanRef struct {
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

// GitOpsStatusResponse is GET /api/v1/policies/gitops/status's result: the
// most recent reconcile pass's computed status for every manifest under
// NETRA_GITOPS_DIR, regardless of whether anything was actually applied.
type GitOpsStatusResponse struct {
	LastRun    time.Time              `json:"lastRun"`
	Dir        string                 `json:"dir"`
	AutoApply  bool                   `json:"autoApply"`
	Manifests  []GitOpsManifestStatus `json:"manifests"`
	LoadErrors []string               `json:"loadErrors,omitempty"`
}
