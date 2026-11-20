// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

// Package gitops is a mode of netrad, not a new binary or sidecar — it
// needs the same *kube.Client/*store.Store the elected leader already
// owns, and a separate process would need its own election or awkward IPC
// with the controller, both worse. It reads a local directory of YAML
// CiliumNetworkPolicy manifests (populated by an operator-supplied
// git-sync-style sidecar — the same pattern Argo CD/Flux use — which keeps
// netrad itself Git-agnostic) and reconciles them through the exact same
// plan/preflight/apply pipeline a human operator's Preflight → Apply click
// already uses, so GitOps applies land in the same audit trail and
// revision/rollback UI as manual applies. No parallel audit mechanism.
package gitops

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/zyvorai/netra/internal/kube"
	"github.com/zyvorai/netra/internal/models"
	"github.com/zyvorai/netra/internal/policy"
	"github.com/zyvorai/netra/internal/store"
	"gopkg.in/yaml.v3"
)

// Actor is recorded on every audit event/revision GitOps produces, the same
// way NETRA_MCP_ACTOR distinguishes agent-driven mutations from human
// netractl use, and is how detectDrift recognizes "the last GitOps-applied
// revision" among a policy's full history.
const Actor = "gitops"

// Manifest is one loaded, JSON-converted candidate policy.
type Manifest struct {
	Path string
	JSON []byte
}

// LoadManifests reads every *.yaml/*.yml file directly in dir (no
// recursion — matches git-sync's own flat checkout layout) and converts
// each YAML document to the JSON []byte shape internal/policy.AnalyzeChange
// already accepts. yaml.v3 (unlike yaml.v2) decodes mapping keys as plain
// strings, so the intermediate value round-trips through encoding/json
// without yaml.v2's map[interface{}]interface{} problem. A file that fails
// to read or parse is skipped with an entry in the returned error list —
// one bad file must never block reconciling every other manifest.
func LoadManifests(dir string) ([]Manifest, []string) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, []string{fmt.Sprintf("read gitops dir %s: %v", dir, err)}
	}
	var names []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		lower := strings.ToLower(e.Name())
		if strings.HasSuffix(lower, ".yaml") || strings.HasSuffix(lower, ".yml") {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)

	var out []Manifest
	var loadErrors []string
	for _, name := range names {
		raw, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			loadErrors = append(loadErrors, fmt.Sprintf("%s: %v", name, err))
			continue
		}
		dec := yaml.NewDecoder(strings.NewReader(string(raw)))
		for {
			var doc map[string]any
			if err := dec.Decode(&doc); err != nil {
				if errors.Is(err, io.EOF) {
					break
				}
				loadErrors = append(loadErrors, fmt.Sprintf("%s: %v", name, err))
				break
			}
			if len(doc) == 0 {
				continue // a blank "---" document between multi-doc YAML files
			}
			j, err := json.Marshal(doc)
			if err != nil {
				loadErrors = append(loadErrors, fmt.Sprintf("%s: %v", name, err))
				continue
			}
			out = append(out, Manifest{Path: name, JSON: j})
		}
	}
	return out, loadErrors
}

// needsApply is the real "does this candidate differ from live" check.
// plan.SpecChanged alone is not enough: internal/policy.AnalyzeChange's own
// "policy doesn't exist yet" branch (len(current) == 0) never touches
// SpecChanged at all — it stays the zero value, false — even though a
// brand-new policy is obviously a real change. !plan.Exists catches that
// case; plan.SpecChanged catches every other real change to an existing
// policy.
func needsApply(p policy.ChangePlan) bool {
	return !p.Exists || p.SpecChanged
}

func toChangePlanRef(p policy.ChangePlan) models.ChangePlanRef {
	return models.ChangePlanRef{
		Namespace: p.Namespace, Name: p.Name, Exists: p.Exists, Risk: p.Risk,
		Changes: p.Changes, Warnings: p.Warnings,
		AddedDestinations: p.AddedDestinations, RemovedDestinations: p.RemovedDestinations,
		CurrentEgressRules: p.CurrentEgressRules, ProposedEgressRules: p.ProposedEgressRules,
		SelectorChanged: p.SelectorChanged, SpecChanged: p.SpecChanged,
	}
}

// detectDrift compares the live policy against the last revision GitOps
// itself applied (found by scanning st.PolicyHistory, newest first, for
// the first Actor==Actor / Action=="apply" entry) via AnalyzeChange again —
// not a new comparator, per this feature's own design constraint. No prior
// GitOps-applied revision at all means there is nothing to have drifted
// from yet, so that is never drift, just a normal first apply.
func detectDrift(st *store.Store, ns, name string, current []byte) (bool, error) {
	if len(current) == 0 {
		return false, nil
	}
	for _, r := range st.PolicyHistory(ns, name, 200) {
		if r.Actor != Actor || r.Action != "apply" {
			continue
		}
		plan, err := policy.AnalyzeChange(r.Manifest, current)
		if err != nil {
			return false, err
		}
		return plan.SpecChanged, nil
	}
	return false, nil
}

// applyManifest runs the exact existing plan/preflight/apply pipeline
// (AnalyzeChange → server-side dry-run → IssuePreflight/ConsumePreflight →
// ApplyPolicy → RecordPolicyRevision/AddAudit) — the same sequence
// internal/api/server.go's planPolicy/applyPolicy handlers already use for
// a human operator's Preflight → Apply click, so GitOps applies land in the
// identical audit trail and revision/rollback UI. confirmedRisk must equal
// plan.Risk (case-insensitively) whenever that risk is "high" or
// "critical" — the same X-Netra-Confirm-Risk gate applyPolicy enforces.
// Returns the computed plan regardless of whether anything was applied
// (plan.SpecChanged false means nothing needed to change, not an error).
func applyManifest(ctx context.Context, k *kube.Client, st *store.Store, ns, name string, candidate []byte, confirmedRisk string) (policy.ChangePlan, error) {
	current, found, err := k.GetPolicy(ctx, ns, name)
	if err != nil {
		return policy.ChangePlan{}, fmt.Errorf("get live policy: %w", err)
	}
	plan, err := policy.AnalyzeChange(current, candidate)
	if err != nil {
		return plan, fmt.Errorf("analyze change: %w", err)
	}
	if !needsApply(plan) {
		return plan, nil
	}
	if plan.Risk == "high" || plan.Risk == "critical" {
		if !strings.EqualFold(strings.TrimSpace(confirmedRisk), plan.Risk) {
			return plan, fmt.Errorf("risk is %s; apply requires confirming risk=%s", plan.Risk, plan.Risk)
		}
	}
	if _, err := k.ApplyPolicy(ctx, ns, name, candidate, true); err != nil {
		return plan, fmt.Errorf("server-side dry-run failed: %w", err)
	}
	receipt, err := st.IssuePreflight(candidate, plan.Risk, Actor, 5*time.Minute)
	if err != nil {
		return plan, fmt.Errorf("issue preflight: %w", err)
	}
	if _, ok, err := st.ConsumePreflight(receipt.Token, candidate); err != nil {
		return plan, fmt.Errorf("consume preflight: %w", err)
	} else if !ok {
		return plan, fmt.Errorf("preflight receipt rejected")
	}
	out, err := k.ApplyPolicy(ctx, ns, name, candidate, false)
	if err != nil {
		return plan, fmt.Errorf("apply: %w", err)
	}
	if found {
		if snap, snapErr := kube.PreparePolicyForApply(current); snapErr == nil {
			_, _ = st.RecordPolicyRevision(ns, name, "checkpoint", Actor, snap)
		}
	}
	if snap, snapErr := kube.PreparePolicyForApply(out); snapErr == nil {
		_, _ = st.RecordPolicyRevision(ns, name, "apply", Actor, snap)
	} else if snap, snapErr := kube.PreparePolicyForApply(candidate); snapErr == nil {
		_, _ = st.RecordPolicyRevision(ns, name, "apply", Actor, snap)
	}
	_ = st.AddAudit(models.AuditEvent{Actor: Actor, Action: "policy.apply", Target: ns + "/" + name})
	return plan, nil
}

// Resync is the explicit human override POST /api/v1/policies/gitops/resync
// calls: it applies candidate via the exact same pipeline as an auto-apply
// would, regardless of drift or of Reconcile's own auto-apply gating —
// that gating exists only to make Reconcile's unattended pass conservative;
// a human explicitly resyncing has already made the call. confirmedRisk
// still gates high/critical risk exactly like a manual apply would.
func Resync(ctx context.Context, k *kube.Client, st *store.Store, candidate []byte, confirmedRisk string) (models.ChangePlanRef, error) {
	ns, name, err := kube.ExtractIdentity(candidate)
	if err != nil {
		return models.ChangePlanRef{}, fmt.Errorf("candidate manifest: %w", err)
	}
	plan, err := applyManifest(ctx, k, st, ns, name, candidate, confirmedRisk)
	return toChangePlanRef(plan), err
}

// Reconcile computes (and, when autoApply allows it, applies) a status for
// every manifest. A manifest is never auto-applied when: its live policy
// has drifted from the last GitOps-applied revision (never silently
// overwrite a hand-edit), autoApply is false (plan-only mode, the
// default), or its risk is "high"/"critical" (auto-apply never applies
// those, regardless of the autoApply setting — POST
// .../gitops/resync with an explicit confirmed risk is required either
// way).
func Reconcile(ctx context.Context, k *kube.Client, st *store.Store, manifests []Manifest, autoApply bool) []models.GitOpsManifestStatus {
	out := make([]models.GitOpsManifestStatus, 0, len(manifests))
	for _, m := range manifests {
		status := models.GitOpsManifestStatus{Path: m.Path, Manifest: json.RawMessage(m.JSON)}
		ns, name, err := kube.ExtractIdentity(m.JSON)
		if err != nil {
			status.Error = err.Error()
			out = append(out, status)
			continue
		}
		status.Namespace, status.Name = ns, name

		current, _, err := k.GetPolicy(ctx, ns, name)
		if err != nil {
			status.Error = fmt.Sprintf("get live policy: %v", err)
			out = append(out, status)
			continue
		}
		plan, err := policy.AnalyzeChange(current, m.JSON)
		if err != nil {
			status.Error = fmt.Sprintf("analyze change: %v", err)
			out = append(out, status)
			continue
		}
		planRef := toChangePlanRef(plan)
		status.Plan = &planRef

		drifted, err := detectDrift(st, ns, name, current)
		if err != nil {
			status.Error = fmt.Sprintf("drift check: %v", err)
			out = append(out, status)
			continue
		}
		status.Drifted = drifted

		switch {
		case !needsApply(plan):
			status.Note = "in sync"
		case drifted:
			status.Note = "drift detected: the live policy differs from the last GitOps-applied revision; resolve via POST /api/v1/policies/gitops/resync (never silently overwritten)"
		case !autoApply:
			status.Note = "NETRA_GITOPS_AUTO_APPLY is false; plan computed only"
		case plan.Risk == "high" || plan.Risk == "critical":
			status.Note = fmt.Sprintf("risk is %s; auto-apply never applies high/critical-risk changes — resolve via POST /api/v1/policies/gitops/resync with a confirmed risk", plan.Risk)
		default:
			if _, err := applyManifest(ctx, k, st, ns, name, m.JSON, plan.Risk); err != nil {
				status.Error = err.Error()
			} else {
				status.Applied = true
				status.Note = "applied"
			}
		}
		out = append(out, status)
	}
	return out
}
