// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

// Package features is the curated Netra capability catalog used by
// netractl features and GET/POST /api/v1/features.
package features

import (
	"fmt"
	"os"
	"strings"
)

// Scope where a feature takes effect.
type Scope string

const (
	ScopeController Scope = "controller"
	ScopeAgent      Scope = "agent"
	ScopeCluster    Scope = "cluster"
)

// Feature is one enable/disable capability.
type Feature struct {
	ID          string `json:"id"`
	Title       string `json:"title"`
	Description string `json:"description"`
	Scope       Scope  `json:"scope"`
	HelmSet     string `json:"helmSet"`           // e.g. dnsdetect.enabled
	EnvKey      string `json:"envKey,omitempty"`  // controller/agent env when applicable
	EnvTrue     string `json:"envTrue,omitempty"` // value that means enabled (default "true"); "nonempty" = any non-empty
	CLI         string `json:"cli"`               // netractl features enable <id>
	Target      string `json:"target,omitempty"`  // deployment|daemonset for API patch
}

// Catalog is the allowlisted feature set (stable IDs for CLI/UX).
func Catalog() []Feature {
	return []Feature{
		{ID: "agent", Title: "Node agent", Description: "Privileged DaemonSet on every node (eBPF observe + leased enforce).", Scope: ScopeCluster, HelmSet: "agent.enabled", CLI: "netractl features enable agent"},
		{ID: "cilium", Title: "Cilium enrichment", Description: "Optional CiliumNetworkPolicy management and RBAC.", Scope: ScopeController, HelmSet: "cilium.enabled", EnvKey: "NETRA_CILIUM_ENABLED", Target: "deployment", CLI: "netractl features enable cilium"},
		{ID: "hubble", Title: "Hubble flows", Description: "Optional Hubble Relay live flow stream.", Scope: ScopeController, HelmSet: "hubble.enabled", EnvKey: "NETRA_HUBBLE_ENABLED", Target: "deployment", CLI: "netractl features enable hubble"},
		{ID: "dns-detect", Title: "DNS anomaly detect", Description: "GA observe-only DNS tunneling/DGA/NXDOMAIN heuristics (chart default on).", Scope: ScopeController, HelmSet: "dnsdetect.enabled", EnvKey: "NETRA_DNSDETECT_ENABLED", Target: "deployment", CLI: "netractl features enable dns-detect"},
		{ID: "scan-detect", Title: "Scan detect", Description: "GA observe-only port-scan / SYN-flood heuristics (chart default on).", Scope: ScopeController, HelmSet: "scandetect.enabled", EnvKey: "NETRA_SCANDETECT_ENABLED", Target: "deployment", CLI: "netractl features enable scan-detect"},
		{ID: "automitigate", Title: "Auto-mitigate", Description: "GA leased volumetric response (SYN/UDP); acts only under an enforce lease.", Scope: ScopeController, HelmSet: "automitigate.enabled", EnvKey: "NETRA_AUTOMITIGATE_ENABLED", Target: "deployment", CLI: "netractl features enable automitigate"},
		{ID: "tlsfp", Title: "TLS fingerprints", Description: "GA JA3/JA4 ClientHello sampler (agent; chart default auto).", Scope: ScopeAgent, HelmSet: "agent.tlsfp", EnvKey: "NETRA_TLSFP", EnvTrue: "auto", Target: "daemonset", CLI: "netractl features enable tlsfp"},
		{ID: "ai", Title: "AI rewrite", Description: "Optional OpenAI-compatible brief rewrite (read-only).", Scope: ScopeController, HelmSet: "ai.enabled", EnvKey: "NETRA_AI_BASE_URL", EnvTrue: "nonempty", Target: "deployment", CLI: "netractl features enable ai"},
		{ID: "gitops", Title: "Policy GitOps", Description: "Reconcile CiliumNetworkPolicy manifests from a mounted dir.", Scope: ScopeController, HelmSet: "gitops.enabled", EnvKey: "NETRA_GITOPS_DIR", EnvTrue: "nonempty", Target: "deployment", CLI: "netractl features enable gitops"},
		{ID: "workload-console", Title: "Workload console", Description: "In-browser pod logs/exec and VM VNC (extra RBAC).", Scope: ScopeController, HelmSet: "workloadConsole.enabled", EnvKey: "NETRA_WORKLOAD_CONSOLE", Target: "deployment", CLI: "netractl features enable workload-console"},
		{ID: "alerting", Title: "Multi-channel alerting", Description: "Outbound notify poller (webhook/email/Slack/Teams/…).", Scope: ScopeController, HelmSet: "alerting.enabled", EnvKey: "NETRA_ALERT_POLL_INTERVAL", EnvTrue: "nonempty", Target: "deployment", CLI: "netractl features enable alerting"},
		{ID: "auto-capture", Title: "Auto-capture", Description: "GA bounded PCAP on critical drop/congestion signals (chart default on).", Scope: ScopeController, HelmSet: "alerting.autoCapture.enabled", EnvKey: "NETRA_AUTO_CAPTURE", Target: "deployment", CLI: "netractl features enable auto-capture"},
	}
}

// ByID returns a catalog entry or nil.
func ByID(id string) *Feature {
	id = strings.TrimSpace(strings.ToLower(id))
	for _, f := range Catalog() {
		if f.ID == id {
			cp := f
			return &cp
		}
	}
	return nil
}

// Status is one feature's effective state.
type Status struct {
	Feature
	Enabled bool   `json:"enabled"`
	Source  string `json:"source"` // env|agents|unknown
	Note    string `json:"note,omitempty"`
}

// EvalEnv evaluates whether a feature is on from environment variables.
func EvalEnv(f Feature) (enabled bool, known bool) {
	if f.EnvKey == "" {
		return false, false
	}
	raw := strings.TrimSpace(os.Getenv(f.EnvKey))
	switch f.EnvTrue {
	case "nonempty":
		return raw != "", true
	case "auto":
		v := strings.ToLower(raw)
		if v == "off" || v == "false" || v == "0" {
			return false, true
		}
		// empty / auto / required → enabled (agent default)
		return true, true
	default:
		want := f.EnvTrue
		if want == "" {
			want = "true"
		}
		return strings.EqualFold(raw, want), true
	}
}

// FromEnv evaluates controller-visible env for each catalog feature.
func FromEnv() []Status {
	out := make([]Status, 0, len(Catalog()))
	for _, f := range Catalog() {
		st := Status{Feature: f, Source: "env"}
		switch {
		case f.ID == "agent":
			st.Source = "unknown"
			st.Note = "Use netractl status / fleet for agent coverage; toggle via Helm agent.enabled"
			st.Enabled = false
		default:
			en, known := EvalEnv(f)
			if !known {
				st.Source = "unknown"
				st.Note = "Toggle via Helm " + f.HelmSet
			} else {
				st.Enabled = en
			}
		}
		out = append(out, st)
	}
	return out
}

// EnrichAgent marks the agent feature from live agent reports.
func EnrichAgent(statuses []Status, reporting, stale int) []Status {
	for i := range statuses {
		if statuses[i].ID != "agent" {
			continue
		}
		statuses[i].Source = "agents"
		statuses[i].Enabled = reporting > 0
		if reporting == 0 {
			statuses[i].Note = "No agents reporting; enable with netractl features enable agent"
		} else if stale > 0 {
			statuses[i].Note = fmt.Sprintf("%d reporting (%d stale)", reporting, stale)
		} else {
			statuses[i].Note = fmt.Sprintf("%d agents reporting", reporting)
		}
	}
	return statuses
}

// HelmSetPair returns helm --set key=value for enabling/disabling.
func HelmSetPair(id string, enabled bool) (string, error) {
	f := ByID(id)
	if f == nil {
		return "", fmt.Errorf("unknown feature: %s", id)
	}
	v := "false"
	if enabled {
		v = "true"
		if f.ID == "tlsfp" {
			v = "auto"
		}
	} else if f.ID == "tlsfp" {
		v = "off"
	}
	return f.HelmSet + "=" + v, nil
}

// EnvPatchValue returns the env value to write when toggling via API patch.
func EnvPatchValue(f Feature, enabled bool) (string, error) {
	if f.EnvKey == "" {
		return "", fmt.Errorf("feature %s has no env key; use Helm %s", f.ID, f.HelmSet)
	}
	if !enabled {
		switch f.EnvTrue {
		case "nonempty":
			return "", nil
		case "auto":
			return "off", nil
		default:
			return "false", nil
		}
	}
	switch f.EnvTrue {
	case "nonempty":
		switch f.ID {
		case "ai":
			return "https://api.openai.com/v1", nil
		case "gitops":
			return "/gitops/policies", nil
		case "alerting":
			return "30s", nil
		default:
			return "true", nil
		}
	case "auto":
		return "auto", nil
	default:
		return "true", nil
	}
}
