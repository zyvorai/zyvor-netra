// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package api

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/zyvorai/netra/internal/features"
	"github.com/zyvorai/netra/internal/kube"
	"github.com/zyvorai/netra/internal/models"
)

func (s *Server) listFeatures(w http.ResponseWriter, _ *http.Request) {
	statuses := features.FromEnv()
	if s.store != nil {
		agents := s.store.AgentStatuses(time.Now(), s.agentStaleAfter)
		stale := 0
		for _, a := range agents {
			if a.Stale {
				stale++
			}
		}
		statuses = features.EnrichAgent(statuses, len(agents), stale)
	}
	on, off, unk := 0, 0, 0
	for _, st := range statuses {
		switch {
		case st.Source == "unknown":
			unk++
		case st.Enabled:
			on++
		default:
			off++
		}
	}
	writeJSON(w, 200, map[string]any{
		"features": statuses,
		"summary":  map[string]int{"on": on, "off": off, "unknown": unk},
		"note":     "Helm is source of truth for durable desired state; API patch is for live ops. Prefer: netractl features enable NAME --yes",
	})
}

func (s *Server) setFeature(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimSpace(r.PathValue("id"))
	f := features.ByID(id)
	if f == nil {
		errorJSON(w, 404, "unknown feature: "+id)
		return
	}
	if !strings.EqualFold(strings.TrimSpace(r.Header.Get("X-Netra-Confirm-Risk")), "high") {
		errorJSON(w, 409, "toggling features requires X-Netra-Confirm-Risk: high")
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<16))
	if err != nil {
		errorJSON(w, 400, err.Error())
		return
	}
	var req struct {
		Enabled bool `json:"enabled"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		errorJSON(w, 400, "body must be {\"enabled\": true|false}")
		return
	}
	if f.ID == "agent" {
		errorJSON(w, 501, "agent toggle requires Helm: netractl features enable agent --yes")
		return
	}
	if f.EnvKey == "" || f.Target == "" {
		errorJSON(w, 501, "feature has no live env patch; use Helm --set "+f.HelmSet)
		return
	}
	val, err := features.EnvPatchValue(*f, req.Enabled)
	if err != nil {
		errorJSON(w, 400, err.Error())
		return
	}
	if s.kube == nil {
		errorJSON(w, 503, "kubernetes client unavailable")
		return
	}
	ns := kube.ControllerNamespace()
	kind := "deployments"
	name := "netra"
	container := "netra"
	if f.Target == "daemonset" {
		kind = "daemonsets"
		name = "netra-agent"
		container = "agent"
	}
	if err := s.kube.PatchContainerEnv(r.Context(), kind, ns, name, container, f.EnvKey, val); err != nil {
		errorJSON(w, 502, err.Error())
		return
	}
	who := strings.TrimSpace(r.Header.Get("X-Netra-Actor"))
	if verified, ok := verifiedActor(r); ok {
		who = verified // never let an unverified header override a verified identity
	}
	if who == "" {
		who = "api"
	}
	if s.store != nil {
		_ = s.store.AddAudit(models.AuditEvent{
			At:     time.Now().UTC(),
			Actor:  who,
			Action: "features.set",
			Target: f.ID,
			Details: map[string]any{
				"enabled": req.Enabled,
				"envKey":  f.EnvKey,
				"value":   val,
				"helmSet": f.HelmSet,
			},
		})
	}
	action := "disable"
	if req.Enabled {
		action = "enable"
	}
	writeJSON(w, 200, map[string]any{
		"ok":      true,
		"id":      f.ID,
		"enabled": req.Enabled,
		"envKey":  f.EnvKey,
		"value":   val,
		"note":    "Pod restart required for new env; Helm remains source of truth for GitOps.",
		"cli":     "netractl features " + action + " " + f.ID + " --yes",
	})
}
