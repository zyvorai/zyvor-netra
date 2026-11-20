// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package insights

import (
	"time"

	"github.com/zyvorai/netra/internal/models"
)

// NewSinceStartLimitation must accompany any presentation of NewSinceStart's
// results — surfaced verbatim in the API response so this correlation is
// never read as more precise than it actually is.
const NewSinceStartLimitation = "baseline-relative correlation only: there is no existing conversion between kernel-boot-monotonic packet timestamps and Kubernetes wall-clock pod start times, so this reports \"new since the captured baseline, and this pod/workload started after that baseline\" — never a precise \"N ms after first packet\" claim."

// NewSinceStart narrows Drift's "new destination since baseline" findings
// to those whose owning pod/workload started after baseline was captured —
// a plausible same-run correlation (see NewSinceStartLimitation for exactly
// how loose). A pod/workload with more than maxRestarts (<=0 disables this
// filter) cumulative container restarts is excluded entirely: with that
// much churn, which restart the traffic actually followed is too ambiguous
// to call "since start" at all. Inherits Drift's own "does nothing without
// a captured baseline" limitation unchanged.
func NewSinceStart(baseline models.BehaviorBaseline, agents []models.AgentStatus, pods []models.PodInfo, maxRestarts int) []models.DriftFinding {
	drift := Drift(baseline, agents)
	if len(drift.Findings) == 0 {
		return nil
	}

	type podStart struct {
		started      *time.Time
		restartCount int
	}
	startsBySource := map[string]podStart{}
	for _, p := range pods {
		ps := podStart{started: p.Started, restartCount: p.RestartCount}
		startsBySource[models.CanonicalSource(p.Namespace, p.Name, "", "", 0)] = ps
		if p.OwnerKind == "" || p.OwnerName == "" {
			continue
		}
		wSrc := models.CanonicalSource(p.Namespace, "", p.OwnerKind, p.OwnerName, 0)
		cur, ok := startsBySource[wSrc]
		if !ok || (ps.started != nil && (cur.started == nil || ps.started.After(*cur.started))) {
			startsBySource[wSrc] = ps
		}
	}

	out := make([]models.DriftFinding, 0)
	for _, f := range drift.Findings {
		ps, ok := startsBySource[f.Source]
		if !ok || ps.started == nil {
			continue
		}
		if maxRestarts > 0 && ps.restartCount > maxRestarts {
			continue
		}
		if !ps.started.After(baseline.CapturedAt) {
			continue
		}
		out = append(out, f)
	}
	return out
}
