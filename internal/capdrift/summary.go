// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

// Package capdrift turns the capability-change events
// internal/agent/ownership_linux.go's watchCapChanges already computes
// (but, until this package existed, never consumed) into anomaly-shaped
// findings — the same Build(agents, topN) models.X shape every other
// health-signal package in this project (internal/health,
// internal/shielddiag, internal/pathdiag) already uses, so it plugs into
// internal/alert.Poller and the web dashboard the same way.
package capdrift

import (
	"fmt"
	"sort"
	"time"

	"github.com/zyvorai/netra/internal/models"
)

// restartCoverageGapWindow is how long after an agent's own process start
// its capability-drift detection is considered to have a blind spot: the
// in-memory prevCaps map watchCapChanges compares against resets on every
// agent restart, so a capability change that happened before this restart,
// or while the agent was down, is invisible for at least one full sync
// cycle after boot.
const restartCoverageGapWindow = 2 * time.Minute

// Build derives capability-drift anomalies from the CapChangeEvents each
// agent already reports. Thresholds are conservative heuristics, matching
// internal/health/summary.go's own "conservative heuristics, not
// statistical claims" convention.
func Build(agents []models.AgentStatus, topN int) models.CapDriftResponse {
	if topN <= 0 {
		topN = 50
	}
	resp := models.CapDriftResponse{}
	for _, a := range agents {
		if a.Stale {
			continue
		}
		for _, ev := range a.CapChanges {
			resp.Events = append(resp.Events, ev)
			resp.Anomalies = append(resp.Anomalies, anomalyFor(ev))
		}
		if gap := coverageGapAnomaly(a); gap != nil {
			resp.Anomalies = append(resp.Anomalies, *gap)
		}
	}
	// Events and Anomalies are not 1:1 (the coverage-gap anomaly has no
	// corresponding event), so each is sorted independently rather than by
	// cross-indexing into the other.
	sort.SliceStable(resp.Events, func(i, j int) bool {
		return severityRank(anomalyFor(resp.Events[i]).Severity) > severityRank(anomalyFor(resp.Events[j]).Severity)
	})
	sort.SliceStable(resp.Anomalies, func(i, j int) bool {
		return severityRank(resp.Anomalies[i].Severity) > severityRank(resp.Anomalies[j].Severity)
	})
	if len(resp.Events) > topN {
		resp.Events = resp.Events[:topN]
	}
	if len(resp.Anomalies) > topN {
		resp.Anomalies = resp.Anomalies[:topN]
	}
	return resp
}

// severityRank exists only to keep Events sorted in the same order as
// Anomalies before either is truncated — it does not affect the response
// shape, just presentation order.
func severityRank(s string) int {
	switch s {
	case "critical":
		return 3
	case "warning":
		return 2
	default:
		return 1
	}
}

func anomalyFor(ev models.CapChangeEvent) models.NetworkHealthAnomaly {
	sub := subject(ev)
	gained, lost := diffNamed(ev.PreviousCapEff, ev.CurrentCapEff)
	switch {
	case len(gained) > 0:
		return models.NetworkHealthAnomaly{
			Severity: "warning",
			Kind:     "capdrift-gained",
			Subject:  sub,
			Message:  fmt.Sprintf("process gained %v (was 0x%x, now 0x%x)", gained, ev.PreviousCapEff, ev.CurrentCapEff),
			Value:    float64(len(gained)),
		}
	case len(lost) > 0:
		return models.NetworkHealthAnomaly{
			Severity: "info",
			Kind:     "capdrift-lost",
			Subject:  sub,
			Message:  fmt.Sprintf("process lost %v (was 0x%x, now 0x%x)", lost, ev.PreviousCapEff, ev.CurrentCapEff),
			Value:    float64(len(lost)),
		}
	default:
		return models.NetworkHealthAnomaly{
			Severity: "info",
			Kind:     "capdrift-other",
			Subject:  sub,
			Message:  fmt.Sprintf("effective capability set changed (was 0x%x, now 0x%x) outside the tracked CAP_NET_ADMIN/CAP_NET_RAW pair", ev.PreviousCapEff, ev.CurrentCapEff),
		}
	}
}

// diffNamed reports which of the two capabilities capability-gated socket
// deny actually acts on (models.CapabilityBit's small, fixed vocabulary —
// not the full 64-bit capability space) were gained/lost between prev and
// cur. A change to any other bit still produces an event (see
// anomalyFor's default case) but is not named individually, matching this
// project's existing narrow, explicit capability vocabulary everywhere
// else (docs/capability-gated-deny.md).
func diffNamed(prev, cur uint64) (gained, lost []string) {
	for name, bit := range models.CapabilityBit {
		mask := uint64(1) << bit
		was, is := prev&mask != 0, cur&mask != 0
		switch {
		case !was && is:
			gained = append(gained, name)
		case was && !is:
			lost = append(lost, name)
		}
	}
	sort.Strings(gained)
	sort.Strings(lost)
	return gained, lost
}

func subject(ev models.CapChangeEvent) string {
	if ev.Namespace != "" && ev.Pod != "" {
		return ev.Namespace + "/" + ev.Pod
	}
	if ev.Comm != "" {
		return fmt.Sprintf("%s (pid %d)", ev.Comm, ev.PID)
	}
	return fmt.Sprintf("pid %d", ev.PID)
}

// coverageGapAnomaly flags an agent that started recently: watchCapChanges'
// in-memory prevCaps map is empty on a fresh process, so any capability
// change that happened before this restart, or while the agent was down,
// produced no event — this must be surfaced as a real blind spot, not
// silently read as "no drift occurred."
func coverageGapAnomaly(a models.AgentStatus) *models.NetworkHealthAnomaly {
	if a.AgentStartedAt.IsZero() {
		return nil
	}
	age := a.ObservedAt.Sub(a.AgentStartedAt)
	if age < 0 || age > restartCoverageGapWindow {
		return nil
	}
	return &models.NetworkHealthAnomaly{
		Severity: "info",
		Kind:     "capdrift-coverage-gap",
		Subject:  a.Node,
		Message:  "agent restarted recently; capability drift that occurred before this restart, or while the agent was down, is not visible",
		Value:    age.Seconds(),
	}
}
