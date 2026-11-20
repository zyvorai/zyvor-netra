// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

// Package nsdrift turns the network-namespace-change events
// internal/agent/ownership_linux.go's watchNamespaceChanges already
// computes into anomaly-shaped findings, mirroring internal/capdrift's
// Build(agents, topN) models.X shape exactly so it plugs into
// internal/alert.Poller and the web dashboard the same way every other
// health-signal package in this project does.
package nsdrift

import (
	"fmt"
	"sort"
	"time"

	"github.com/zyvorai/netra/internal/models"
)

// restartCoverageGapWindow mirrors internal/capdrift's own constant: the
// in-memory prevNetNS map watchNamespaceChanges compares against resets
// on every agent restart, so a namespace change that happened before
// this restart, or while the agent was down, is invisible for at least
// one full sync cycle after boot.
const restartCoverageGapWindow = 2 * time.Minute

// Build derives namespace-drift anomalies from the NamespaceChangeEvents
// each agent already reports. Every event is "warning" — unlike
// capability drift, there is no benign "lost a capability" case here: a
// live process changing network namespaces after start is always worth
// an operator's attention.
func Build(agents []models.AgentStatus, topN int) models.NamespaceDriftResponse {
	if topN <= 0 {
		topN = 50
	}
	resp := models.NamespaceDriftResponse{}
	for _, a := range agents {
		if a.Stale {
			continue
		}
		for _, ev := range a.NamespaceChanges {
			resp.Events = append(resp.Events, ev)
			resp.Anomalies = append(resp.Anomalies, anomalyFor(ev))
		}
		if gap := coverageGapAnomaly(a); gap != nil {
			resp.Anomalies = append(resp.Anomalies, *gap)
		}
	}
	sort.SliceStable(resp.Events, func(i, j int) bool {
		return resp.Events[i].PID < resp.Events[j].PID
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

func anomalyFor(ev models.NamespaceChangeEvent) models.NetworkHealthAnomaly {
	return models.NetworkHealthAnomaly{
		Severity: "warning",
		Kind:     "nsdrift-netns-changed",
		Subject:  subject(ev),
		Message:  fmt.Sprintf("network namespace changed while process was running (was inode %d, now %d)", ev.PreviousNetNS, ev.CurrentNetNS),
	}
}

func subject(ev models.NamespaceChangeEvent) string {
	if ev.Namespace != "" && ev.Pod != "" {
		return ev.Namespace + "/" + ev.Pod
	}
	if ev.Comm != "" {
		return fmt.Sprintf("%s (pid %d)", ev.Comm, ev.PID)
	}
	return fmt.Sprintf("pid %d", ev.PID)
}

// coverageGapAnomaly mirrors internal/capdrift's own function: an agent
// that started recently has an empty in-memory prevNetNS map, so any
// namespace change that happened before this restart, or while the
// agent was down, produced no event — a real blind spot, not silently
// "no drift occurred."
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
		Kind:     "nsdrift-coverage-gap",
		Subject:  a.Node,
		Message:  "agent restarted recently; a namespace change that occurred before this restart, or while the agent was down, is not visible",
		Value:    age.Seconds(),
	}
}
