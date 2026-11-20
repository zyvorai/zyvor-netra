// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

// Package exehash turns the exe-content-hash-change events
// internal/agent/ownership_linux.go's watchExeHashChanges already
// computes into anomaly-shaped findings, mirroring internal/capdrift
// and internal/nsdrift's Build(agents, topN) models.X shape exactly.
// This is the observe-only half of docs/exporter-tetragon-borrow-
// backlog.md's "Exe-hash leased deny" item — enforcement (an optional
// fail-open lease map) is explicitly a later, separate step.
package exehash

import (
	"fmt"
	"sort"
	"time"

	"github.com/zyvorai/netra/internal/models"
)

// restartCoverageGapWindow mirrors internal/capdrift/internal/nsdrift's
// own constant: the in-memory prevExeHash map watchExeHashChanges
// compares against resets on every agent restart.
const restartCoverageGapWindow = 2 * time.Minute

// Build derives exe-hash-drift anomalies from the ExeHashChangeEvents
// each agent already reports. Every event is "warning": procmeta reads
// the magic /proc/PID/exe symlink directly (not the readlink target
// path), which the kernel resolves to the live backing inode even
// after an on-disk replace — so the common benign case (a package
// upgrade replacing the file at that path while an old process
// instance keeps running) does not change the hash. A real change
// here means the process's own backing inode content changed while it
// was running, a narrower and rarer signal than capability or
// namespace drift.
func Build(agents []models.AgentStatus, topN int) models.ExeHashDriftResponse {
	if topN <= 0 {
		topN = 50
	}
	resp := models.ExeHashDriftResponse{}
	for _, a := range agents {
		if a.Stale {
			continue
		}
		for _, ev := range a.ExeHashChanges {
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

func anomalyFor(ev models.ExeHashChangeEvent) models.NetworkHealthAnomaly {
	return models.NetworkHealthAnomaly{
		Severity: "warning",
		Kind:     "exehash-changed",
		Subject:  subject(ev),
		Message:  fmt.Sprintf("executable content changed while process was running (%s)", ev.Exe),
	}
}

func subject(ev models.ExeHashChangeEvent) string {
	if ev.Namespace != "" && ev.Pod != "" {
		return ev.Namespace + "/" + ev.Pod
	}
	if ev.Comm != "" {
		return fmt.Sprintf("%s (pid %d)", ev.Comm, ev.PID)
	}
	return fmt.Sprintf("pid %d", ev.PID)
}

// coverageGapAnomaly mirrors internal/capdrift/internal/nsdrift's own
// function: an agent that started recently has an empty in-memory
// prevExeHash map, so any exe-hash change that happened before this
// restart, or while the agent was down, produced no event.
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
		Kind:     "exehash-coverage-gap",
		Subject:  a.Node,
		Message:  "agent restarted recently; an executable-content change that occurred before this restart, or while the agent was down, is not visible",
		Value:    age.Seconds(),
	}
}
