// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package alert

import (
	"sync"
	"time"

	"github.com/zyvorai/netra/internal/notify"
)

// severityRank mirrors internal/health/summary.go's own severity-order map
// (no shared severity-rank helper exists anywhere in this codebase today;
// duplicating the same three-line map a second time here is consistent with
// that precedent, not a smell worth centralizing on its own).
var severityRank = map[string]int{"critical": 3, "warning": 2, "info": 1}

type dedupKey struct{ Source, Kind, Subject string }

type fireState struct {
	Severity string
	At       time.Time
}

// dedupState tracks the last time each (source, kind, subject) fired and at
// what severity, so a persistent condition doesn't refire every poll
// interval. State is in-memory only and intentionally reset on process
// restart/HA failover, matching how agent reports are already treated as
// ephemeral rather than durable.
type dedupState struct {
	mu   sync.Mutex
	last map[dedupKey]fireState
}

func newDedupState() *dedupState {
	return &dedupState{last: map[dedupKey]fireState{}}
}

// shouldFire reports whether ev should be published now, and if so records
// it as the new fire state for its key.
func (d *dedupState) shouldFire(now time.Time, cooldown time.Duration, ev notify.Event) bool {
	key := dedupKey{ev.Source, ev.Kind, ev.Subject}
	d.mu.Lock()
	defer d.mu.Unlock()
	prev, seen := d.last[key]
	fire := !seen || severityRank[ev.Severity] > severityRank[prev.Severity] || !now.Before(prev.At.Add(cooldown))
	if fire {
		d.last[key] = fireState{Severity: ev.Severity, At: now}
	}
	return fire
}

// sweep evicts entries older than max(cooldown*8, 1h). Anomaly subjects can
// be per-destination/per-flow (e.g. internal/health's subject() helper) and
// are not naturally bounded like a fixed node/reason key space would be;
// without eviction a long-running controller in a churny cluster
// accumulates unbounded dedup state. Over-eager eviction only costs one
// extra duplicate notification, never data loss, so erring toward eviction
// is the safe direction.
func (d *dedupState) sweep(now time.Time, cooldown time.Duration) {
	maxAge := cooldown * 8
	if maxAge < time.Hour {
		maxAge = time.Hour
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	for k, v := range d.last {
		if now.Sub(v.At) > maxAge {
			delete(d.last, k)
		}
	}
}
