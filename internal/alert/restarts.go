// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package alert

import (
	"sync"

	"github.com/zyvorai/netra/internal/models"
)

// restartTracker remembers each pod/workload source's last-seen
// RestartCount across ticks — the cross-tick memory a stateless API handler
// (GET /api/v1/insights/new-since-start) can't carry, needed to tell "this
// pod just restarted between the last poll and this one" (ambiguous which
// start any given finding follows, so suppress for one cycle) apart from
// "this pod has restarted before" (internal/insights.NewSinceStart's own
// maxRestarts already handles that, statelessly). Same shape as this
// package's existing dedupState: an in-memory map, no persistence.
type restartTracker struct {
	mu   sync.Mutex
	last map[string]int
}

func newRestartTracker() *restartTracker {
	return &restartTracker{last: map[string]int{}}
}

// justRestarted reports whether source's restartCount increased since the
// last call for that source, then remembers the new count. The first call
// for a source is never "just restarted" — there is nothing to compare
// against yet.
func (t *restartTracker) justRestarted(source string, restartCount int) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	prev, ok := t.last[source]
	t.last[source] = restartCount
	return ok && restartCount > prev
}

// restartCountsBySource mirrors internal/insights.NewSinceStart's own
// pod/workload source indexing, kept local rather than exported from
// insights since this is the only other caller and uses it for a different
// purpose (cross-tick suppression here, vs. the started-after-baseline join
// there).
func restartCountsBySource(pods []models.PodInfo) map[string]int {
	out := make(map[string]int, len(pods))
	for _, p := range pods {
		out[models.CanonicalSource(p.Namespace, p.Name, "", "", 0)] = p.RestartCount
		if p.OwnerKind == "" || p.OwnerName == "" {
			continue
		}
		wSrc := models.CanonicalSource(p.Namespace, "", p.OwnerKind, p.OwnerName, 0)
		if p.RestartCount > out[wSrc] {
			out[wSrc] = p.RestartCount
		}
	}
	return out
}
