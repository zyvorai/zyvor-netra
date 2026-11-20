// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package store

import (
	"slices"

	"github.com/zyvorai/netra/internal/models"
)

// maxNetlinkEvents bounds the per-node change history the controller keeps.
// It lives in memory only, like every agent report: a controller restart
// clears it, and the agents' next reports rebuild the current state.
const maxNetlinkEvents = 2000

// mergeNetlink folds one agent report's netlink section into the node's
// history. The store replaces a node's whole report on every tick, so without
// this only the newest three seconds of changes would ever be visible.
//
//   - events accumulate, capped at maxNetlinkEvents;
//   - a resent event (a report whose response was lost, so the agent did not
//     advance its cursor) is dropped by (epoch, cursor), while an agent restart
//     starts a new epoch whose sequence numbers legitimately begin again;
//   - a report without a snapshot means "unchanged", so the last one carries
//     forward.
func mergeNetlink(prev, next *models.NetlinkReport) *models.NetlinkReport {
	if next == nil {
		return nil
	}
	out := *next
	out.Events = slices.Clone(next.Events)
	if prev == nil {
		return &out
	}
	if out.Snapshot == nil {
		out.Snapshot = prev.Snapshot
	}
	if prev.Epoch == out.Epoch {
		out.Events = slices.DeleteFunc(out.Events, func(e models.NetlinkEvent) bool {
			return e.Sequence <= prev.Cursor
		})
	}
	if len(prev.Events) > 0 {
		out.Events = append(slices.Clone(prev.Events), out.Events...)
	}
	if len(out.Events) > maxNetlinkEvents {
		out.Events = slices.Clone(out.Events[len(out.Events)-maxNetlinkEvents:])
	}
	return &out
}

// cloneNetlink copies what a reader could mutate. Snapshot is immutable once
// stored, so it is shared.
func cloneNetlink(r *models.NetlinkReport) *models.NetlinkReport {
	if r == nil {
		return nil
	}
	out := *r
	out.Events = slices.Clone(r.Events)
	return &out
}
