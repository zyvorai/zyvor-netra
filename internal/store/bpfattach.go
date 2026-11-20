// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package store

import "github.com/zyvorai/netra/internal/models"

// mergeBPFAttach restores the interface list for an "unchanged" report. The
// agent sends the full list only when it changed (or every few minutes) and a
// small summary otherwise; the store replaces a node's whole report each tick,
// so without this the list would vanish between refreshes.
//
// It only restores when the hash matches what it holds: a summary for a list the
// controller does not have (it restarted, or missed the full report) stays
// unrestored, and the diagnostic treats that as "cannot judge", never as
// "nothing attached".
func mergeBPFAttach(prev, next *models.BPFAttachReport) *models.BPFAttachReport {
	if next == nil {
		return nil
	}
	out := *next
	if next.Unchanged && prev != nil && !prev.Unchanged && prev.Hash == next.Hash && prev.Interfaces != nil {
		out.Interfaces = prev.Interfaces
		out.Failed = prev.Failed
		out.Error = prev.Error
		out.Unchanged = false
	}
	return &out
}

// cloneBPFAttach isolates a reader from the stored report. The interface list is
// immutable once stored, so it is shared.
func cloneBPFAttach(r *models.BPFAttachReport) *models.BPFAttachReport {
	if r == nil {
		return nil
	}
	out := *r
	return &out
}
