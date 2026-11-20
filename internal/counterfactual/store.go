// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package counterfactual

import (
	"context"
	"time"
)

// Query selects a subset of stored flows for evaluation.
type Query struct {
	// Start and End bound the window, inclusive of Start, exclusive of
	// End. A zero End means "up to now".
	Start time.Time
	End   time.Time

	// Workload, if non-empty (WorkloadRef.Key()), restricts to flows
	// attributed to that workload.
	Workload string

	// Limit caps the number of flows returned. Zero means no limit; a
	// Store implementation may still apply its own hard cap and should
	// document it.
	Limit int
}

// Store is the narrow interface this package needs from a historical
// flow backend. FlowLogStore adapts the controller flowlog; MemoryStore
// is the in-memory reference for tests.
type Store interface {
	// Query returns flows matching q, ordered by Timestamp ascending.
	Query(ctx context.Context, q Query) ([]Flow, error)
}
