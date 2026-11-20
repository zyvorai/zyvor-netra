// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package counterfactual

import (
	"context"
	"sort"
	"sync"
)

// MemoryStore is an in-memory, reference implementation of Store for
// tests and small deployments. Production controllers use FlowLogStore.
//
// MemoryStore is safe for concurrent use.
type MemoryStore struct {
	mu    sync.RWMutex
	flows []Flow
}

// NewMemoryStore returns an empty MemoryStore.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{}
}

// Add appends flows to the store. It does not deduplicate.
func (m *MemoryStore) Add(flows ...Flow) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.flows = append(m.flows, flows...)
}

// Len returns the number of flows currently held.
func (m *MemoryStore) Len() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.flows)
}

// Query implements Store.
func (m *MemoryStore) Query(_ context.Context, q Query) ([]Flow, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	out := make([]Flow, 0, len(m.flows))
	for _, f := range m.flows {
		if !q.Start.IsZero() && f.Timestamp.Before(q.Start) {
			continue
		}
		if !q.End.IsZero() && !f.Timestamp.Before(q.End) {
			continue
		}
		if q.Workload != "" && f.Workload.Key() != q.Workload {
			continue
		}
		out = append(out, f)
	}

	sort.Slice(out, func(i, j int) bool { return out[i].Timestamp.Before(out[j].Timestamp) })

	if q.Limit > 0 && len(out) > q.Limit {
		out = out[:q.Limit]
	}
	return out, nil
}
