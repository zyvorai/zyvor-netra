// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package api

import (
	"sync"

	"github.com/zyvorai/netra/internal/models"
)

// workloadInventoryCache remembers the last successful per-node
// ListWorkloads result so a transient Kubernetes API error doesn't
// silently zero out workload attribution for that node.
//
// Why this exists: ebpfConfig calls s.kube.ListWorkloads(ctx, node) fresh
// on every agent sync (every ~3s, per node, uncached) with only a 4s
// timeout. Before this cache existed, a single failed call — a 429, a
// timeout, brief apiserver unavailability — made ebpfConfig respond 200
// with cfg.Workloads simply left empty (see the ListWorkloads error
// branch below). The agent has no way to distinguish "this node
// genuinely has zero workloads" from "the fetch failed" once it receives
// an empty list, so internal/workload.Resolve would then re-resolve
// every cgroup on that node against an empty pod table — which its
// documented fail-open behavior turns into a *blank* WorkloadIdentity
// per cgroup (UID/Namespace/Pod left empty) rather than skipping them.
// internal/insights.Dependencies (and anything else that requires
// Namespace/Pod/WorkloadName to be set) would then drop every stat from
// that node, on every subsequent report, until the next successful
// ListWorkloads call — on a real cluster under real API-server load,
// that can mean an indefinitely empty Topology graph despite the agent
// itself staying perfectly healthy. See docs/standalone-ebpf.md.
type workloadInventoryCache struct {
	mu    sync.Mutex
	items map[string][]models.WorkloadIdentity
}

func newWorkloadInventoryCache() *workloadInventoryCache {
	return &workloadInventoryCache{items: map[string][]models.WorkloadIdentity{}}
}

// set records node's latest successful inventory.
func (c *workloadInventoryCache) set(node string, items []models.WorkloadIdentity) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.items[node] = items
}

// get returns node's last-known-good inventory, if any. ok is false only
// for a node whose very first ListWorkloads call has never succeeded —
// there is nothing to fall back to yet, so the caller's existing
// empty-list behavior is the correct (and only available) choice there.
func (c *workloadInventoryCache) get(node string) ([]models.WorkloadIdentity, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	items, ok := c.items[node]
	return items, ok
}
