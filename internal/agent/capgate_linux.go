//go:build linux

package agent

import (
	"fmt"
	"math"

	"github.com/zyvorai/netra/internal/models"
	"github.com/zyvorai/netra/internal/procmeta"
)

// applyCapabilityGate is a full clear-then-rewrite of capgate_pids (same
// convention as every other config map this agent pushes), gated behind
// the same NETRA_PROCMETA_ENABLED flag every other /proc-derived feature
// uses — this is a real expansion of what the agent reads from the host,
// same disclosure standard. When enabled and cfg.DeniedCapabilities is
// non-empty, it lists every PID currently on the node (procmeta.ListPIDs)
// and writes the ones whose effective capabilities currently intersect
// the configured deny set as a plain presence flag.
//
// This is a TOCTOU-caveated, agent-sourced signal, not a kernel credential
// read: a process's capabilities can change (drop or gain one) in the
// window between this scan and the socket() call socket4/socket6 actually
// checks capgate_pids against — see docs/capability-gated-deny.md.
func (a *Agent) applyCapabilityGate(cfg models.EBPFFastPathConfig) error {
	m := a.collection.Maps["capgate_pids"]
	if m == nil {
		return fmt.Errorf("map capgate_pids unavailable")
	}
	var oldKey uint32
	var oldVal uint8
	var stale []uint32
	it := m.Iterate()
	for it.Next(&oldKey, &oldVal) {
		stale = append(stale, oldKey)
	}
	if err := mapIterErr(it.Err()); err != nil {
		return err
	}
	for _, k := range stale {
		_ = m.Delete(k)
	}
	if !a.procMetaEnabled || len(cfg.DeniedCapabilities) == 0 {
		return nil
	}
	pids, err := procmeta.ListPIDs()
	if err != nil {
		return err
	}
	for _, pid := range pids {
		meta, err := procMetaCache.Get(pid)
		if err != nil {
			continue
		}
		if meta.Caps.HasAny(cfg.DeniedCapabilities...) {
			if pid > 0 && pid <= math.MaxInt32 {
				if err := m.Put(uint32(pid), uint8(1)); err != nil {
					return err
				}
			}
		}
	}
	return nil
}
