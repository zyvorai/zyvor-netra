//go:build linux

// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package agent

import (
	"fmt"
	"math"
	"strings"

	"github.com/zyvorai/netra/internal/models"
	"github.com/zyvorai/netra/internal/procmeta"
)

// applyExeHashGate clears and rewrites exehash_pids from BlockedExeHashes
// against current /proc exe digests (procmeta). Same TOCTOU shape as
// applyCapabilityGate — fails open when not enforcing.
func (a *Agent) applyExeHashGate(cfg models.EBPFFastPathConfig) error {
	m := a.collection.Maps["exehash_pids"]
	if m == nil {
		return fmt.Errorf("map exehash_pids unavailable")
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
	if !a.procMetaEnabled || len(cfg.BlockedExeHashes) == 0 {
		return nil
	}
	want := make(map[string]struct{}, len(cfg.BlockedExeHashes))
	for _, h := range cfg.BlockedExeHashes {
		h = strings.ToLower(strings.TrimSpace(h))
		if h != "" {
			want[h] = struct{}{}
		}
	}
	pids, err := procmeta.ListPIDs()
	if err != nil {
		return err
	}
	for _, pid := range pids {
		meta, err := procMetaCache.Get(pid)
		if err != nil || meta.ExeHash == "" {
			continue
		}
		if _, ok := want[strings.ToLower(meta.ExeHash)]; !ok {
			continue
		}
		if pid > 0 && pid <= math.MaxInt32 {
			if err := m.Put(uint32(pid), uint8(1)); err != nil {
				return err
			}
		}
	}
	return nil
}
