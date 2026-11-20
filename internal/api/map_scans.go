// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package api

import (
	"fmt"
	"sort"

	"github.com/zyvorai/netra/internal/models"
)

// writeMapScanMetrics adds what the agents' BPF map reads cost, worst node per
// map, so an expensive collection is a number on a dashboard instead of something
// found with strace. The only label is the map name, of which there are a handful.
func writeMapScanMetrics(w interface{ Write([]byte) (int, error) }, agents []models.AgentStatus) {
	type worst struct {
		millis    float64
		entries   int
		unbatched int
	}
	by := map[string]*worst{}
	for _, a := range agents {
		if a.Stale {
			continue
		}
		for _, s := range a.MapScans {
			x := by[s.Map]
			if x == nil {
				x = &worst{}
				by[s.Map] = x
			}
			if s.Millis > x.millis {
				x.millis = s.Millis
			}
			if s.Entries > x.entries {
				x.entries = s.Entries
			}
			if !s.Batched {
				x.unbatched++
			}
		}
	}
	if len(by) == 0 {
		return
	}
	names := make([]string, 0, len(by))
	for n := range by {
		names = append(names, n)
	}
	sort.Strings(names)
	emit := func(metric, help string, val func(*worst) string) {
		fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s gauge\n", metric, help, metric)
		for _, n := range names {
			fmt.Fprintf(w, "%s{map=\"%s\"} %s\n", metric, promLabel(n), val(by[n]))
		}
	}
	emit("netra_agent_map_scan_millis_max", "Wall time of the slowest node's latest read of this BPF map, in milliseconds.",
		func(x *worst) string { return fmt.Sprintf("%.3f", x.millis) })
	emit("netra_agent_map_scan_entries_max", "Entries in this BPF map at the fullest node's latest read.",
		func(x *worst) string { return fmt.Sprintf("%d", x.entries) })
	emit("netra_agent_map_scan_unbatched_nodes", "Nodes whose kernel refused batch lookup for this map, so the agent reads it entry by entry (about 100x more syscalls).",
		func(x *worst) string { return fmt.Sprintf("%d", x.unbatched) })
}
