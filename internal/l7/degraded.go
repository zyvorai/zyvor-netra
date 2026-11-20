// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package l7

import (
	"sort"

	"github.com/zyvorai/netra/internal/models"
)

// l7ProgramNames mirrors internal/agent/agent.go's l7Progs — the two BPF
// program names this datapath's L7 (TLS SNI / HTTP Host) observability
// depends on.
var l7ProgramNames = []string{"netra_l7_cgroup_ingress", "netra_l7_cgroup_egress"}

// Degraded reports whether any non-stale agent's currently-loaded BPF
// programs are missing an L7 program by name. This must be checked by
// name-absence, not Attached:false: when netra_l7_cgroup_egress fails
// kernel verifier load (a real, observed failure — see docs/l7-metadata.md
// — a fixed jump-history limit on some kernels, not a proportional
// complexity budget), internal/agent/agent.go deletes it from the
// collection before reload, so it is entirely absent from
// AgentReport.Programs rather than present with Attached:false. A quiet
// TLS/HTTP metadata feed on a degraded node must never be read as "no
// activity" — it may just mean Netra can't see it right now.
func Degraded(agents []models.AgentStatus) (degraded bool, nodes []string) {
	for _, a := range agents {
		if a.Stale {
			continue
		}
		present := make(map[string]bool, len(a.Programs))
		for _, p := range a.Programs {
			present[p.Name] = true
		}
		for _, name := range l7ProgramNames {
			if !present[name] {
				degraded = true
				nodes = append(nodes, a.Node)
				break
			}
		}
	}
	sort.Strings(nodes)
	return degraded, nodes
}
