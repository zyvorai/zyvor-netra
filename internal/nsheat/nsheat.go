// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package nsheat

import (
	"sort"
	"time"

	"github.com/zyvorai/netra/internal/models"
)

type Row struct {
	Namespace string `json:"namespace"`
	Packets   uint64 `json:"packets"`
	Bytes     uint64 `json:"bytes"`
	Blocked   uint64 `json:"blocked"`
	Dests     int    `json:"destinations"`
}

type Board struct {
	GeneratedAt time.Time `json:"generatedAt"`
	Rows        []Row     `json:"rows"`
	Count       int       `json:"count"`
}

func Build(agents []models.AgentStatus, now time.Time, limit int) Board {
	if now.IsZero() {
		now = time.Now().UTC()
	}
	if limit <= 0 || limit > 200 {
		limit = 30
	}
	type acc struct {
		pkts, bytes, blocked uint64
		dests                map[string]struct{}
	}
	m := map[string]*acc{}
	for _, a := range agents {
		for _, st := range a.Stats {
			ns := st.Namespace
			if ns == "" {
				ns = "(unlabeled)"
			}
			x := m[ns]
			if x == nil {
				x = &acc{dests: map[string]struct{}{}}
				m[ns] = x
			}
			x.pkts += st.Packets
			x.bytes += st.Bytes
			x.blocked += st.Blocked
			if st.DestinationIP != "" {
				x.dests[st.DestinationIP] = struct{}{}
			}
		}
	}
	out := Board{GeneratedAt: now.UTC()}
	for ns, x := range m {
		out.Rows = append(out.Rows, Row{Namespace: ns, Packets: x.pkts, Bytes: x.bytes, Blocked: x.blocked, Dests: len(x.dests)})
	}
	sort.Slice(out.Rows, func(i, j int) bool {
		if out.Rows[i].Packets != out.Rows[j].Packets {
			return out.Rows[i].Packets > out.Rows[j].Packets
		}
		return out.Rows[i].Namespace < out.Rows[j].Namespace
	})
	if len(out.Rows) > limit {
		out.Rows = out.Rows[:limit]
	}
	out.Count = len(out.Rows)
	return out
}
