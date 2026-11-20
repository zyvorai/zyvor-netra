// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package talkers

import (
	"sort"
	"time"

	"github.com/zyvorai/netra/internal/models"
)

type Row struct {
	Destination string `json:"destination"`
	Packets     uint64 `json:"packets"`
	Bytes       uint64 `json:"bytes"`
	Blocked     uint64 `json:"blocked"`
	Nodes       int    `json:"nodes"`
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
		limit = 20
	}
	type acc struct {
		pkts, bytes, blocked uint64
		nodes                map[string]struct{}
	}
	m := map[string]*acc{}
	for _, a := range agents {
		for _, st := range a.Stats {
			ip := st.DestinationIP
			if ip == "" {
				continue
			}
			x := m[ip]
			if x == nil {
				x = &acc{nodes: map[string]struct{}{}}
				m[ip] = x
			}
			x.pkts += st.Packets
			x.bytes += st.Bytes
			x.blocked += st.Blocked
			if a.Node != "" {
				x.nodes[a.Node] = struct{}{}
			}
		}
	}
	out := Board{GeneratedAt: now.UTC()}
	for ip, x := range m {
		out.Rows = append(out.Rows, Row{Destination: ip, Packets: x.pkts, Bytes: x.bytes, Blocked: x.blocked, Nodes: len(x.nodes)})
	}
	sort.Slice(out.Rows, func(i, j int) bool {
		if out.Rows[i].Packets != out.Rows[j].Packets {
			return out.Rows[i].Packets > out.Rows[j].Packets
		}
		return out.Rows[i].Destination < out.Rows[j].Destination
	})
	if len(out.Rows) > limit {
		out.Rows = out.Rows[:limit]
	}
	out.Count = len(out.Rows)
	return out
}
