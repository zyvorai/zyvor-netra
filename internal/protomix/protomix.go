// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package protomix

import (
	"sort"
	"strings"
	"time"

	"github.com/zyvorai/netra/internal/models"
)

type Row struct {
	Protocol string `json:"protocol"`
	Packets  uint64 `json:"packets"`
	Bytes    uint64 `json:"bytes"`
	Blocked  uint64 `json:"blocked"`
	Flows    int    `json:"flows"`
}

type Mix struct {
	GeneratedAt time.Time `json:"generatedAt"`
	Rows        []Row     `json:"rows"`
}

func Build(agents []models.AgentStatus, now time.Time) Mix {
	if now.IsZero() {
		now = time.Now().UTC()
	}
	type acc struct {
		pkts, bytes, blocked uint64
		flows                int
	}
	m := map[string]*acc{}
	for _, a := range agents {
		for _, st := range a.Stats {
			p := strings.ToUpper(strings.TrimSpace(st.Protocol))
			if p == "" {
				p = "UNKNOWN"
			}
			x := m[p]
			if x == nil {
				x = &acc{}
				m[p] = x
			}
			x.pkts += st.Packets
			x.bytes += st.Bytes
			x.blocked += st.Blocked
			x.flows++
		}
	}
	out := Mix{GeneratedAt: now.UTC()}
	for p, x := range m {
		out.Rows = append(out.Rows, Row{Protocol: p, Packets: x.pkts, Bytes: x.bytes, Blocked: x.blocked, Flows: x.flows})
	}
	sort.Slice(out.Rows, func(i, j int) bool {
		if out.Rows[i].Packets != out.Rows[j].Packets {
			return out.Rows[i].Packets > out.Rows[j].Packets
		}
		return out.Rows[i].Protocol < out.Rows[j].Protocol
	})
	return out
}
