// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package portheat

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/zyvorai/netra/internal/models"
)

type Row struct {
	Port     uint16 `json:"port"`
	Protocol string `json:"protocol"`
	Key      string `json:"key"`
	Packets  uint64 `json:"packets"`
	Blocked  uint64 `json:"blocked"`
	Flows    int    `json:"flows"`
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
		pkts, blocked uint64
		flows         int
		port          uint16
		proto         string
	}
	m := map[string]*acc{}
	for _, a := range agents {
		for _, st := range a.Stats {
			proto := strings.ToUpper(strings.TrimSpace(st.Protocol))
			if proto == "" {
				proto = "UNKNOWN"
			}
			key := fmt.Sprintf("%s/%d", proto, st.Port)
			x := m[key]
			if x == nil {
				x = &acc{port: st.Port, proto: proto}
				m[key] = x
			}
			x.pkts += st.Packets
			x.blocked += st.Blocked
			x.flows++
		}
	}
	out := Board{GeneratedAt: now.UTC()}
	for key, x := range m {
		out.Rows = append(out.Rows, Row{Port: x.port, Protocol: x.proto, Key: key, Packets: x.pkts, Blocked: x.blocked, Flows: x.flows})
	}
	sort.Slice(out.Rows, func(i, j int) bool {
		if out.Rows[i].Packets != out.Rows[j].Packets {
			return out.Rows[i].Packets > out.Rows[j].Packets
		}
		return out.Rows[i].Key < out.Rows[j].Key
	})
	if len(out.Rows) > limit {
		out.Rows = out.Rows[:limit]
	}
	out.Count = len(out.Rows)
	return out
}
