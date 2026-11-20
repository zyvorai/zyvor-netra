// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package dnsboard

import (
	"sort"
	"strings"
	"time"

	"github.com/zyvorai/netra/internal/models"
)

type Row struct {
	Name      string  `json:"name"`
	Queries   uint64  `json:"queries"`
	Responses uint64  `json:"responses"`
	Failures  uint64  `json:"failures"`
	FailRate  float64 `json:"failRate"`
}

type Board struct {
	GeneratedAt time.Time `json:"generatedAt"`
	Rows        []Row     `json:"rows"`
	Queries     uint64    `json:"queries"`
	Failures    uint64    `json:"failures"`
}

func Build(agents []models.AgentStatus, now time.Time, limit int) Board {
	if now.IsZero() {
		now = time.Now().UTC()
	}
	if limit <= 0 || limit > 200 {
		limit = 30
	}
	type acc struct{ q, r, f uint64 }
	m := map[string]*acc{}
	out := Board{GeneratedAt: now.UTC()}
	for _, a := range agents {
		for _, d := range a.DNSHealth {
			name := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(d.Name), "."))
			if name == "" {
				continue
			}
			x := m[name]
			if x == nil {
				x = &acc{}
				m[name] = x
			}
			x.q += d.Queries
			x.r += d.Responses
			x.f += d.Failures
			out.Queries += d.Queries
			out.Failures += d.Failures
		}
	}
	for name, x := range m {
		rate := 0.0
		if x.q > 0 {
			rate = float64(x.f) / float64(x.q)
		}
		out.Rows = append(out.Rows, Row{Name: name, Queries: x.q, Responses: x.r, Failures: x.f, FailRate: rate})
	}
	sort.Slice(out.Rows, func(i, j int) bool {
		if out.Rows[i].Failures != out.Rows[j].Failures {
			return out.Rows[i].Failures > out.Rows[j].Failures
		}
		return out.Rows[i].Name < out.Rows[j].Name
	})
	if len(out.Rows) > limit {
		out.Rows = out.Rows[:limit]
	}
	return out
}
