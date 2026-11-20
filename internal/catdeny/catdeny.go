// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

// Package catdeny builds review-only leased SNI/DNS deny drafts from
// app-category hits (e.g. block social/saas shadow). Never auto-applied.
package catdeny

import (
	"fmt"
	"sort"
	"strings"

	"github.com/zyvorai/netra/internal/appcat"
	"github.com/zyvorai/netra/internal/models"
)

// Draft is one category-based deny suggestion.
type Draft struct {
	ID        string          `json:"id"`
	Category  appcat.Category `json:"category"`
	Host      string          `json:"host"`
	Label     string          `json:"label,omitempty"`
	Severity  string          `json:"severity"`
	Operation string          `json:"operation"` // deny-sni | deny-dns
	Body      map[string]any  `json:"body"`
	CLI       string          `json:"cli"`
	Rationale string          `json:"rationale"`
}

// Result is GET /api/v1/insights/category-deny.
type Result struct {
	Drafts []Draft `json:"drafts"`
	Count  int     `json:"count"`
	Capped bool    `json:"capped"`
	Note   string  `json:"note"`
}

const MaxDrafts = 100

// DefaultTargets are categories commonly blocked in shadow-SaaS policies.
func DefaultTargets() []appcat.Category {
	return []appcat.Category{appcat.CatSocial, appcat.CatFinance}
}

// Build drafts leased denies for hosts in target categories.
func Build(agents []models.AgentStatus, targets []appcat.Category, limit int) Result {
	if limit <= 0 || limit > MaxDrafts {
		limit = MaxDrafts
	}
	if len(targets) == 0 {
		targets = DefaultTargets()
	}
	want := map[appcat.Category]bool{}
	for _, c := range targets {
		want[c] = true
	}
	hits := appcat.Match(agents, nil, appcat.MaxHits)
	seen := map[string]bool{}
	out := Result{
		Drafts: []Draft{},
		Note:   "Review-only category deny drafts. Requires enforce lease to take effect. Prefer PacketWolf for durable policy.",
	}
	for _, h := range hits.Hits {
		if !want[h.Category] {
			continue
		}
		host := strings.ToLower(h.Host)
		if host == "" || seen[host] {
			continue
		}
		seen[host] = true
		if len(out.Drafts) >= limit {
			out.Capped = true
			break
		}
		id := fmt.Sprintf("cat-%s-%s", h.Category, host)
		out.Drafts = append(out.Drafts, Draft{
			ID: id, Category: h.Category, Host: host, Label: h.Label,
			Severity: "medium", Operation: "deny-sni",
			Body:      map[string]any{"sni": host, "direction": "egress"},
			CLI:       "netractl ebpf sni add " + host + " egress",
			Rationale: fmt.Sprintf("Category %s (%s) — draft leased SNI deny after review", h.Category, h.Label),
		})
	}
	sort.Slice(out.Drafts, func(i, j int) bool {
		if out.Drafts[i].Category != out.Drafts[j].Category {
			return out.Drafts[i].Category < out.Drafts[j].Category
		}
		return out.Drafts[i].Host < out.Drafts[j].Host
	})
	out.Count = len(out.Drafts)
	return out
}
