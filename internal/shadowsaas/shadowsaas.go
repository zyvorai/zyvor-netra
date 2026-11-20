// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

// Package shadowsaas ranks observed destinations that look like SaaS /
// GenAI against an operator sanctioned-host allow-list. Observe-only;
// optional leased deny is a separate API step. Metadata only — no CASB
// content inspection.
package shadowsaas

import (
	"sort"
	"strings"

	"github.com/zyvorai/netra/internal/ainet"
	"github.com/zyvorai/netra/internal/appcat"
	"github.com/zyvorai/netra/internal/models"
)

// DefaultSanctioned is a small enterprise baseline when NETRA_SANCTIONED_HOSTS
// is unset. Operators should replace this with their real allow-list.
func DefaultSanctioned() []string {
	return []string{
		"office.com", "office365.com", "sharepoint.com", "microsoft.com",
		"okta.com", "auth0.com", "github.com", "githubusercontent.com",
		"slack.com", "atlassian.net", "zoom.us", "googleapis.com",
		"amazonaws.com", "azure.com", "windows.net",
	}
}

// ParseSanctioned splits a comma/whitespace list of hostname suffixes.
func ParseSanctioned(raw string) []string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	var out []string
	for _, p := range strings.FieldsFunc(raw, func(r rune) bool {
		return r == ',' || r == ' ' || r == '\n' || r == '\t' || r == ';'
	}) {
		p = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(p), "."))
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

// Finding is one unsanctioned (or unknown) destination.
type Finding struct {
	Host      string `json:"host"`
	Kind      string `json:"kind"` // sni | http-host | dns
	Category  string `json:"category,omitempty"`
	Label     string `json:"label,omitempty"`
	Status    string `json:"status"` // shadow | unknown | sanctioned
	Risk      string `json:"risk"`   // low | medium | high
	Node      string `json:"node,omitempty"`
	Namespace string `json:"namespace,omitempty"`
	Pod       string `json:"pod,omitempty"`
	Packets   uint64 `json:"packets,omitempty"`
	AIRelated bool   `json:"aiRelated,omitempty"`
	Rationale string `json:"rationale,omitempty"`
}

// Result is GET /api/v1/insights/shadow-saas.
type Result struct {
	Findings       []Finding `json:"findings"`
	Count          int       `json:"count"`
	Shadow         int       `json:"shadow"`
	Unknown        int       `json:"unknown"`
	SanctionedSeen int       `json:"sanctionedSeen"`
	SanctionedList int       `json:"sanctionedListSize"`
	Capped         bool      `json:"capped"`
	Note           string    `json:"note"`
}

const MaxFindings = 500

// Build compares live metadata hosts to sanctioned suffixes.
// sanctioned nil/empty → DefaultSanctioned().
func Build(agents []models.AgentStatus, sanctioned []string, limit int) Result {
	if limit <= 0 || limit > MaxFindings {
		limit = MaxFindings
	}
	if len(sanctioned) == 0 {
		sanctioned = DefaultSanctioned()
	}
	aiCat := ainet.DefaultCatalog()
	type key struct{ host, kind string }
	agg := map[key]*Finding{}

	consider := func(host, kind, node, ns, pod string, pkts uint64) {
		host = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
		if host == "" || !strings.Contains(host, ".") {
			return
		}
		k := key{host, kind}
		f := agg[k]
		if f == nil {
			f = &Finding{Host: host, Kind: kind, Node: node, Namespace: ns, Pod: pod}
			agg[k] = f
			if appcat.MatchHostSuffix(host, sanctioned) {
				f.Status = "sanctioned"
				f.Risk = "low"
				f.Rationale = "matches sanctioned host suffix"
			} else if e, ok := appcat.Lookup(host); ok {
				f.Category = string(e.Category)
				f.Label = e.Label
				switch e.Category {
				case appcat.CatSaaS, appcat.CatSocial, appcat.CatFinance:
					f.Status = "shadow"
					f.Risk = "high"
					f.Rationale = "known SaaS category not on sanctioned list"
				case appcat.CatDev:
					f.Status = "shadow"
					f.Risk = "medium"
					f.Rationale = "devtools destination not on sanctioned list"
				case appcat.CatCloud, appcat.CatCDN:
					f.Status = "shadow"
					f.Risk = "medium"
					f.Rationale = "cloud/CDN destination not on sanctioned list"
				default:
					f.Status = "shadow"
					f.Risk = "medium"
				}
			} else {
				f.Status = "unknown"
				f.Risk = "medium"
				f.Rationale = "hostname not in app catalog and not sanctioned"
			}
			if ae, ok := lookupAI(aiCat, host); ok {
				f.AIRelated = true
				f.Status = "shadow"
				f.Risk = "high"
				f.Label = ae.Label
				f.Category = string(ae.Category)
				f.Rationale = "GenAI/MCP SaaS destination not on sanctioned list"
			}
		}
		f.Packets += pkts
		if ns != "" {
			f.Namespace = ns
		}
		if pod != "" {
			f.Pod = pod
		}
		if node != "" {
			f.Node = node
		}
	}

	for _, a := range agents {
		if a.Stale {
			continue
		}
		for _, t := range a.TLSMetadata {
			consider(t.SNI, "sni", a.Node, t.Namespace, t.Pod, t.Handshakes)
		}
		for _, h := range a.HTTPMetadata {
			consider(h.Host, "http-host", a.Node, h.Namespace, h.Pod, h.Requests)
		}
		for _, d := range a.DNSHealth {
			consider(d.Name, "dns", a.Node, d.Namespace, d.Pod, d.Queries)
		}
	}

	out := Result{
		Findings: []Finding{}, SanctionedList: len(sanctioned),
		Note: "CASB-lite: metadata hostnames vs sanctioned suffixes. No content inspection. Set NETRA_SANCTIONED_HOSTS to override defaults.",
	}
	for _, f := range agg {
		switch f.Status {
		case "shadow":
			out.Shadow++
		case "unknown":
			out.Unknown++
		case "sanctioned":
			out.SanctionedSeen++
			continue // board focuses on unsanctioned; count only
		}
		out.Findings = append(out.Findings, *f)
	}
	sort.Slice(out.Findings, func(i, j int) bool {
		ri, rj := riskRank(out.Findings[i].Risk), riskRank(out.Findings[j].Risk)
		if ri != rj {
			return ri > rj
		}
		return out.Findings[i].Packets > out.Findings[j].Packets
	})
	if len(out.Findings) > limit {
		out.Findings = out.Findings[:limit]
		out.Capped = true
	}
	out.Count = len(out.Findings)
	return out
}

func lookupAI(catalog []ainet.CatalogEntry, host string) (ainet.CatalogEntry, bool) {
	h := strings.ToLower(strings.TrimSuffix(host, "."))
	bestLen := -1
	var best ainet.CatalogEntry
	for _, e := range catalog {
		suf := strings.ToLower(e.Suffix)
		if h == suf || strings.HasSuffix(h, "."+suf) {
			if len(suf) > bestLen {
				best = e
				bestLen = len(suf)
			}
		}
	}
	if bestLen < 0 {
		return ainet.CatalogEntry{}, false
	}
	return best, true
}

func riskRank(r string) int {
	switch r {
	case "high":
		return 3
	case "medium":
		return 2
	default:
		return 1
	}
}
