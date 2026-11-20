// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

// Package destrisk ranks destinations by combined risk signals: threat
// intel hits, external exposure volume, app/AI category, encrypted DNS.
// Observe-only.
package destrisk

import (
	"net/netip"
	"sort"
	"strings"

	"github.com/zyvorai/netra/internal/ainet"
	"github.com/zyvorai/netra/internal/appcat"
	"github.com/zyvorai/netra/internal/encdns"
	"github.com/zyvorai/netra/internal/intel"
	"github.com/zyvorai/netra/internal/models"
	"github.com/zyvorai/netra/internal/watchlist"
)

// Item is one ranked destination.
type Item struct {
	Destination  string   `json:"destination"`
	Kind         string   `json:"kind"` // ip | host
	Score        int      `json:"score"`
	Severity     string   `json:"severity"`
	Reasons      []string `json:"reasons"`
	Category     string   `json:"category,omitempty"`
	Label        string   `json:"label,omitempty"`
	Packets      uint64   `json:"packets,omitempty"`
	IntelHit     bool     `json:"intelHit,omitempty"`
	AIRelated    bool     `json:"aiRelated,omitempty"`
	EncryptedDNS bool     `json:"encryptedDns,omitempty"`
	External     bool     `json:"external,omitempty"`
}

// Result is GET /api/v1/insights/destination-risk.
type Result struct {
	Destinations []Item `json:"destinations"`
	Count        int    `json:"count"`
	Capped       bool   `json:"capped"`
	Note         string `json:"note"`
}

const MaxItems = 500

// Build merges intel, categories, AI, DoH/DoT, and traffic volume.
func Build(agents []models.AgentStatus, intelFeed []intel.Entry, limit int) Result {
	if limit <= 0 || limit > MaxItems {
		limit = MaxItems
	}
	type agg struct {
		kind     string
		packets  uint64
		reasons  map[string]bool
		cat, lab string
		intel    bool
		ai       bool
		encdns   bool
		external bool
		score    int
	}
	by := map[string]*agg{}
	ensure := func(dest, kind string) *agg {
		a := by[dest]
		if a == nil {
			a = &agg{kind: kind, reasons: map[string]bool{}}
			by[dest] = a
		}
		return a
	}

	// Traffic volume by IP.
	for _, a := range agents {
		if a.Stale {
			continue
		}
		for _, st := range a.Stats {
			if st.DestinationIP == "" {
				continue
			}
			x := ensure(st.DestinationIP, "ip")
			x.packets += st.Packets
			if addr, err := netip.ParseAddr(st.DestinationIP); err == nil && !addr.IsPrivate() && !addr.IsLoopback() && !addr.IsLinkLocalUnicast() {
				x.external = true
			}
		}
	}

	// Host metadata.
	for _, a := range agents {
		if a.Stale {
			continue
		}
		for _, t := range a.TLSMetadata {
			host := norm(t.SNI)
			if host == "" {
				continue
			}
			x := ensure(host, "host")
			x.packets += t.Handshakes
			x.external = true
			if e, ok := appcat.Lookup(host); ok {
				x.cat, x.lab = string(e.Category), e.Label
				switch e.Category {
				case appcat.CatSaaS, appcat.CatSocial, appcat.CatFinance:
					x.score += 15
					x.reasons["saas-category"] = true
				case appcat.CatDev:
					x.score += 8
					x.reasons["devtools-category"] = true
				}
			}
			if ae, ok := aiLookup(host); ok {
				x.ai = true
				x.score += 25
				x.lab = ae.Label
				x.cat = string(ae.Category)
				x.reasons["ai-mcp-destination"] = true
			}
		}
		for _, h := range a.HTTPMetadata {
			host := norm(h.Host)
			if host == "" {
				continue
			}
			x := ensure(host, "host")
			x.packets += h.Requests
			x.external = true
			if e, ok := appcat.Lookup(host); ok && x.cat == "" {
				x.cat, x.lab = string(e.Category), e.Label
			}
		}
	}

	// Encrypted DNS.
	ed := encdns.Match(agents, encdns.MaxHits)
	for _, h := range ed.Hits {
		dest := h.Host
		if dest == "" {
			dest = h.DestIP
		}
		if dest == "" {
			continue
		}
		x := ensure(dest, kindOf(dest))
		x.encdns = true
		x.score += 20
		x.packets += h.Packets
		x.reasons["encrypted-dns"] = true
	}

	// Intel hits.
	if len(intelFeed) > 0 {
		match := watchlist.Match(agents, intelFeed, watchlist.MaxHits)
		for _, hit := range match.Hits {
			dest := hit.Value
			if dest == "" {
				continue
			}
			x := ensure(dest, hit.Type)
			if x.kind == "" {
				x.kind = hit.Type
			}
			x.intel = true
			x.score += 40
			x.packets += hit.Packets
			x.reasons["threat-intel-hit"] = true
		}
	}

	out := Result{
		Destinations: []Item{},
		Note:         "Combined destination risk from intel, categories, AI/MCP, DoH/DoT, and volume. Observe-only.",
	}
	for dest, x := range by {
		if x.external {
			x.score += 5
			x.reasons["external"] = true
		}
		// Volume bump (log-ish).
		switch {
		case x.packets > 100000:
			x.score += 15
			x.reasons["high-volume"] = true
		case x.packets > 10000:
			x.score += 8
			x.reasons["elevated-volume"] = true
		}
		if x.score == 0 && !x.external {
			continue // skip boring private low-signal
		}
		if x.score > 100 {
			x.score = 100
		}
		it := Item{
			Destination: dest, Kind: x.kind, Score: x.score, Severity: sev(x.score),
			Category: x.cat, Label: x.lab, Packets: x.packets,
			IntelHit: x.intel, AIRelated: x.ai, EncryptedDNS: x.encdns, External: x.external,
		}
		for r := range x.reasons {
			it.Reasons = append(it.Reasons, r)
		}
		sort.Strings(it.Reasons)
		out.Destinations = append(out.Destinations, it)
	}
	sort.Slice(out.Destinations, func(i, j int) bool {
		if out.Destinations[i].Score != out.Destinations[j].Score {
			return out.Destinations[i].Score > out.Destinations[j].Score
		}
		return out.Destinations[i].Packets > out.Destinations[j].Packets
	})
	if len(out.Destinations) > limit {
		out.Destinations = out.Destinations[:limit]
		out.Capped = true
	}
	out.Count = len(out.Destinations)
	return out
}

func norm(h string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(h), "."))
}

func kindOf(s string) string {
	if _, err := netip.ParseAddr(s); err == nil {
		return "ip"
	}
	return "host"
}

func aiLookup(host string) (ainet.CatalogEntry, bool) {
	h := norm(host)
	bestLen := -1
	var best ainet.CatalogEntry
	for _, e := range ainet.DefaultCatalog() {
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

func sev(score int) string {
	switch {
	case score >= 70:
		return "critical"
	case score >= 45:
		return "high"
	case score >= 25:
		return "medium"
	default:
		return "low"
	}
}
