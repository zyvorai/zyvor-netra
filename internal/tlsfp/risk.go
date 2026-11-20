// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package tlsfp

import (
	"sort"
	"strings"
)

// RiskItem is one rare / noteworthy fingerprint for the risk board.
type RiskItem struct {
	JA3      string   `json:"ja3"`
	JA4      string   `json:"ja4,omitempty"`
	SNI      string   `json:"sni,omitempty"`
	Node     string   `json:"node,omitempty"`
	Count    uint64   `json:"count"`
	ECH      bool     `json:"ech,omitempty"`
	Severity string   `json:"severity"`
	Reasons  []string `json:"reasons"`
}

// RiskBoard ranks rare JA3s and ECH sightings. Observe-only.
type RiskBoard struct {
	Items        []RiskItem `json:"items"`
	Count        int        `json:"count"`
	UniqueJA3    int        `json:"uniqueJa3"`
	ECHSightings int        `json:"echSightings"`
	Rare         int        `json:"rare"`
	Note         string     `json:"note"`
}

// Risk builds a board from detector observations. Rare = seen ≤ rareMax times.
func (d *Detector) Risk(limit int, rareMax uint64) RiskBoard {
	if rareMax == 0 {
		rareMax = 2
	}
	if limit <= 0 {
		limit = 100
	}
	out := RiskBoard{
		Items: []RiskItem{},
		Note:  "JA3/JA4 from datapath ClientHello samples (tls_hello_events via netra_tlsfp, rate-limited) and capture-stream frames. Single-skb, no decrypt. ECH ext 0xfe0d flagged when present.",
	}
	if d == nil {
		out.Note = "TLS fingerprint detector disabled."
		return out
	}
	snap := d.Snapshot(0)
	out.UniqueJA3 = len(snap)
	for _, o := range snap {
		if o.ECH {
			out.ECHSightings++
		}
		reasons := []string{}
		sev := "info"
		if o.Count <= rareMax {
			reasons = append(reasons, "rare-fingerprint")
			sev = "medium"
			out.Rare++
		}
		if o.ECH {
			reasons = append(reasons, "ech-extension")
			sev = "high"
		}
		if o.SNI == "" && o.Count > 0 {
			reasons = append(reasons, "missing-sni")
			if sev == "info" {
				sev = "medium"
			}
		}
		if len(reasons) == 0 {
			continue
		}
		out.Items = append(out.Items, RiskItem{
			JA3: o.JA3, JA4: o.JA4, SNI: o.SNI, Node: o.Node, Count: o.Count,
			ECH: o.ECH, Severity: sev, Reasons: reasons,
		})
	}
	sort.Slice(out.Items, func(i, j int) bool {
		si, sj := sevRank(out.Items[i].Severity), sevRank(out.Items[j].Severity)
		if si != sj {
			return si > sj
		}
		return out.Items[i].Count < out.Items[j].Count
	})
	if len(out.Items) > limit {
		out.Items = out.Items[:limit]
	}
	out.Count = len(out.Items)
	return out
}

func sevRank(s string) int {
	switch strings.ToLower(s) {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	default:
		return 1
	}
}
