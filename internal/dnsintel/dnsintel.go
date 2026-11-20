// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

// Package dnsintel ranks DNS / SNI / Host names against the threat-intel
// feed with suffix matching and light C2-style heuristics (high NXDOMAIN /
// failure ratio, long random labels). Observe-only; leased deny is a
// separate API step.
package dnsintel

import (
	"sort"
	"strings"
	"unicode"

	"github.com/zyvorai/netra/internal/intel"
	"github.com/zyvorai/netra/internal/models"
)

// Hit is one domain-focused intel or heuristic finding.
type Hit struct {
	Host       string `json:"host"`
	Kind       string `json:"kind"` // intel-dns | intel-sni | heuristic-nx | heuristic-dga
	Severity   string `json:"severity"`
	FeedValue  string `json:"feedValue,omitempty"`
	Node       string `json:"node,omitempty"`
	Namespace  string `json:"namespace,omitempty"`
	Pod        string `json:"pod,omitempty"`
	Queries    uint64 `json:"queries,omitempty"`
	Failures   uint64 `json:"failures,omitempty"`
	Handshakes uint64 `json:"handshakes,omitempty"`
	Rationale  string `json:"rationale"`
	LeaseHint  string `json:"leaseHint,omitempty"` // dns | sni
}

// Result is GET /api/v1/intel/dns-hits.
type Result struct {
	Hits      []Hit  `json:"hits"`
	Count     int    `json:"count"`
	Intel     int    `json:"intelHits"`
	Heuristic int    `json:"heuristicHits"`
	Capped    bool   `json:"capped"`
	Note      string `json:"note"`
}

const MaxHits = 500

// Build matches feed dns/sni entries (exact + suffix) and adds heuristics.
func Build(agents []models.AgentStatus, feed []intel.Entry, limit int) Result {
	if limit <= 0 || limit > MaxHits {
		limit = MaxHits
	}
	out := Result{
		Hits: []Hit{},
		Note: "DNS/C2-style domain board from intel feed + failure/DGA heuristics. Metadata only. Apply leased deny via intel/apply or ebpf deny.",
	}
	var domains, snis []intel.Entry
	for _, e := range feed {
		switch e.Type {
		case "dns", "domain", "fqdn":
			domains = append(domains, e)
		case "sni":
			snis = append(snis, e)
		}
	}

	seen := map[string]bool{}
	add := func(h Hit) {
		key := h.Kind + "|" + h.Host + "|" + h.Namespace + "|" + h.Pod
		if seen[key] || len(out.Hits) >= limit {
			if len(out.Hits) >= limit {
				out.Capped = true
			}
			return
		}
		seen[key] = true
		out.Hits = append(out.Hits, h)
		if strings.HasPrefix(h.Kind, "intel") {
			out.Intel++
		} else {
			out.Heuristic++
		}
	}

	for _, a := range agents {
		if a.Stale {
			continue
		}
		for _, d := range a.DNSHealth {
			host := norm(d.Name)
			if host == "" {
				continue
			}
			if e, ok := matchSuffix(domains, host); ok {
				add(Hit{
					Host: host, Kind: "intel-dns", Severity: "high", FeedValue: e.Value,
					Node: a.Node, Namespace: d.Namespace, Pod: d.Pod,
					Queries: d.Queries, Failures: d.Failures,
					Rationale: "DNS name matches threat-intel feed (exact or suffix)",
					LeaseHint: "dns",
				})
			}
			if d.Queries >= 5 && d.Failures*2 >= d.Queries {
				add(Hit{
					Host: host, Kind: "heuristic-nx", Severity: "medium",
					Node: a.Node, Namespace: d.Namespace, Pod: d.Pod,
					Queries: d.Queries, Failures: d.Failures,
					Rationale: "High DNS failure ratio (possible sinkhole / DGA noise)",
					LeaseHint: "dns",
				})
			}
			if looksDGA(host) {
				add(Hit{
					Host: host, Kind: "heuristic-dga", Severity: "medium",
					Node: a.Node, Namespace: d.Namespace, Pod: d.Pod,
					Queries:   d.Queries,
					Rationale: "Hostname looks algorithmically generated (long consonant-heavy label)",
					LeaseHint: "dns",
				})
			}
		}
		for _, t := range a.TLSMetadata {
			host := norm(t.SNI)
			if host == "" {
				continue
			}
			if e, ok := matchSuffix(append(snis, domains...), host); ok {
				add(Hit{
					Host: host, Kind: "intel-sni", Severity: "high", FeedValue: e.Value,
					Node: a.Node, Namespace: t.Namespace, Pod: t.Pod,
					Handshakes: t.Handshakes,
					Rationale:  "SNI matches threat-intel feed (exact or suffix)",
					LeaseHint:  "sni",
				})
			}
		}
	}

	sort.Slice(out.Hits, func(i, j int) bool {
		if out.Hits[i].Severity != out.Hits[j].Severity {
			return sev(out.Hits[i].Severity) > sev(out.Hits[j].Severity)
		}
		return out.Hits[i].Host < out.Hits[j].Host
	})
	out.Count = len(out.Hits)
	return out
}

func norm(s string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(s), "."))
}

func matchSuffix(entries []intel.Entry, host string) (intel.Entry, bool) {
	for _, e := range entries {
		want := norm(e.Value)
		if want == "" {
			continue
		}
		if host == want || strings.HasSuffix(host, "."+want) {
			return e, true
		}
	}
	return intel.Entry{}, false
}

func looksDGA(host string) bool {
	labels := strings.Split(host, ".")
	if len(labels) < 2 {
		return false
	}
	lab := labels[0]
	if len(lab) < 12 {
		return false
	}
	vowels, consonants, digits := 0, 0, 0
	for _, r := range lab {
		switch {
		case unicode.IsDigit(r):
			digits++
		case strings.ContainsRune("aeiou", unicode.ToLower(r)):
			vowels++
		case unicode.IsLetter(r):
			consonants++
		}
	}
	if digits > len(lab)/3 {
		return true
	}
	return consonants > vowels*3 && len(lab) >= 16
}

func sev(s string) int {
	switch s {
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
