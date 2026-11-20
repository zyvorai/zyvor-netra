// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package securityreview

import (
	"github.com/zyvorai/netra/internal/dnsdetect"
	"github.com/zyvorai/netra/internal/intel"
	"github.com/zyvorai/netra/internal/models"
	"github.com/zyvorai/netra/internal/scandetect"
	"sort"
	"time"
)

type Evidence struct {
	ID      string    `json:"id"`
	Kind    string    `json:"kind"`
	Message string    `json:"message"`
	At      time.Time `json:"at"`
}
type Incident struct {
	ID        string     `json:"id"`
	Node      string     `json:"node"`
	Namespace string     `json:"namespace"`
	Pod       string     `json:"pod"`
	LastSeen  time.Time  `json:"lastSeen"`
	Evidence  []Evidence `json:"evidence"`
}
type Incidents struct {
	Items       []Incident `json:"items"`
	AutoApplied bool       `json:"autoApplied"`
	Truncated   bool       `json:"truncated"`
	Note        string     `json:"note"`
}

// Correlate requires exact node/namespace/pod and two different evidence kinds
// in the last ten minutes. No approximate joins or causal/attack verdicts.
func Correlate(agents []models.AgentStatus, dns []dnsdetect.Finding, scan []scandetect.Finding, entries []intel.Entry, now time.Time) Incidents {
	out := Incidents{Items: []Incident{}, Note: "Temporal correlation of independent evidence kinds on the exact node/namespace/pod within ten minutes. Signals may be unrelated; this does not prove an attack or causality."}
	live := map[string]bool{}
	for _, a := range agents {
		if !a.Stale {
			live[a.Node] = true
		}
	}
	groups := map[string]*Incident{}
	seen := map[string]bool{}
	add := func(node, ns, pod string, e Evidence) {
		if !live[node] || ns == "" || pod == "" || !recent(e.At, now) {
			return
		}
		key := stableID([]string{node, ns, pod})
		e.ID = stableID([]any{key, e.Kind, e.ID, e.At, e.Message})
		if seen[e.ID] {
			return
		}
		seen[e.ID] = true
		g := groups[key]
		if g == nil {
			g = &Incident{ID: key, Node: node, Namespace: ns, Pod: pod, Evidence: []Evidence{}}
			groups[key] = g
		}
		g.Evidence = append(g.Evidence, e)
		if e.At.After(g.LastSeen) {
			g.LastSeen = e.At
		}
	}
	for _, f := range dns {
		add(f.Node, f.Namespace, f.Pod, Evidence{ID: f.ID, Kind: "dns", Message: string(f.Type) + ": " + f.Domain, At: f.LastSeen})
	}
	for _, f := range scan {
		add(f.Node, f.Namespace, f.Pod, Evidence{ID: f.ID, Kind: "scan", Message: string(f.Type), At: f.LastSeen})
	}
	for _, a := range agents {
		if a.Stale {
			continue
		}
		for _, e := range a.Events {
			if !recent(e.ObservedAt, now) {
				continue
			}
			for _, entry := range entries {
				if entry.Type != "ip" && entry.Type != "cidr" {
					continue
				}
				r := Rule{Type: entry.Type, Value: entry.Value, Direction: direction(entry.Direction)}
				if matches(r, e) {
					add(a.Node, e.Namespace, e.Pod, Evidence{ID: stableID([]any{e.TimestampNS, entry, e.SourceIP, e.DestinationIP, e.SourcePort, e.DestinationPort, e.Direction}), Kind: "intel", Message: "Observed endpoint matches " + entry.Type + " " + entry.Value, At: e.ObservedAt})
				}
			}
		}
	}
	for _, g := range groups {
		kinds := map[string]bool{}
		for _, e := range g.Evidence {
			kinds[e.Kind] = true
		}
		if len(kinds) < 2 {
			continue
		}
		sort.Slice(g.Evidence, func(i, j int) bool {
			a, b := g.Evidence[i], g.Evidence[j]
			if !a.At.Equal(b.At) {
				return a.At.After(b.At)
			}
			return a.ID < b.ID
		})
		if len(g.Evidence) > 50 {
			// Retain at least one item of each independent evidence kind.
			selected := []Evidence{}
			used := map[string]bool{}
			selectedIDs := map[string]bool{}
			for _, e := range g.Evidence {
				if !used[e.Kind] {
					used[e.Kind] = true
					selectedIDs[e.ID] = true
					selected = append(selected, e)
				}
			}
			for _, e := range g.Evidence {
				if len(selected) == 50 {
					break
				}
				if !selectedIDs[e.ID] {
					selected = append(selected, e)
				}
			}
			g.Evidence = selected
			sort.Slice(g.Evidence, func(i, j int) bool {
				a, b := g.Evidence[i], g.Evidence[j]
				if !a.At.Equal(b.At) {
					return a.At.After(b.At)
				}
				return a.ID < b.ID
			})
			out.Truncated = true
		}
		out.Items = append(out.Items, *g)
	}
	sort.Slice(out.Items, func(i, j int) bool {
		a, b := out.Items[i], out.Items[j]
		if !a.LastSeen.Equal(b.LastSeen) {
			return a.LastSeen.After(b.LastSeen)
		}
		return a.ID < b.ID
	})
	if len(out.Items) > 200 {
		out.Items = out.Items[:200]
		out.Truncated = true
	}
	return out
}
