// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

// Package exfil ranks workloads by metadata exfiltration heuristics:
// destination fan-out, byte/packet volume, and rare external hosts.
// No payload / DLP inspection.
package exfil

import (
	"net/netip"
	"sort"
	"strings"

	"github.com/zyvorai/netra/internal/models"
)

// Finding is one workload exfil-risk row.
type Finding struct {
	Namespace    string   `json:"namespace,omitempty"`
	Pod          string   `json:"pod,omitempty"`
	WorkloadKind string   `json:"workloadKind,omitempty"`
	WorkloadName string   `json:"workloadName,omitempty"`
	Node         string   `json:"node,omitempty"`
	Score        int      `json:"score"`
	Severity     string   `json:"severity"`
	UniqueDsts   int      `json:"uniqueDestinations"`
	ExternalDsts int      `json:"externalDestinations"`
	Packets      uint64   `json:"packets"`
	Bytes        uint64   `json:"bytes,omitempty"`
	RareHosts    []string `json:"rareHosts,omitempty"`
	Signals      []string `json:"signals"`
	Rationale    string   `json:"rationale"`
}

// Result is GET /api/v1/insights/exfil.
type Result struct {
	Findings []Finding `json:"findings"`
	Count    int       `json:"count"`
	High     int       `json:"high"`
	Capped   bool      `json:"capped"`
	Note     string    `json:"note"`
}

const MaxFindings = 200

// Build aggregates per-workload fan-out and volume.
func Build(agents []models.AgentStatus, limit int) Result {
	if limit <= 0 || limit > MaxFindings {
		limit = MaxFindings
	}
	type key struct{ ns, pod, kind, name, node string }
	type agg struct {
		dsts    map[string]uint64
		packets uint64
		bytes   uint64
		hosts   map[string]uint64
	}
	by := map[key]*agg{}
	globalHost := map[string]int{} // host → workload count

	ensure := func(k key) *agg {
		if a := by[k]; a != nil {
			return a
		}
		a := &agg{dsts: map[string]uint64{}, hosts: map[string]uint64{}}
		by[k] = a
		return a
	}

	for _, a := range agents {
		if a.Stale {
			continue
		}
		for _, st := range a.Stats {
			k := key{st.Namespace, st.Pod, st.WorkloadKind, st.WorkloadName, a.Node}
			x := ensure(k)
			if st.DestinationIP != "" {
				x.dsts[st.DestinationIP] += st.Packets
			}
			x.packets += st.Packets
			x.bytes += st.Bytes
		}
		for _, t := range a.TLSMetadata {
			k := key{t.Namespace, t.Pod, t.WorkloadKind, t.WorkloadName, a.Node}
			x := ensure(k)
			host := strings.ToLower(strings.TrimSuffix(t.SNI, "."))
			if host != "" {
				x.hosts[host] += t.Handshakes
			}
		}
		for _, c := range a.ConnectionAttempts {
			k := key{c.Namespace, c.Pod, c.WorkloadKind, c.WorkloadName, a.Node}
			x := ensure(k)
			if c.RemoteIP != "" {
				x.dsts[c.RemoteIP] += c.Attempts
			}
		}
	}
	for k, x := range by {
		_ = k
		for h := range x.hosts {
			globalHost[h]++
		}
	}

	out := Result{
		Findings: []Finding{},
		Note:     "Exfil heuristics from fan-out / volume / rare hosts — not DLP. Review then optional leased deny.",
	}
	for k, x := range by {
		if k.ns == "" && k.pod == "" {
			continue
		}
		ext := 0
		for ip := range x.dsts {
			if isExternal(ip) {
				ext++
			}
		}
		var rare []string
		for h, n := range x.hosts {
			if globalHost[h] <= 1 && n > 0 {
				rare = append(rare, h)
			}
		}
		sort.Strings(rare)
		if len(rare) > 8 {
			rare = rare[:8]
		}
		f := Finding{
			Namespace: k.ns, Pod: k.pod, WorkloadKind: k.kind, WorkloadName: k.name, Node: k.node,
			UniqueDsts: len(x.dsts), ExternalDsts: ext, Packets: x.packets, Bytes: x.bytes, RareHosts: rare,
		}
		score := 0
		var signals []string
		if ext >= 30 {
			score += 40
			signals = append(signals, "high-external-fanout")
		} else if ext >= 15 {
			score += 25
			signals = append(signals, "elevated-external-fanout")
		} else if ext >= 8 {
			score += 10
			signals = append(signals, "moderate-external-fanout")
		}
		if x.packets > 5_000_000 {
			score += 30
			signals = append(signals, "high-packet-volume")
		} else if x.packets > 500_000 {
			score += 15
			signals = append(signals, "elevated-packet-volume")
		}
		if len(rare) >= 3 {
			score += 20
			signals = append(signals, "rare-destination-hosts")
		} else if len(rare) >= 1 {
			score += 8
			signals = append(signals, "rare-host")
		}
		if score < 15 {
			continue
		}
		f.Score = score
		f.Signals = signals
		switch {
		case score >= 60:
			f.Severity = "high"
			out.High++
		case score >= 35:
			f.Severity = "medium"
		default:
			f.Severity = "low"
		}
		f.Rationale = "Metadata fan-out/volume heuristics; no payload inspection"
		out.Findings = append(out.Findings, f)
	}
	sort.Slice(out.Findings, func(i, j int) bool {
		if out.Findings[i].Score != out.Findings[j].Score {
			return out.Findings[i].Score > out.Findings[j].Score
		}
		return out.Findings[i].Namespace+out.Findings[i].Pod < out.Findings[j].Namespace+out.Findings[j].Pod
	})
	if len(out.Findings) > limit {
		out.Findings = out.Findings[:limit]
		out.Capped = true
	}
	out.Count = len(out.Findings)
	return out
}

func isExternal(ip string) bool {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return true
	}
	return !(addr.IsPrivate() || addr.IsLoopback() || addr.IsLinkLocalUnicast() || addr.IsMulticast())
}
