// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package insights

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math"
	"net/netip"
	"sort"
	"strings"

	"github.com/zyvorai/netra/internal/models"
)

func metricRates(m models.RateMetric) map[string]float64 {
	return map[string]float64{
		"packets": m.PacketsPerSecond, "bytes": m.BytesPerSecond, "blocked": m.BlockedPerSecond,
		"connections": m.ConnectionsPerSecond, "dns-queries": m.DNSQueriesPerSecond, "dns-failures": m.DNSFailuresPerSecond,
		"tls-handshakes": m.TLSHandshakesPerSecond, "http-requests": m.HTTPRequestsPerSecond,
	}
}

func rateFloor(metric string) float64 {
	switch metric {
	case "bytes":
		return 1024
	case "packets":
		return 5
	case "connections":
		return 0.5
	case "dns-queries", "tls-handshakes", "http-requests":
		return 0.5
	case "dns-failures", "blocked":
		return 0.05
	default:
		return 0.1
	}
}

func RateDrift(b models.RateBaseline, current models.RateWindow) models.RateDriftResponse {
	out := models.RateDriftResponse{Window: current}
	if b.SchemaVersion == 0 || b.CapturedAt.IsZero() || current.Warming {
		return out
	}
	captured := b.CapturedAt
	out.BaselineCapturedAt = &captured
	base := map[string]float64{}
	for _, e := range b.Entries {
		base[e.Source+"\x00"+e.Metric] = e.Rate
	}
	for _, m := range current.Metrics {
		for metric, rate := range metricRates(m) {
			floor := rateFloor(metric)
			if rate < floor {
				continue
			}
			baseline := base[m.Source+"\x00"+metric]
			if baseline <= 0 {
				if rate < floor*4 {
					continue
				}
				out.Findings = append(out.Findings, models.RateFinding{Severity: "warning", Source: m.Source, Metric: metric, CurrentRate: rate, Message: fmt.Sprintf("%s rate is newly active relative to the captured rate baseline", metric)})
				continue
			}
			ratio := rate / baseline
			increase := rate - baseline
			if ratio < 2 || increase < floor {
				continue
			}
			severity := "warning"
			if ratio >= 5 {
				severity = "high"
			}
			if ratio >= 10 {
				severity = "critical"
			}
			out.Findings = append(out.Findings, models.RateFinding{Severity: severity, Source: m.Source, Metric: metric, BaselineRate: baseline, CurrentRate: rate, Ratio: ratio, Message: fmt.Sprintf("%s rate is %.1fx the captured baseline", metric, ratio)})
		}
	}
	rank := map[string]int{"critical": 4, "high": 3, "warning": 2, "info": 1}
	sort.SliceStable(out.Findings, func(i, j int) bool {
		if rank[out.Findings[i].Severity] != rank[out.Findings[j].Severity] {
			return rank[out.Findings[i].Severity] > rank[out.Findings[j].Severity]
		}
		return out.Findings[i].Ratio > out.Findings[j].Ratio
	})
	return out
}

func Exposure(graph models.DependencyGraph, behavior models.DriftResponse, rates models.RateDriftResponse) []models.ExposureScore {
	type acc struct {
		external, behavior, rate, score int
		reasons                         []string
	}
	by := map[string]*acc{}
	get := func(src string) *acc {
		if by[src] == nil {
			by[src] = &acc{}
		}
		return by[src]
	}
	for _, e := range graph.Edges {
		if e.External {
			x := get(e.Source)
			x.external++
			if x.external <= 6 {
				x.score += 5
			}
		}
	}
	for _, f := range behavior.Findings {
		x := get(f.Source)
		x.behavior++
		p := 3
		if f.Severity == "warning" {
			p = 8
		}
		x.score += p
	}
	for _, f := range rates.Findings {
		x := get(f.Source)
		x.rate++
		p := 10
		if f.Severity == "high" {
			p = 20
		}
		if f.Severity == "critical" {
			p = 30
		}
		x.score += p
	}
	out := make([]models.ExposureScore, 0, len(by))
	for src, x := range by {
		if x.external > 0 {
			x.reasons = append(x.reasons, fmt.Sprintf("%d external network dependencies", x.external))
		}
		if x.behavior > 0 {
			x.reasons = append(x.reasons, fmt.Sprintf("%d post-baseline behavior changes", x.behavior))
		}
		if x.rate > 0 {
			x.reasons = append(x.reasons, fmt.Sprintf("%d time-window rate anomalies", x.rate))
		}
		if x.score > 100 {
			x.score = 100
		}
		sev := "low"
		if x.score >= 25 {
			sev = "medium"
		}
		if x.score >= 50 {
			sev = "high"
		}
		if x.score >= 75 {
			sev = "critical"
		}
		out = append(out, models.ExposureScore{Source: src, Score: x.score, Severity: sev, ExternalDependencies: x.external, BehaviorDrift: x.behavior, RateDrift: x.rate, Reasons: x.reasons})
	}
	rank := map[string]int{"critical": 4, "high": 3, "medium": 2, "low": 1}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Score != out[j].Score {
			return out[i].Score > out[j].Score
		}
		return rank[out[i].Severity] > rank[out[j].Severity]
	})
	return out
}

func Remediations(graph models.DependencyGraph, behavior models.DriftResponse, rates models.RateDriftResponse, limit int) []models.RemediationProposal {
	if limit <= 0 {
		limit = 50
	}
	external := map[string]map[string]bool{}
	nodes := map[string]models.DependencyNode{}
	for _, n := range graph.Nodes {
		nodes[n.ID] = n
	}
	for _, e := range graph.Edges {
		if !e.External {
			continue
		}
		if external[e.Source] == nil {
			external[e.Source] = map[string]bool{}
		}
		if n := nodes[e.Target]; n.IP != "" {
			external[e.Source][n.IP] = true
		}
	}
	out := []models.RemediationProposal{}
	add := func(src, sev, kind, title string, rationale []string, action map[string]any) {
		h := sha256.Sum256([]byte(src + "\x00" + kind + "\x00" + fmt.Sprint(action)))
		out = append(out, models.RemediationProposal{ID: "proposal-" + hex.EncodeToString(h[:6]), Source: src, Severity: sev, Kind: kind, Title: title, Rationale: rationale, Action: action, ReviewRequired: true})
	}
	for _, f := range behavior.Findings {
		if f.Severity != "warning" {
			continue
		}
		switch f.Kind {
		case "sni":
			add(f.Source, "medium", "ebpf-sni-deny-draft", "Review new TLS destination", []string{f.Message, "Exact SNI denial is fail-open when SNI cannot be parsed; validate application impact before staging."}, map[string]any{"operation": "ebpf.sni.add", "name": f.Value})
		case "destination":
			for ip := range external[f.Source] {
				if f.Value != ip && !strings.HasPrefix(f.Value, ip+":") {
					continue
				}
				if a, err := netip.ParseAddr(ip); err == nil {
					add(f.Source, "high", "ebpf-ip-deny-draft", "Review new external destination", []string{f.Message, "Destination is external to the current Kubernetes pod/service inventory."}, map[string]any{"operation": "ebpf.deny.add", "ip": a.String()})
				}
				break
			}
		}
	}
	for _, f := range rates.Findings {
		if f.Severity == "high" || f.Severity == "critical" {
			add(f.Source, f.Severity, "investigation", "Investigate traffic-rate anomaly", []string{f.Message, "Rate findings are delta-based; confirm the workload and dependency before containment."}, map[string]any{"operation": "inspect", "metric": f.Metric, "currentRate": math.Round(f.CurrentRate*100) / 100, "baselineRate": math.Round(f.BaselineRate*100) / 100})
		}
	}
	rank := map[string]int{"critical": 4, "high": 3, "medium": 2, "low": 1}
	sort.SliceStable(out, func(i, j int) bool { return rank[out[i].Severity] > rank[out[j].Severity] })
	if len(out) > limit {
		out = out[:limit]
	}
	return out
}
