// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
//
// Package report builds a point-in-time operator briefing from already-
// computed controller observations. It never calls Kubernetes, never
// inspects payloads, and never applies policy. The markdown form is
// meant to be pasted into a ticket or on-call handoff; the JSON form is
// the same fields for automation.
package report

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/zyvorai/netra/internal/models"
)

// Input is the already-joined snapshot the API layer gathers from
// store + health + insights + incident. Keeping the package free of
// store/api imports matches internal/incident and internal/timeline.
type Input struct {
	GeneratedAt     time.Time
	Version         string
	Mode            string
	ScopeMode       string
	LeaseExpiresAt  time.Time
	Agents          int
	StaleAgents     int
	HealthScore     int
	Packets         uint64
	Blocked         uint64
	TCPRetrans      uint64
	DNSFailures     uint64
	Anomalies       []models.NetworkHealthAnomaly
	DriftFindings   int
	RateDrift       int
	HighExposure    int
	Incidents       int
	BaselineAt      time.Time
	RateBaselineAt  time.Time
	Audit           []models.AuditEvent
	TopAnomalies    []models.NetworkHealthAnomaly
	IncidentSamples []models.IncidentCluster
}

// Snapshot is the JSON-serializable briefing.
type Snapshot struct {
	GeneratedAt    time.Time `json:"generatedAt"`
	Version        string    `json:"version,omitempty"`
	Headline       string    `json:"headline"`
	Mode           string    `json:"mode"`
	ScopeMode      string    `json:"scopeMode,omitempty"`
	LeaseExpiresAt time.Time `json:"leaseExpiresAt,omitempty"`
	Agents         int       `json:"agents"`
	StaleAgents    int       `json:"staleAgents"`
	HealthScore    int       `json:"healthScore"`
	Packets        uint64    `json:"packets"`
	Blocked        uint64    `json:"blocked"`
	TCPRetrans     uint64    `json:"tcpRetransmissions"`
	DNSFailures    uint64    `json:"dnsFailures"`
	AnomalyCount   int       `json:"anomalyCount"`
	DriftFindings  int       `json:"driftFindings"`
	RateDrift      int       `json:"rateDriftFindings"`
	HighExposure   int       `json:"highExposure"`
	Incidents      int       `json:"incidentClusters"`
	BaselineAt     time.Time `json:"baselineCapturedAt,omitempty"`
	RateBaselineAt time.Time `json:"rateBaselineCapturedAt,omitempty"`
	Attention      []string  `json:"attention"`
	RecentAudit    []string  `json:"recentAudit"`
}

// Build derives a Snapshot. It is deterministic given Input.
func Build(in Input) Snapshot {
	if in.GeneratedAt.IsZero() {
		in.GeneratedAt = time.Now().UTC()
	}
	s := Snapshot{
		GeneratedAt:    in.GeneratedAt.UTC(),
		Version:        in.Version,
		Mode:           first(in.Mode, "observe"),
		ScopeMode:      in.ScopeMode,
		LeaseExpiresAt: in.LeaseExpiresAt.UTC(),
		Agents:         in.Agents,
		StaleAgents:    in.StaleAgents,
		HealthScore:    in.HealthScore,
		Packets:        in.Packets,
		Blocked:        in.Blocked,
		TCPRetrans:     in.TCPRetrans,
		DNSFailures:    in.DNSFailures,
		AnomalyCount:   len(in.Anomalies),
		DriftFindings:  in.DriftFindings,
		RateDrift:      in.RateDrift,
		HighExposure:   in.HighExposure,
		Incidents:      in.Incidents,
		BaselineAt:     in.BaselineAt.UTC(),
		RateBaselineAt: in.RateBaselineAt.UTC(),
	}
	s.Attention = attention(in)
	s.RecentAudit = auditLines(in.Audit, 8)
	s.Headline = headline(s)
	return s
}

func headline(s Snapshot) string {
	switch {
	case s.StaleAgents > 0 && s.HealthScore < 50:
		return fmt.Sprintf("Degraded: health %d/100 and %d stale agent(s)", s.HealthScore, s.StaleAgents)
	case s.StaleAgents > 0:
		return fmt.Sprintf("Coverage gap: %d stale agent(s), health %d/100", s.StaleAgents, s.HealthScore)
	case s.HealthScore < 50:
		return fmt.Sprintf("Degraded health %d/100 with %d incident cluster(s)", s.HealthScore, s.Incidents)
	case s.Mode == "enforce":
		return fmt.Sprintf("Enforce lease active, health %d/100", s.HealthScore)
	case s.Incidents > 0:
		return fmt.Sprintf("Observe-mode, %d incident cluster(s), health %d/100", s.Incidents, s.HealthScore)
	default:
		return fmt.Sprintf("Observe-mode, health %d/100, %d agent(s) fresh", s.HealthScore, s.Agents)
	}
}

func attention(in Input) []string {
	var out []string
	if in.StaleAgents > 0 {
		out = append(out, fmt.Sprintf("%d node agent(s) past the stale threshold — hook coverage is incomplete", in.StaleAgents))
	}
	if in.Mode == "enforce" {
		if in.LeaseExpiresAt.IsZero() {
			out = append(out, "standalone datapath is in enforce without a visible lease expiry on this snapshot")
		} else {
			out = append(out, fmt.Sprintf("standalone datapath is in enforce until %s (fails open after)", in.LeaseExpiresAt.UTC().Format(time.RFC3339)))
		}
	}
	if in.HealthScore < 70 {
		out = append(out, fmt.Sprintf("cluster health score %d/100 is below the 70 soft floor used by the dashboard pulse", in.HealthScore))
	}
	if in.DriftFindings > 0 {
		out = append(out, fmt.Sprintf("%d behavior-drift finding(s) versus the captured baseline", in.DriftFindings))
	}
	if in.RateDrift > 0 {
		out = append(out, fmt.Sprintf("%d rate-drift finding(s) versus the captured rate baseline", in.RateDrift))
	}
	if in.HighExposure > 0 {
		out = append(out, fmt.Sprintf("%d high-exposure source(s)", in.HighExposure))
	}
	if in.BaselineAt.IsZero() {
		out = append(out, "no behavior baseline captured — drift and recommendations stay empty until POST /api/v1/insights/baseline")
	}
	// Surface the noisiest anomalies first, capped so the briefing stays short.
	anoms := append([]models.NetworkHealthAnomaly(nil), in.TopAnomalies...)
	if len(anoms) == 0 {
		anoms = append([]models.NetworkHealthAnomaly(nil), in.Anomalies...)
	}
	sort.SliceStable(anoms, func(i, j int) bool {
		return sevRank(anoms[i].Severity) > sevRank(anoms[j].Severity)
	})
	if len(anoms) > 5 {
		anoms = anoms[:5]
	}
	for _, a := range anoms {
		out = append(out, fmt.Sprintf("%s %s: %s", strings.ToLower(a.Severity), a.Kind, a.Message))
	}
	for i, c := range in.IncidentSamples {
		if i >= 3 {
			break
		}
		out = append(out, fmt.Sprintf("incident %s (%s, %d signals)", c.SourceKey, c.Severity, len(c.Findings)))
	}
	return out
}

func auditLines(events []models.AuditEvent, n int) []string {
	if n <= 0 || n > len(events) {
		n = len(events)
	}
	out := make([]string, 0, n)
	for i := 0; i < n; i++ {
		e := events[i]
		when := e.At.UTC().Format(time.RFC3339)
		line := when + " " + e.Actor + " " + e.Action
		if e.Target != "" {
			line += " " + e.Target
		}
		out = append(out, line)
	}
	return out
}

func sevRank(s string) int {
	switch strings.ToLower(s) {
	case "critical":
		return 4
	case "high":
		return 3
	case "warning", "medium":
		return 2
	default:
		return 1
	}
}

func first(v, d string) string {
	if strings.TrimSpace(v) == "" {
		return d
	}
	return v
}

// Markdown renders a Snapshot as a handoff-ready briefing.
func Markdown(s Snapshot) string {
	var b bytes.Buffer
	fmt.Fprintf(&b, "# Netra operator report\n\n")
	fmt.Fprintf(&b, "_Generated %s", s.GeneratedAt.Format(time.RFC3339))
	if s.Version != "" {
		fmt.Fprintf(&b, " · controller %s", s.Version)
	}
	fmt.Fprintf(&b, "_\n\n")
	fmt.Fprintf(&b, "**%s**\n\n", s.Headline)
	fmt.Fprintf(&b, "| Signal | Value |\n|---|---|\n")
	fmt.Fprintf(&b, "| Mode | `%s` |\n", s.Mode)
	if s.ScopeMode != "" {
		fmt.Fprintf(&b, "| Scope | `%s` |\n", s.ScopeMode)
	}
	fmt.Fprintf(&b, "| Agents | %d (%d stale) |\n", s.Agents, s.StaleAgents)
	fmt.Fprintf(&b, "| Health | %d/100 |\n", s.HealthScore)
	fmt.Fprintf(&b, "| Packets / blocked | %d / %d |\n", s.Packets, s.Blocked)
	fmt.Fprintf(&b, "| TCP retransmits | %d |\n", s.TCPRetrans)
	fmt.Fprintf(&b, "| DNS failures | %d |\n", s.DNSFailures)
	fmt.Fprintf(&b, "| Anomalies | %d |\n", s.AnomalyCount)
	fmt.Fprintf(&b, "| Behavior drift | %d |\n", s.DriftFindings)
	fmt.Fprintf(&b, "| Rate drift | %d |\n", s.RateDrift)
	fmt.Fprintf(&b, "| High exposure | %d |\n", s.HighExposure)
	fmt.Fprintf(&b, "| Incident clusters | %d |\n", s.Incidents)
	if !s.BaselineAt.IsZero() {
		fmt.Fprintf(&b, "| Behavior baseline | %s |\n", s.BaselineAt.Format(time.RFC3339))
	}
	if !s.RateBaselineAt.IsZero() {
		fmt.Fprintf(&b, "| Rate baseline | %s |\n", s.RateBaselineAt.Format(time.RFC3339))
	}
	if !s.LeaseExpiresAt.IsZero() {
		fmt.Fprintf(&b, "| Enforce lease | %s |\n", s.LeaseExpiresAt.Format(time.RFC3339))
	}
	fmt.Fprintf(&b, "\n## Attention\n\n")
	if len(s.Attention) == 0 {
		fmt.Fprintf(&b, "No attention items. Cluster is quiet relative to the current baselines.\n")
	} else {
		for _, a := range s.Attention {
			fmt.Fprintf(&b, "- %s\n", a)
		}
	}
	fmt.Fprintf(&b, "\n## Recent audit\n\n")
	if len(s.RecentAudit) == 0 {
		fmt.Fprintf(&b, "No audit events in this snapshot.\n")
	} else {
		for _, a := range s.RecentAudit {
			fmt.Fprintf(&b, "- `%s`\n", a)
		}
	}
	fmt.Fprintf(&b, "\n## Notes\n\n")
	fmt.Fprintf(&b, "- This briefing is observe-only. It does not apply CiliumNetworkPolicy or extend an enforce lease.\n")
	fmt.Fprintf(&b, "- Enforcement, if any, remains lease-bounded and fails open to observe.\n")
	fmt.Fprintf(&b, "- No application payloads, argv, or Secret contents are included.\n")
	return b.String()
}

// JSON renders a Snapshot.
func JSON(s Snapshot) ([]byte, error) {
	return json.MarshalIndent(s, "", "  ")
}
