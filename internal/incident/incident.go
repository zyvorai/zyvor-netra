// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

// Package incident is the deeper cross-signal correlator: it joins findings
// from internal/health, internal/insights (Drift/RateDrift/Exposure),
// internal/detective, and the audit log into subject-keyed clusters —
// wider than internal/health's own correlateAnomalies, which only groups
// same-tick anomalies within that one package. It takes already-computed
// results from each of those packages rather than raw agent data, the same
// composition style internal/api/insights.go's insightsSummary already
// uses.
package incident

import (
	"net"
	"sort"
	"strings"
	"time"

	"github.com/zyvorai/netra/internal/detective"
	"github.com/zyvorai/netra/internal/models"
	"github.com/zyvorai/netra/internal/timeline"
)

// controlPlaneSourceKey is the pseudo-source an audit event lands under
// when its Target can't be resolved to any specific workload/pod — most
// mode/scope/shield/policy-history/baseline actions, which genuinely
// aren't about one workload.
const controlPlaneSourceKey = "control-plane"

var severityRank = map[string]int{"critical": 5, "high": 4, "medium": 3, "warning": 3, "low": 2, "info": 1}

func rank(sev string) int { return severityRank[strings.ToLower(sev)] }

// Build joins the given already-computed findings into subject-keyed
// clusters, returning only clusters with findings from at least two
// distinct Kinds (see models.IncidentCluster's doc comment). graph may be
// the empty models.DependencyGraph{} — detective and Target-is-an-IP audit
// resolution then simply never match anything, and every other join
// (health/drift/rateDrift/exposure, which already key off the shared
// CanonicalSource scheme directly) still works.
func Build(health []models.NetworkHealthAnomaly, drift []models.DriftFinding, rateDrift []models.RateFinding, exposure []models.ExposureScore, dropFindings []models.DropDetectiveFinding, graph models.DependencyGraph, audit []models.AuditEvent, now time.Time) []models.IncidentCluster {
	now = now.UTC()
	by := map[string]*models.IncidentCluster{}
	get := func(key, subject string) *models.IncidentCluster {
		c := by[key]
		if c == nil {
			c = &models.IncidentCluster{SourceKey: key, Subject: subject}
			by[key] = c
		}
		return c
	}
	add := func(c *models.IncidentCluster, kind, severity, joinConfidence, subject, message string, at time.Time) {
		c.Findings = append(c.Findings, models.IncidentFinding{Kind: kind, Severity: severity, JoinConfidence: joinConfidence, Subject: subject, Message: message, At: at})
	}

	for _, a := range health {
		if a.SourceKey == "" {
			continue
		}
		add(get(a.SourceKey, a.Subject), "health", a.Severity, detective.ConfidenceExact, a.Subject, a.Message, now)
	}
	for _, f := range drift {
		add(get(f.Source, f.Source), "drift", f.Severity, detective.ConfidenceExact, f.Source, f.Message, now)
	}
	for _, f := range rateDrift {
		add(get(f.Source, f.Source), "rate-drift", f.Severity, detective.ConfidenceExact, f.Source, f.Message, now)
	}
	for _, x := range exposure {
		msg := x.Source
		if len(x.Reasons) > 0 {
			msg = strings.Join(x.Reasons, "; ")
		}
		add(get(x.Source, x.Source), "exposure", x.Severity, detective.ConfidenceExact, x.Source, msg, now)
	}
	for _, f := range dropFindings {
		key, ok := ipToSourceKey(hostOnly(f.Dst), graph)
		if !ok {
			key, ok = ipToSourceKey(hostOnly(f.Src), graph)
		}
		joinConfidence := detective.ConfidenceProbable
		subject := key
		if !ok {
			// No resolvable attribution at all — still surfaced (never
			// silently dropped), just not attributed to one workload.
			key, subject, joinConfidence = controlPlaneSourceKey, "control plane", ""
		}
		add(get(key, subject), "detective", "warning", joinConfidence, subject, f.Explanation, now)
	}
	for _, ev := range audit {
		key, joinConfidence := auditSourceKey(ev, graph)
		subject := key
		if key == controlPlaneSourceKey {
			subject = "control plane"
		}
		add(get(key, subject), "audit", "info", joinConfidence, subject, timeline.ExplainAuditEvent(ev), ev.At)
	}

	out := make([]models.IncidentCluster, 0, len(by))
	for _, c := range by {
		kinds := map[string]bool{}
		worst := "info"
		for _, f := range c.Findings {
			kinds[f.Kind] = true
			if rank(f.Severity) > rank(worst) {
				worst = f.Severity
			}
		}
		if len(kinds) < 2 {
			continue
		}
		c.Severity = worst
		c.GeneratedAt = now
		sort.SliceStable(c.Findings, func(i, j int) bool { return c.Findings[i].At.Before(c.Findings[j].At) })
		out = append(out, *c)
	}
	sort.Slice(out, func(i, j int) bool {
		if rank(out[i].Severity) != rank(out[j].Severity) {
			return rank(out[i].Severity) > rank(out[j].Severity)
		}
		if len(out[i].Findings) != len(out[j].Findings) {
			return len(out[i].Findings) > len(out[j].Findings)
		}
		return out[i].SourceKey < out[j].SourceKey
	})
	return out
}

// ipToSourceKey resolves a bare IP to a workload/pod node's canonical ID in
// the live dependency graph — the same best-effort join detective drop
// findings already need, since PolicyDropStat/DropDetectiveFinding carry
// zero namespace/pod/cgroup attribution of their own (confirmed against
// internal/detective/detective.go).
func ipToSourceKey(ip string, graph models.DependencyGraph) (string, bool) {
	if ip == "" {
		return "", false
	}
	for _, n := range graph.Nodes {
		if n.IP == ip && (n.Kind == "workload" || n.Kind == "pod") {
			return n.ID, true
		}
	}
	return "", false
}

// hostOnly strips a port from a detective-formatted endpoint ("ip:port",
// "[ipv6]:port", a bare IP, or the literal "?" for an unknown endpoint —
// see internal/detective/detective.go's formatEndpoint). A bare IP or "?"
// is returned unchanged; "?" simply never matches any graph node.
func hostOnly(endpoint string) string {
	if h, _, err := net.SplitHostPort(endpoint); err == nil {
		return h
	}
	return endpoint
}

// auditSourceKey applies the same best-effort resolution AuditEvent.Target
// needs, since it has no canonical shape across its ~50 distinct call
// sites in internal/store: an IP-shaped Target (most ebpf.*.add/.delete
// rule actions) resolves like a detective finding; a "namespace/name"
// Target on a policy.* action resolves against a matching workload node.
// Anything else falls back to controlPlaneSourceKey with an empty join
// confidence — a real action worth showing in the timeline, just not
// attributable to one specific workload.
func auditSourceKey(ev models.AuditEvent, graph models.DependencyGraph) (key, joinConfidence string) {
	if net.ParseIP(ev.Target) != nil {
		if k, ok := ipToSourceKey(ev.Target, graph); ok {
			return k, detective.ConfidenceProbable
		}
		return controlPlaneSourceKey, ""
	}
	if strings.HasPrefix(ev.Action, "policy.") {
		if ns, name, ok := strings.Cut(ev.Target, "/"); ok {
			for _, n := range graph.Nodes {
				if n.Kind == "workload" && n.Namespace == ns && n.Name == name {
					return n.ID, detective.ConfidenceProbable
				}
			}
		}
	}
	return controlPlaneSourceKey, ""
}
