// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package main

import (
	"context"
	"fmt"

	"github.com/zyvorai/netra/internal/mcpserver"
)

func registerResources(srv *mcpserver.Server, c *client) error {
	type spec struct {
		uri, name, desc, path string
	}
	items := []spec{
		{"netra://ai/brief", "Cluster brief", "Live heuristic brief from /api/v1/ai/brief.", "/api/v1/ai/brief"},
		{"netra://ai/digest", "On-call digest", "Pager/Slack card plus incident fingerprint from /api/v1/ai/digest.", "/api/v1/ai/digest"},
		{"netra://ai/congestion", "Congestion brief", "Kernel-network congestion brief from /api/v1/ai/congestion-brief.", "/api/v1/ai/congestion-brief"},
		{"netra://ai/suggestions", "Live questions", "Snapshot-derived follow-up questions.", "/api/v1/ai/suggestions"},
		{"netra://status", "Controller status", "GET /api/v1/status.", "/api/v1/status"},
		{"netra://metrics/contexts", "Metric contexts", "Every per-second metric context with charts and dimensions from /api/v1/metrics/contexts.", "/api/v1/metrics/contexts"},
		{"netra://metrics/anomalies", "Metric anomalies", "Anomaly rate per node and the most anomalous metrics over the last 15 minutes from /api/v1/metrics/anomalies.", "/api/v1/metrics/anomalies"},
		{"netra://metrics/alerts", "Metric alerts", "Active metric health alerts from /api/v1/metrics/alerts.", "/api/v1/metrics/alerts"},
		{"netra://incidents/timeline", "Incident timeline", "Chronological, human-readable merge of the audit log and cluster-health-signature transitions from /api/v1/incidents/timeline.", "/api/v1/incidents/timeline"},
		{"netra://incidents", "Cross-signal incidents", "Health/drift/rate-drift/exposure/detective/audit findings joined into subject-keyed clusters from /api/v1/incidents.", "/api/v1/incidents"},
		{"netra://ebpf/health", "eBPF health", "TCP health/retransmit anomalies from /api/v1/ebpf/health.", "/api/v1/ebpf/health"},
		{"netra://ebpf/tls-risk", "JA3 risk", "Rare JA3 / ECH risk rows from /api/v1/ebpf/tls-fingerprints/risk.", "/api/v1/ebpf/tls-fingerprints/risk"},
		{"netra://insights/exposure", "Exposure findings", "External exposure findings from /api/v1/insights/exposure.", "/api/v1/insights/exposure"},
		{"netra://security/incidents", "Security incidents", "Security-review incident correlation from /api/v1/security/incidents.", "/api/v1/security/incidents"},
		{"netra://ebpf/ai-destinations", "AI destinations", "GenAI/MCP hostname catalog matches from /api/v1/ebpf/ai-destinations.", "/api/v1/ebpf/ai-destinations"},
		{"netra://compliance", "Compliance packs", "Compliance pack controls from /api/v1/compliance.", "/api/v1/compliance"},
		{"netra://ebpf/maps", "eBPF maps", "Controller-desired map inventory from /api/v1/ebpf/maps.", "/api/v1/ebpf/maps"},
		{"netra://ebpf/app-categories", "App categories", "Heuristic app/category hits from /api/v1/ebpf/app-categories.", "/api/v1/ebpf/app-categories"},
		{"netra://ebpf/tls-fingerprints", "TLS fingerprints", "JA3/JA4 samples from /api/v1/ebpf/tls-fingerprints.", "/api/v1/ebpf/tls-fingerprints"},
		{"netra://flows/history", "Flow history", "Native flow history from /api/v1/flows/history?limit=100.", "/api/v1/flows/history?limit=100"},
		{"netra://insights/red", "RED metrics", "Workload RED board from /api/v1/insights/red?window=5m.", "/api/v1/insights/red?window=5m"},
		{"netra://insights/traces", "Inferred traces", "Inferred spans from /api/v1/insights/traces?since=15m.", "/api/v1/insights/traces?since=15m"},
		{"netra://handoff", "On-call handoff", "JSON on-call pack from /api/v1/handoff?format=json.", "/api/v1/handoff?format=json"},
		{"netra://slo", "Workload SLOs", "Error-budget burn from /api/v1/slo.", "/api/v1/slo"},
		{"netra://listen-queues", "Listen queues", "TCP accept-queue pressure from /api/v1/listen-queues.", "/api/v1/listen-queues"},
		{"netra://ebpf/stack-histograms", "Stack histograms", "Softirq/softnet/listen depth buckets from /api/v1/ebpf/stack-histograms.", "/api/v1/ebpf/stack-histograms"},
		{"netra://ebpf/reasons", "Drop reasons", "FastPath action/reason histogram from /api/v1/ebpf/reasons.", "/api/v1/ebpf/reasons"},
		{"netra://fleet/flows", "Fleet flow history", "Multi-cluster flow deltas from /api/v1/fleet/flows/history?limit=100.", "/api/v1/fleet/flows/history?limit=100"},
		{"netra://ebpf/capdrift", "Capability drift", "Cap-change findings from /api/v1/ebpf/capdrift.", "/api/v1/ebpf/capdrift"},
		{"netra://ebpf/nsdrift", "Namespace drift", "Netns-change findings from /api/v1/ebpf/nsdrift.", "/api/v1/ebpf/nsdrift"},
		{"netra://ebpf/exehash", "Exe-hash drift", "Executable content-hash findings from /api/v1/ebpf/exehash.", "/api/v1/ebpf/exehash"},
		{"netra://insights/policy-packs", "Policy packs", "Review-only policy packs from /api/v1/insights/policy-packs.", "/api/v1/insights/policy-packs"},
	}
	for _, it := range items {
		it := it
		if err := srv.RegisterResource(mcpserver.Resource{
			URI:         it.uri,
			Name:        it.name,
			Description: it.desc,
			MimeType:    "application/json",
			Read: func(ctx context.Context) (string, error) {
				body, status, err := c.do(ctx, "GET", it.path, nil, nil)
				if err != nil {
					return "", err
				}
				if status < 200 || status >= 300 {
					return "", fmt.Errorf("controller HTTP %d: %s", status, body)
				}
				return string(body), nil
			},
		}); err != nil {
			return err
		}
	}
	return nil
}
