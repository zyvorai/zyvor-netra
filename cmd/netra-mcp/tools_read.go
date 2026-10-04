// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package main

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/zyvorai/netra/internal/mcpserver"
)

// registerReadTools registers every read-only GET endpoint plus the
// three pure-generator POSTs that mutate nothing (policy build, policy
// lockdown-manifest generation, and ebpf scope preview — none of them
// write to the cluster or the store, and none record an audit event).
// These are always available, independent of NETRA_MCP_ALLOW_MUTATIONS.
//
// GET /api/v1/flows/stream is deliberately not wrapped here: it is a
// Server-Sent-Events stream, which does not fit a request/response MCP
// tool call. netra_flow_summary (a bounded, point-in-time aggregate of
// the same underlying Hubble flows) is the tool-shaped equivalent.
func registerReadTools(srv *mcpserver.Server, c *client) error {
	tools := []endpointTool{
		{
			name: "netra_status", method: "GET", path: "/api/v1/status",
			description: "Overall Netra controller status: fast-path config, agent counts/staleness, baseline and rate-baseline capture state, Hubble status, HA/Cilium flags.",
			schema:      emptySchema(),
		},
		{
			name: "netra_agents", method: "GET", path: "/api/v1/agents",
			description: "List all reporting Netra agents (one per node) with their latest status and staleness.",
			schema:      emptySchema(),
		},
		{
			name: "netra_audit", method: "GET", path: "/api/v1/audit",
			description: "List recent Netra audit events: every mutating action taken through the controller API, including by this MCP server, with actor/action/target.",
			schema:      objSchema(map[string]any{"limit": intProp("Max events to return, 1-500 (server caps at 500). Default 100.")}),
			queryParams: []string{"limit"},
		},
		{
			name: "netra_export_audit", method: "GET", path: "/api/v1/export/audit",
			description: "Export recent audit events for a SIEM or log pipeline. Formats: json (default), jsonl, cef, syslog (RFC5424), otlp (OTLP/HTTP JSON Logs). Observe-only; no payloads.",
			schema: objSchema(map[string]any{
				"format": enumProp("Export encoding.", "json", "jsonl", "cef", "syslog", "otlp"),
				"limit":  intProp("Max events, 1-500. Default 100."),
			}),
			queryParams: []string{"format", "limit"},
		},
		{
			name: "netra_export_events", method: "GET", path: "/api/v1/export/events",
			description: "Export current health anomalies and incident clusters (optionally audit) in the same SIEM encodings as netra_export_audit. include is a comma list of anomaly,incident,audit.",
			schema: objSchema(map[string]any{
				"format":  enumProp("Export encoding.", "json", "jsonl", "cef", "syslog", "otlp"),
				"include": strProp("Comma list of anomaly, incident, audit. Default anomaly,incident."),
				"limit":   intProp("Audit cap when include lists audit, 1-500. Default 100."),
			}),
			queryParams: []string{"format", "include", "limit"},
		},
		{
			name: "netra_report", method: "GET", path: "/api/v1/report",
			description: "Point-in-time operator briefing (health, drift, exposure, incidents, recent audit). format=markdown (default) or json. Observe-only; never applies policy or extends a lease.",
			schema:      objSchema(map[string]any{"format": enumProp("Briefing encoding.", "markdown", "json")}),
			queryParams: []string{"format"},
		},
		{
			name: "netra_playbooks", method: "GET", path: "/api/v1/playbooks",
			description: "Review-only operator playbook derived from the current report snapshot. AutoApply is always false; steps suggest netractl/API actions a human still has to run.",
			schema:      objSchema(map[string]any{"format": enumProp("Playbook encoding.", "json", "markdown")}),
			queryParams: []string{"format"},
		},
		{
			name: "netra_audit_summary", method: "GET", path: "/api/v1/audit/summary",
			description: "Rollup of the audit log by actor, action, and hour. Observe-only.",
			schema: objSchema(map[string]any{
				"limit": intProp("Max audit events to aggregate, 1-1000. Default 500."),
				"since": strProp("RFC3339 lower bound."),
				"until": strProp("RFC3339 upper bound."),
			}),
			queryParams: []string{"limit", "since", "until"},
		},
		{
			name: "netra_export_flows", method: "GET", path: "/api/v1/export/flows",
			description: "Export current non-stale destination-flow counters (5-tuple + packets/bytes/blocked) in the SIEM encodings. No payloads.",
			schema: objSchema(map[string]any{
				"format": enumProp("Export encoding.", "json", "jsonl", "cef", "syslog", "otlp"),
				"limit":  intProp("Max flow rows, 1-2000. Default 200."),
			}),
			queryParams: []string{"format", "limit"},
		},
		{
			name: "netra_export_blocks", method: "GET", path: "/api/v1/export/blocks",
			description: "Export current blocked/dropped FastPathEvents (5-tuple + reason + process identity) in the SIEM encodings, including otlp-trace — each blocked event becomes one OTLP span for a trace-based backend. No payloads.",
			schema: objSchema(map[string]any{
				"format": enumProp("Export encoding.", "json", "jsonl", "cef", "syslog", "otlp", "otlp-trace"),
				"limit":  intProp("Max blocked events, 1-2000. Default 200."),
			}),
			queryParams: []string{"format", "limit"},
		},
		{
			name: "netra_export_status", method: "GET", path: "/api/v1/export/status",
			description: "Whether optional syslog push is configured, plus the pull-export endpoints and encodings this controller supports.",
			schema:      emptySchema(),
		},
		{
			name: "netra_ebpf_coverage", method: "GET", path: "/api/v1/ebpf/coverage",
			description: "Per-node hook/program coverage matrix: attached vs detached programs, missing maps, stale agents. Observe-only.",
			schema:      emptySchema(),
		},
		{
			name: "netra_fleet", method: "GET", path: "/api/v1/fleet",
			description: "Compact per-node agent inventory. Observe-only.",
			schema:      emptySchema(),
		},
		{
			name: "netra_fleet_clusters", method: "GET", path: "/api/v1/fleet/clusters",
			description: "Multi-cluster read-only aggregator: local fleet plus optional NETRA_FLEET_PEERS remotes (name|url|key|tenant).",
			schema:      emptySchema(),
		},
		{
			name: "netra_fleet_tenants", method: "GET", path: "/api/v1/fleet/tenants",
			description: "Partner/MSSP tenant rollup from fleet cluster tenant labels. Read-only.",
			schema:      emptySchema(),
		},
		{
			name: "netra_report_prevention", method: "GET", path: "/api/v1/report/prevention",
			description: "Threat-prevention-style coverage snapshot: intel hits, lease state, detector findings, AI/DoH/DoT/JA3. Not IPS efficacy %.",
			schema:      emptySchema(),
		},
		{
			name: "netra_ebpf_tls_fingerprints", method: "GET", path: "/api/v1/ebpf/tls-fingerprints",
			description: "JA3/JA4 fingerprints observed from capture-stream ClientHello frames (single-skb). Observe-only.",
			schema:      emptySchema(),
		},
		{
			name: "netra_ebpf_tls_fingerprint_risk", method: "GET", path: "/api/v1/ebpf/tls-fingerprints/risk",
			description: "Rare JA3 / missing-SNI / ECH-extension risk board from capture fingerprints.",
			schema:      objSchema(map[string]any{"limit": intProp("Max items.")}),
			queryParams: []string{"limit"},
		},
		{
			name: "netra_ebpf_encrypted_dns", method: "GET", path: "/api/v1/ebpf/encrypted-dns",
			description: "DoT (port 853) and known DoH SaaS destinations from metadata. No decryption.",
			schema:      emptySchema(),
		},
		{
			name: "netra_ebpf_app_categories", method: "GET", path: "/api/v1/ebpf/app-categories",
			description: "Heuristic CDN/SaaS/cloud category labels from SNI/Host/DNS metadata. Not DPI.",
			schema:      emptySchema(),
		},
		{
			name: "netra_compliance", method: "GET", path: "/api/v1/compliance",
			description: "CIS-inspired network hardening pack from sysctl-audit. Review-only; Netra never writes sysctls.",
			schema:      emptySchema(),
		},
		{
			name: "netra_node_resources", method: "GET", path: "/api/v1/node-resources",
			description: "Per-node CPU/memory/load-average snapshot plus per-workload cgroup v2 CPU/memory usage, top-N by CPU. A \"top\"-like view attributed to Kubernetes workloads rather than raw host PIDs. Observe-only.",
			schema:      objSchema(map[string]any{"limit": intProp("Max top-CPU workload rows, 1-200. Default 20.")}),
			queryParams: []string{"limit"},
		},
		{
			name: "netra_handoff", method: "GET", path: "/api/v1/handoff",
			description: "On-call pack: report + playbook + coverage + fleet + audit + drop reasons.",
			schema:      objSchema(map[string]any{"format": enumProp("Pack encoding.", "markdown", "json")}),
			queryParams: []string{"format"},
		},
		{
			name: "netra_scorecard", method: "GET", path: "/api/v1/scorecard",
			description: "Single 0-100 board from health, stale agents, detached programs, missing maps, blocked events.",
			schema:      emptySchema(),
		},
		{
			name: "netra_ebpf_reasons", method: "GET", path: "/api/v1/ebpf/reasons",
			description: "Histogram of FastPathEvent action/reason pairs. No payloads.",
			schema:      emptySchema(),
		},
		{
			name: "netra_talkers", method: "GET", path: "/api/v1/talkers",
			description: "Top destination IPs by packet count across current agent reports.",
			schema:      objSchema(map[string]any{"limit": intProp("Max rows, 1-200. Default 20.")}),
			queryParams: []string{"limit"},
		},
		{
			name: "netra_namespace_heat", method: "GET", path: "/api/v1/namespaces/heat",
			description: "Packets/bytes/blocked rolled up by Kubernetes namespace from agent destination stats.",
			schema:      objSchema(map[string]any{"limit": intProp("Max rows, 1-200. Default 30.")}),
			queryParams: []string{"limit"},
		},
		{
			name: "netra_protocols", method: "GET", path: "/api/v1/protocols",
			description: "L4 protocol mix (TCP/UDP/…) across current destination stats.",
			schema:      emptySchema(),
		},
		{
			name: "netra_ebpf_census", method: "GET", path: "/api/v1/ebpf/census",
			description: "Counts of deny/allow list entries. Does not return the entries themselves.",
			schema:      emptySchema(),
		},
		{
			name: "netra_ebpf_maps", method: "GET", path: "/api/v1/ebpf/maps",
			description: "Read-only inventory of datapath map contents (controller desired state under /sys/fs/bpf/netra): deny/allow/rate/policy entries with human labels, counts, and limits. Not a raw bpftool dump. See docs/ebpf-maps.md.",
			schema:      emptySchema(),
		},
		{
			name: "netra_metrics_contexts", method: "GET", path: "/api/v1/metrics/contexts",
			description: "List per-second metric contexts (for example system.cpu, net.net, disk.space, cgroup.cpu, app.cpu_utilization) with chart instances, dimensions, units and labels per node. Read-only. See docs/metrics.md.",
			schema: objSchema(map[string]any{
				"nodes":  strProp("Comma list of node globs. Default all nodes."),
				"family": strProp("Family glob, for example net or disk."),
			}),
			queryParams: []string{"nodes", "family"},
		},
		{
			name: "netra_metrics_query", method: "GET", path: "/api/v1/metrics/data",
			description: "Query one metric context as evenly spaced points with a per-point anomaly rate. after/before are unix seconds or negative seconds relative to now (after=-600 is the last ten minutes). The tier (1s, 1m, 1h) is picked from the time range. Read-only.",
			schema: objSchema(map[string]any{
				"context":    strProp("Metric context, for example system.cpu. Required."),
				"nodes":      strProp("Comma list of node globs."),
				"charts":     strProp("Comma list of chart globs."),
				"dimensions": strProp("Comma list of dimension globs."),
				"labels":     strProp("Comma list of key:value label filters; values may use *."),
				"after":      intProp("Start, unix seconds or negative relative seconds. Default -600."),
				"before":     intProp("End, unix seconds or 0 for now."),
				"points":     intProp("Number of points, max 3000."),
				"group":      enumProp("Reduction inside a time bucket.", "avg", "min", "max", "sum", "last", "p50", "p90", "p95", "p99"),
				"group_by":   strProp("dimension (default), chart, node, instance, all or label:<key>."),
				"aggregate":  enumProp("How series in one group combine.", "sum", "avg", "min", "max"),
			}),
			queryParams: []string{"context", "nodes", "charts", "dimensions", "labels", "after", "before", "points", "group", "group_by", "aggregate"},
		},
		{
			name: "netra_metrics_anomalies", method: "GET", path: "/api/v1/metrics/anomalies",
			description: "Machine-learning anomaly summary: anomaly rate per node and the most anomalous metrics in a window. With highlight_after/highlight_before it also ranks metrics whose distribution changed versus the preceding baseline (metric correlations). Read-only.",
			schema: objSchema(map[string]any{
				"nodes":            strProp("Comma list of node globs."),
				"after":            intProp("Window start. Default -900."),
				"before":           intProp("Window end. Default now."),
				"highlight_after":  intProp("Highlighted range start for correlation ranking."),
				"highlight_before": intProp("Highlighted range end for correlation ranking."),
				"top":              intProp("Ranked rows to return, default 30."),
			}),
			queryParams: []string{"nodes", "after", "before", "highlight_after", "highlight_before", "top"},
		},
		{
			name: "netra_metrics_evidence", method: "GET", path: "/api/v1/metrics/evidence",
			description: "Evidence behind a metric over a window: top flow-history peers (ranked by blocked packets for drop metrics, retransmissions for TCP metrics, bytes otherwise), current kernel drop reasons, overlapping capture sessions, other anomalous metrics, and links to drop explain, TCP events, DNS findings and flow history. Read-only.",
			schema: objSchema(map[string]any{
				"context": strProp("Metric context, e.g. ebpf.kernel_drops, net.net, workload.red_errors."),
				"node":    strProp("Node name; empty for all nodes."),
				"labels":  strProp("Chart labels to narrow flows, e.g. namespace:shop,workload:cart."),
				"after":   intProp("Window start (unix seconds, or negative relative). Default -900."),
				"before":  intProp("Window end. Default now."),
			}, "context"),
			queryParams: []string{"context", "node", "labels", "after", "before"},
		},
		{
			name: "netra_metrics_fleet", method: "GET", path: "/api/v1/metrics/fleet",
			description: "Fleet metrics roll-up: this cluster plus every NETRA_FLEET_PEERS peer — nodes, series, anomaly rate over the last 15 minutes, raised metric alerts by severity, top alerts and anomalous dimensions per cluster. Peers are read best-effort. Read-only.",
			schema:      emptySchema(),
		},
		{
			name: "netra_metrics_alerts", method: "GET", path: "/api/v1/metrics/alerts",
			description: "Active metric health alerts (warning/critical), recent transitions, rules and silences from the declarative metric alert engine. Read-only.",
			schema:      emptySchema(),
		},
		{
			name: "netra_baselines", method: "GET", path: "/api/v1/baselines",
			description: "Whether behavior and rate baselines exist and how old they are.",
			schema:      emptySchema(),
		},
		{
			name: "netra_ports", method: "GET", path: "/api/v1/ports",
			description: "Top destination ports by packet count (protocol/port).",
			schema:      objSchema(map[string]any{"limit": intProp("Max rows, 1-200. Default 30.")}),
			queryParams: []string{"limit"},
		},
		{
			name: "netra_dns_board", method: "GET", path: "/api/v1/dns/board",
			description: "DNS names ranked by failure count from agent DNS health stats.",
			schema:      objSchema(map[string]any{"limit": intProp("Max rows, 1-200. Default 30.")}),
			queryParams: []string{"limit"},
		},
		{
			name: "netra_lease", method: "GET", path: "/api/v1/lease",
			description: "Enforce-mode lease clock: remaining seconds, expired, or none. Observe-only.",
			schema:      emptySchema(),
		},
		{
			name: "netra_capture_status", method: "GET", path: "/api/v1/capture/status",
			description: "Every node with an active packet-capture session: filter, snap length, requestor, start/expiry time. Does not return captured packets themselves.",
			schema:      emptySchema(),
		},
		{
			name: "netra_pods", method: "GET", path: "/api/v1/pods",
			description: "List pods known to the cluster, with lockdown status.",
			schema:      objSchema(map[string]any{"namespace": strProp("Restrict to this namespace. Omit for all namespaces.")}),
			queryParams: []string{"namespace"},
		},
		{
			name: "netra_vms", method: "GET", path: "/api/v1/vms",
			description: "List KubeVirt VMs known to the cluster, with lockdown status. `available` in the result indicates whether KubeVirt is installed.",
			schema:      objSchema(map[string]any{"namespace": strProp("Restrict to this namespace. Omit for all namespaces.")}),
			queryParams: []string{"namespace"},
		},
		{
			name: "netra_workload_detail", method: "GET", path: "/api/v1/workloads/{kind}/{namespace}/{name}",
			description: "Detailed info for one workload: phase, node, IP, labels, recommended NetworkPolicy selector, matching policies, and lockdown status.",
			schema: objSchema(map[string]any{
				"kind":      enumProp("Workload kind.", "pod", "vm"),
				"namespace": strProp("Kubernetes namespace."),
				"name":      strProp("Workload name."),
			}, "kind", "namespace", "name"),
			pathParams: []string{"kind", "namespace", "name"},
		},
		{
			name: "netra_flow_summary", method: "GET", path: "/api/v1/flows/summary",
			description: "A bounded, point-in-time summary of recent Hubble flows (top talkers/destinations), optionally filtered. This is the request/response equivalent of the flows/stream SSE endpoint, which this MCP server does not expose.",
			schema: objSchema(map[string]any{
				"number":      intProp("Max underlying flows to sample, 1-5000. Default 500."),
				"verdict":     enumProp("Filter by Hubble verdict.", "FORWARDED", "DROPPED", "ERROR", "AUDIT", "REDIRECTED", "TRACED", "TRANSLATED"),
				"namespace":   strProp("Filter by namespace."),
				"pod":         strProp("Filter by pod name."),
				"direction":   enumProp("Filter by direction.", "EGRESS", "INGRESS"),
				"protocol":    strProp("Filter by L4 protocol, e.g. TCP or UDP."),
				"destination": strProp("Filter by destination IP address or CIDR."),
			}),
			queryParams: []string{"number", "verdict", "namespace", "pod", "direction", "protocol", "destination"},
		},
		{
			name: "netra_drops_explain", method: "GET", path: "/api/v1/drops/explain",
			description: "Unified explain-a-drop findings: Netra's own standalone-eBPF Drop Detective findings (always present) plus Hubble/Cilium findings when Hubble is configured. Each finding's source field distinguishes netra from hubble.",
			schema: objSchema(map[string]any{
				"limit":     intProp("Max dropped flows to explain, 1-100. Default 20."),
				"namespace": strProp("Filter by namespace."),
				"pod":       strProp("Filter by pod name."),
			}),
			queryParams: []string{"limit", "namespace", "pod"},
		},
		{
			name: "netra_policies_list", method: "GET", path: "/api/v1/policies",
			description: "List CiliumNetworkPolicies in a namespace, raw from the cluster. Requires Cilium integration to be enabled on the controller.",
			schema:      objSchema(map[string]any{"namespace": strProp("Namespace to list. Default \"default\".")}),
			queryParams: []string{"namespace"},
		},
		{
			name: "netra_policies_history", method: "GET", path: "/api/v1/policies/history",
			description: "List recorded policy revisions (checkpoints, applies, rollbacks, deletes) Netra has captured, optionally filtered by namespace/name.",
			schema: objSchema(map[string]any{
				"namespace": strProp("Filter by namespace."),
				"name":      strProp("Filter by policy name."),
				"limit":     intProp("Max revisions to return, 1-200. Default 50."),
			}),
			queryParams: []string{"namespace", "name", "limit"},
		},
		{
			name: "netra_policies_history_export", method: "GET", path: "/api/v1/policies/history/export",
			description: "Export the full policy revision archive as JSON (for backup or transfer to another controller via netra_policy_history_import).",
			schema:      emptySchema(),
		},
		{
			name: "netra_ebpf_config", method: "GET", path: "/api/v1/ebpf/config",
			description: "The live eBPF fast-path configuration (mode, all blocked IPs/CIDRs/ports/UIDs/DNS/processes/SNI, rate limits, workload scopes).",
			schema:      objSchema(map[string]any{"node": strProp("Also include the current workload inventory for this node.")}),
			queryParams: []string{"node"},
		},
		{
			name: "netra_ebpf_workloads", method: "GET", path: "/api/v1/ebpf/workloads",
			description: "List workload identities (pod/cgroup/container attribution) known to the cluster, optionally for one node.",
			schema:      objSchema(map[string]any{"node": strProp("Restrict to this node. Omit for all nodes.")}),
			queryParams: []string{"node"},
		},
		{
			name: "netra_ebpf_topology", method: "GET", path: "/api/v1/ebpf/topology",
			description: "A derived service/workload topology view built from current agent reports.",
			schema:      objSchema(map[string]any{"limit": intProp("Max topology items, 1-1000. Default 100.")}),
			queryParams: []string{"limit"},
		},
		{
			name: "netra_ebpf_summary", method: "GET", path: "/api/v1/ebpf/summary",
			description: "A high-level rollup of eBPF fast-path activity across all agents.",
			schema:      emptySchema(),
		},
		{
			name: "netra_ebpf_health", method: "GET", path: "/api/v1/ebpf/health",
			description: "Network health diagnostics and anomalies derived from agent reports (TCP health, retransmits, connect latency, etc.).",
			schema:      objSchema(map[string]any{"limit": intProp("Max items, 1-200. Default 20.")}),
			queryParams: []string{"limit"},
		},
		{
			name: "netra_ebpf_capdrift", method: "GET", path: "/api/v1/ebpf/capdrift",
			description: "Capability-change anomalies (effective-capability gain/loss) on processes the eBPF datapath already tracks — agent-sourced from a periodic /proc scan (requires NETRA_PROCMETA_ENABLED on the agent), not a live kernel credential read. Includes a capdrift-coverage-gap finding when an agent restarted recently, since its in-memory diff state resets on restart.",
			schema:      objSchema(map[string]any{"limit": intProp("Max items, 1-200. Default 50.")}),
			queryParams: []string{"limit"},
		},
		{
			name: "netra_ebpf_nsdrift", method: "GET", path: "/api/v1/ebpf/nsdrift",
			description: "Network-namespace-change anomalies on processes the eBPF datapath already tracks — a live process moving network namespaces after start (setns), agent-sourced from the same periodic /proc scan capability-drift uses (requires NETRA_PROCMETA_ENABLED). Includes an nsdrift-coverage-gap finding when an agent restarted recently.",
			schema:      objSchema(map[string]any{"limit": intProp("Max items, 1-200. Default 50.")}),
			queryParams: []string{"limit"},
		},
		{
			name: "netra_ebpf_exehash", method: "GET", path: "/api/v1/ebpf/exehash",
			description: "Executable-content-hash-change anomalies on processes the eBPF datapath already tracks — a live process's on-disk binary content changing while it runs. Observe-only half of exe-hash leased deny; agent-sourced from the same periodic /proc scan capability-drift uses (requires NETRA_PROCMETA_ENABLED). Includes an exehash-coverage-gap finding when an agent restarted recently.",
			schema:      objSchema(map[string]any{"limit": intProp("Max items, 1-200. Default 50.")}),
			queryParams: []string{"limit"},
		},
		{
			name: "netra_ebpf_path", method: "GET", path: "/api/v1/ebpf/path",
			description: "Path diagnostics: per-hop/per-hook health signals for traffic across the cluster.",
			schema:      objSchema(map[string]any{"limit": intProp("Max items, 1-500. Default 50.")}),
			queryParams: []string{"limit"},
		},
		{
			name: "netra_ebpf_drops", method: "GET", path: "/api/v1/ebpf/drops",
			description: "Drop diagnostics aggregated from kernel skb drop-reason counters across agents.",
			schema:      objSchema(map[string]any{"limit": intProp("Max items, 1-500. Default 50.")}),
			queryParams: []string{"limit"},
		},
		{
			name: "netra_ebpf_sysctl_audit", method: "GET", path: "/api/v1/ebpf/sysctl-audit",
			description: "Network-hardening/tuning sysctl inventory across agents: per-interface security posture (rp_filter, redirects, source-route, martians, proxy_arp), IPv6 posture, TCP tuning/lifecycle, conntrack timeouts, and ARP/neighbor/bridge settings, flagged against an established hardening baseline where one exists. Context-dependent settings (ip_forward, disable_ipv6, tcp_congestion_control, conntrack timeout durations, etc.) are reported informationally, without a pass/fail verdict. Distinct from netra_ebpf_drops/kernel-network, which are evidence-correlated congestion diagnostics.",
			schema:      objSchema(map[string]any{"limit": intProp("Max findings/outlier rows per node, 1-500. Default 50.")}),
			queryParams: []string{"limit"},
		},
		{
			name: "netra_ebpf_dns_findings", method: "GET", path: "/api/v1/ebpf/dns-findings",
			description: "Metadata-only DNS anomaly findings (tunneling, DGA, beaconing, NXDOMAIN/SERVFAIL storms) from a continuously-running detector fed by matched DNS-response events. Observe-only; a miss does not prove a domain is benign. Returns 409 if NETRA_DNSDETECT_ENABLED is not set. Distinct from netra_dns_board, which is per-name query/failure counters, not behavioral detection.",
			schema:      emptySchema(),
		},
		{
			name: "netra_ebpf_scan_findings", method: "GET", path: "/api/v1/ebpf/scan-findings",
			description: "Port-scan, fan-out, lateral-movement, and SYN-flood findings from a continuously-running detector fed by per-connection-attempt TCP flag data. Allowed (non-blocked) traffic is only sampled by the datapath, so absence of a finding is not proof a workload made no such attempts. Returns 409 if NETRA_SCANDETECT_ENABLED is not set.",
			schema:      emptySchema(),
		},
		{
			name: "netra_ebpf_ipv6", method: "GET", path: "/api/v1/ebpf/ipv6",
			description: "IPv6 extension-header and fragmentation diagnostics: extension-header counts, fragmentation rate, and truncated-chain counts per node, with anomaly detection.",
			schema:      objSchema(map[string]any{"limit": intProp("Max items, 1-500. Default 50.")}),
			queryParams: []string{"limit"},
		},
		{
			name: "netra_ebpf_shield", method: "GET", path: "/api/v1/ebpf/shield",
			description: "XDP Shield diagnostics: allowed/dropped/audited traffic broken out by class (SYN/UDP/ICMP/other) per node, plus the top offending sources across the cluster, with anomaly detection.",
			schema:      objSchema(map[string]any{"limit": intProp("Max items, 1-500. Default 50.")}),
			queryParams: []string{"limit"},
		},
		{
			name: "netra_ebpf_interfaces", method: "GET", path: "/api/v1/ebpf/interfaces",
			description: "Per-interface flow attribution: packets/bytes/blocked and top destinations per network interface, from Netra's TC/TCX-attached hooks only (not cgroup or XDP-early-deny traffic).",
			schema:      objSchema(map[string]any{"limit": intProp("Max top destinations per interface, 1-200. Default 10.")}),
			queryParams: []string{"limit"},
		},
		{
			name: "netra_ebpf_diagnose", method: "GET", path: "/api/v1/ebpf/diagnose",
			description: "Drop-detective findings: likely root causes for observed drops, correlated with the current fast-path config.",
			schema:      objSchema(map[string]any{"limit": intProp("Max findings. Default 50.")}),
			queryParams: []string{"limit"},
		},
		{
			name: "netra_ebpf_l7", method: "GET", path: "/api/v1/ebpf/l7",
			description: "Best-effort L7 observability: TLS SNI, cleartext HTTP/1 method+Host, and HTTP/1 status when the status line starts the packet.",
			schema:      objSchema(map[string]any{"limit": intProp("Max items, 1-1000. Default 100.")}),
			queryParams: []string{"limit"},
		},
		{
			name: "netra_ebpf_capabilities", method: "GET", path: "/api/v1/ebpf/capabilities",
			description: "Static manifest of this Netra deployment's eBPF hooks, observability signals, and enforcement capabilities, including per-rule-type map capacity limits.",
			schema:      emptySchema(),
		},
		{
			name: "netra_ebpf_rules_list", method: "GET", path: "/api/v1/ebpf/rules",
			description: "List every eBPF fast-path deny rule (exact IP, CIDR, port, UID, process, DNS, SNI, rate limit) with its stable ID, so it can be referenced by netra_ebpf_rules_patch/_delete/_history instead of the legacy value-keyed add/delete tools.",
			schema:      emptySchema(),
		},
		{
			name: "netra_ebpf_rules_get", method: "GET", path: "/api/v1/ebpf/rules/{id}",
			description: "Get one eBPF fast-path rule by its stable ID.",
			schema:      objSchema(map[string]any{"id": strProp("Rule ID from netra_ebpf_rules_list.")}, "id"),
			pathParams:  []string{"id"},
		},
		{
			name: "netra_ebpf_rules_history", method: "GET", path: "/api/v1/ebpf/rules/{id}/history",
			description: "Revision history for one eBPF fast-path rule's edits (via netra_ebpf_rules_patch), each with a before/after snapshot. Rule creation/deletion remain visible via netra_audit instead.",
			schema: objSchema(map[string]any{
				"id":    strProp("Rule ID from netra_ebpf_rules_list."),
				"limit": intProp("Max revisions to return, 1-200. Default 50."),
			}, "id"),
			pathParams:  []string{"id"},
			queryParams: []string{"limit"},
		},
		{
			name: "netra_insights_summary", method: "GET", path: "/api/v1/insights/summary",
			description: "Rollup counts across dependency graph, behavior drift, rate drift, exposure, and remediation insights.",
			schema:      emptySchema(),
		},
		{
			name: "netra_insights_dependencies", method: "GET", path: "/api/v1/insights/dependencies",
			description: "The inferred service dependency graph (who talks to whom, including external destinations).",
			schema:      objSchema(map[string]any{"limit": intProp("Max edges, 1-5000. Default 500.")}),
			queryParams: []string{"limit"},
		},
		{
			name: "netra_insights_baseline_get", method: "GET", path: "/api/v1/insights/baseline",
			description: "The currently captured behavior baseline, if any (see netra_insights_baseline_capture to create one).",
			schema:      emptySchema(),
		},
		{
			name: "netra_insights_drift", method: "GET", path: "/api/v1/insights/drift",
			description: "Behavior drift findings: how current traffic differs from the captured baseline.",
			schema:      emptySchema(),
		},
		{
			name: "netra_insights_recommendations", method: "GET", path: "/api/v1/insights/recommendations",
			description: "Suggested NetworkPolicy changes derived from the dependency graph and observed behavior. Always requires human review before applying (applyRequiresReview is always true in the result).",
			schema: objSchema(map[string]any{
				"limit":     intProp("Max recommendations, 1-200. Default 50."),
				"namespace": strProp("Filter by namespace."),
				"workload":  strProp("Filter by workload name."),
			}),
			queryParams: []string{"limit", "namespace", "workload"},
		},
		{
			name: "netra_insights_zero_trust", method: "GET", path: "/api/v1/insights/zero-trust",
			description: "Identity-aware Zero Trust allow/deny drafts from live workload traffic. Review-only; never applies. Durable NetPol remains PacketWolf/Cilium when present.",
			schema:      objSchema(map[string]any{"limit": intProp("Max drafts, 1-200. Default 50.")}),
			queryParams: []string{"limit"},
		},
		{
			name: "netra_insights_microseg", method: "GET", path: "/api/v1/insights/microseg",
			description: "East-west microsegmentation guidance: prefer PacketWolf on Cilium; Netra lease drafts only when Cilium is absent.",
			schema:      objSchema(map[string]any{"limit": intProp("Max Netra lease drafts when applicable.")}),
			queryParams: []string{"limit"},
		},
		{
			name: "netra_insights_shadow_saas", method: "GET", path: "/api/v1/insights/shadow-saas",
			description: "Shadow SaaS / unsanctioned destinations from SNI/Host/DNS vs NETRA_SANCTIONED_HOSTS. Observe-only CASB-lite.",
			schema:      objSchema(map[string]any{"limit": intProp("Max findings.")}),
			queryParams: []string{"limit"},
		},
		{
			name: "netra_insights_experience", method: "GET", path: "/api/v1/insights/experience",
			description: "Workload digital-experience scorecard from connect latency, TCP retrans/RTO, DNS failures. No endpoint agent.",
			schema:      objSchema(map[string]any{"limit": intProp("Max workloads.")}),
			queryParams: []string{"limit"},
		},
		{
			name: "netra_flow_history", method: "GET", path: "/api/v1/flows/history",
			description: "Queryable flow history (pod, peer, port, protocol, bytes, drops, comm). 7-day sidecar, no payloads.",
			schema: objSchema(map[string]any{
				"since":     strProp("Duration (1h) or RFC3339. Default 1h. Max 168h."),
				"namespace": strProp("Filter by namespace."),
				"pod":       strProp("Filter by pod name."),
				"peer":      strProp("Filter by peer IP."),
				"protocol":  strProp("Filter by protocol, for example tcp."),
				"app":       strProp("Well-known-port hint: mysql, postgres, redis, kafka, grpc, http, https."),
				"node":      strProp("Filter by node."),
				"limit":     intProp("Max records, 1-2000. Default 200."),
			}),
			queryParams: []string{"since", "namespace", "pod", "peer", "protocol", "app", "node", "limit"},
		},
		{
			name: "netra_insights_red", method: "GET", path: "/api/v1/insights/red",
			description: "Per-workload rate, errors, and TCP SRTT over a window. Errors are drops and retransmits, not HTTP status.",
			schema:      objSchema(map[string]any{"window": strProp("Duration, for example 5m. Max 168h.")}),
			queryParams: []string{"window"},
		},
		{
			name: "netra_insights_traces", method: "GET", path: "/api/v1/insights/traces",
			description: "Inferred service-path spans from flow edges and pod IPs. Not propagated trace context.",
			schema: objSchema(map[string]any{
				"since":     strProp("Duration, for example 15m. Max 168h."),
				"namespace": strProp("Filter by namespace."),
				"pod":       strProp("Filter by pod name."),
			}),
			queryParams: []string{"since", "namespace", "pod"},
		},
		{
			name: "netra_insights_profiles", method: "GET", path: "/api/v1/insights/profiles",
			description: "Bounded kernel stacks for the hottest host comms, plus the kernel wait channel (wchan). Not a user-space flame graph. No argv.",
			schema:      objSchema(map[string]any{}),
		},
		{
			name: "netra_insights_workload_events", method: "GET", path: "/api/v1/insights/workload-events",
			description: "Kubernetes Warning events for pods (OOMKilled, probe failures, BackOff). Not journal or dmesg.",
			schema: objSchema(map[string]any{
				"namespace": strProp("Restrict to this namespace."),
				"pod":       strProp("Restrict to this pod name."),
			}),
			queryParams: []string{"namespace", "pod"},
		},
		{
			name: "netra_insights_kernel_notes", method: "GET", path: "/api/v1/insights/kernel-notes",
			description: "Scrubbed kernel log lines about netdev, TCP, UDP, conntrack, and OOM. Not the application journal.",
			schema:      objSchema(map[string]any{}),
		},
		{
			name: "netra_insights_destination_risk", method: "GET", path: "/api/v1/insights/destination-risk",
			description: "Combined destination risk from intel hits, categories, AI/MCP, DoH/DoT, and volume. Observe-only.",
			schema:      objSchema(map[string]any{"limit": intProp("Max destinations.")}),
			queryParams: []string{"limit"},
		},
		{
			name: "netra_insights_policy_packs", method: "GET", path: "/api/v1/insights/policy-packs",
			description: "Review-only sanctioned-egress CiliumNetworkPolicy packs from NETRA_SANCTIONED_HOSTS + observed traffic. Prefer PacketWolf to apply.",
			schema:      objSchema(map[string]any{"limit": intProp("Max packs.")}),
			queryParams: []string{"limit"},
		},
		{
			name: "netra_insights_identity_drafts", method: "GET", path: "/api/v1/insights/identity-drafts",
			description: "ServiceAccount + label identity drafts with review-only CNP sketches. Never auto-applied.",
			schema:      objSchema(map[string]any{"limit": intProp("Max drafts.")}),
			queryParams: []string{"limit"},
		},
		{
			name: "netra_insights_ech_blind", method: "GET", path: "/api/v1/insights/ech-blind",
			description: "ECH / missing-SNI blindness board. Observe-only; no decrypt.",
			schema:      objSchema(map[string]any{"limit": intProp("Max findings.")}),
			queryParams: []string{"limit"},
		},
		{
			name: "netra_insights_exfil", method: "GET", path: "/api/v1/insights/exfil",
			description: "Exfil heuristics: destination fan-out, volume, rare hosts. Not DLP.",
			schema:      objSchema(map[string]any{"limit": intProp("Max findings.")}),
			queryParams: []string{"limit"},
		},
		{
			name: "netra_insights_lateral", method: "GET", path: "/api/v1/insights/lateral",
			description: "Lateral-movement playbooks from scan findings with review-only lease drafts.",
			schema:      objSchema(map[string]any{"limit": intProp("Max playbooks.")}),
			queryParams: []string{"limit"},
		},
		{
			name: "netra_insights_category_deny", method: "GET", path: "/api/v1/insights/category-deny",
			description: "Review-only leased SNI deny drafts for selected app categories (default social,finance).",
			schema:      objSchema(map[string]any{"limit": intProp("Max drafts."), "categories": strProp("Comma-separated categories.")}),
			queryParams: []string{"limit", "categories"},
		},
		{
			name: "netra_intel_dns_hits", method: "GET", path: "/api/v1/intel/dns-hits",
			description: "DNS/C2-style domain board: intel suffix match + NX/DGA heuristics.",
			schema:      objSchema(map[string]any{"limit": intProp("Max hits.")}),
			queryParams: []string{"limit"},
		},
		{
			name: "netra_insights_rates", method: "GET", path: "/api/v1/insights/rates",
			description: "Current traffic-rate window (packets/bytes per second) across agents.",
			schema:      objSchema(map[string]any{"window": strProp("Duration string, e.g. \"5m\", between 30s and 2h. Default 5m.")}),
			queryParams: []string{"window"},
		},
		{
			name: "netra_insights_rate_baseline_get", method: "GET", path: "/api/v1/insights/rate-baseline",
			description: "The currently captured traffic-rate baseline, if any (see netra_insights_rate_baseline_capture to create one).",
			schema:      emptySchema(),
		},
		{
			name: "netra_insights_rate_drift", method: "GET", path: "/api/v1/insights/rate-drift",
			description: "How current traffic rates differ from the captured rate baseline.",
			schema:      objSchema(map[string]any{"window": strProp("Duration string, e.g. \"5m\", between 30s and 2h. Default 5m.")}),
			queryParams: []string{"window"},
		},
		{
			name: "netra_insights_exposure", method: "GET", path: "/api/v1/insights/exposure",
			description: "Exposure findings combining the dependency graph with behavior and rate drift (e.g. workloads newly reachable from outside the cluster).",
			schema:      objSchema(map[string]any{"window": strProp("Rate-drift window, e.g. \"5m\". Default 5m.")}),
			queryParams: []string{"window"},
		},
		{
			name: "netra_insights_blast_radius", method: "GET", path: "/api/v1/insights/blast-radius",
			description: "Multi-hop reachability from one dependency-graph node, breadth-first over observed traffic edges. This is OBSERVED TRAFFIC REACHABILITY, not a policy allow/deny determination — a node with no edges here may still be permitted to reach further destinations that simply weren't observed in this window. Edges may be stale relative to the currently applied policy.",
			schema: objSchema(map[string]any{
				"root": strProp("Dependency-graph node ID to start from (see netra_insights_dependencies for IDs, e.g. \"workload:prod:deployment:api\")."),
				"hops": intProp("Max hops to traverse, 1-6. Default 3."),
			}, "root"),
			queryParams: []string{"root", "hops"},
		},
		{
			name: "netra_insights_health_trend", method: "GET", path: "/api/v1/insights/health-trend",
			description: "Linear time-to-breach projection from recent cluster health-score history. A heuristic trend over a coarse, step-function score, never a statistical guarantee — confidence is always \"low\" or \"medium\", never \"high\". Returns no projection (with an explanatory note) when there's too little history, the trend is flat/improving, the fit is too noisy, or the breach would be beyond a 24h horizon.",
			schema:      objSchema(map[string]any{"threshold": intProp("Health-score breach threshold, 0-99. Default 50.")}),
			queryParams: []string{"threshold"},
		},
		{
			name: "netra_incidents", method: "GET", path: "/api/v1/incidents",
			description: "Cross-signal incident clusters: health anomalies, behavior/rate drift, exposure, drop-detective findings, and audit events joined by a shared canonical source (workload/pod/cgroup/node), only surfaced once at least two different signal kinds agree on the same source. Drop-detective and audit-event joins are best-effort (joinConfidence=\"probable\") since neither carries direct namespace/pod attribution; joinConfidence=\"\" means the finding is real but couldn't be attributed to a specific workload at all (grouped under sourceKey=\"control-plane\" instead of being dropped).",
			schema:      objSchema(map[string]any{"auditLimit": intProp("Max audit events considered, 1-1000. Default 200.")}),
			queryParams: []string{"auditLimit"},
		},
		{
			name: "netra_incidents_timeline", method: "GET", path: "/api/v1/incidents/timeline",
			description: "Chronological, human-readable timeline merging the audit log with cluster-health-signature (AI digest fingerprint) transitions. Each entry is a plain sentence, never raw counters. An optional LLM prose rewrite (engine=\"llm\") is attempted only when NETRA_AI_API_KEY is set; the deterministic bullet-point entries are always present and complete on their own.",
			schema:      objSchema(map[string]any{"since": strProp("RFC3339 timestamp; only entries at or after this time are returned. Omit for everything retained (audit: up to 1000 events; health samples: up to 2h).")}),
			queryParams: []string{"since"},
		},
		{
			name: "netra_insights_policy_review", method: "GET", path: "/api/v1/insights/policy-review",
			description: "Full review for one policy recommendation (from netra_insights_recommendations): which live CiliumNetworkPolicy actually governs the workload (best-effort label match, may be ambiguous), a semantic diff against it, a traffic-aware blast-radius check for each destination the diff would remove (CIDR destinations checked against live traffic; FQDN/entity destinations honestly marked \"could not correlate\", never a false negative), and recent policy revision history. Read-only — never applies anything.",
			schema: objSchema(map[string]any{
				"recommendationId": strProp("Recommendation ID from netra_insights_recommendations."),
			}, "recommendationId"),
			queryParams: []string{"recommendationId"},
		},
		{
			name: "netra_insights_new_since_start", method: "GET", path: "/api/v1/insights/new-since-start",
			description: "Behavior-drift findings (new destinations since the captured baseline) whose owning pod/workload started after that baseline — a plausible \"first egress after start\" correlation, not a precise timing claim (no conversion exists between kernel-boot-monotonic packet timestamps and Kubernetes wall-clock pod start times). Stateless and on-demand: may repeat the same finding across a pod's crash loop, unlike the alert-poller's equivalent which suppresses that for one cycle. Requires a captured behavior baseline (see netra_insights_baseline_capture).",
			schema:      objSchema(map[string]any{"maxRestarts": intProp("Exclude pods/workloads with more cumulative container restarts than this. 0 disables the filter. Default 5.")}),
			queryParams: []string{"maxRestarts"},
		},
		{
			name: "netra_insights_protocol_downgrades", method: "GET", path: "/api/v1/insights/protocol-downgrades",
			description: "Workload/host pairs with TLS handshake history at baseline capture time that now also show cleartext HTTP to the same host. Coexistence-tolerant correlation, never a verdict — do not describe a finding as a \"downgrade attack\", \"MITM\", or \"stripped\" TLS. Check l7Degraded/l7DegradedNodes before reading an empty result as \"no downgrades\": when true, the L7 (TLS SNI / HTTP Host) BPF programs failed to load on those nodes, so visibility there is genuinely incomplete, not clean. Requires a captured behavior baseline.",
			schema:      emptySchema(),
		},
		{
			name: "netra_policy_gitops_status", method: "GET", path: "/api/v1/policies/gitops/status",
			description: "GitOps reconciler status: every manifest under NETRA_GITOPS_DIR, its computed change plan, whether it applied, and whether it's drifted (live policy differs from the last GitOps-applied revision — never auto-applied over). 409 if GitOps is not enabled (NETRA_GITOPS_DIR unset).",
			schema:      emptySchema(),
		},
		{
			name: "netra_ai_status", method: "GET", path: "/api/v1/ai/status",
			description: "Whether the optional LLM rewrite path is configured. Heuristic briefs always work; an API key is required only for prose rewrite. AI endpoints never mutate.",
			schema:      emptySchema(),
		},
		{
			name: "netra_ai_brief", method: "GET", path: "/api/v1/ai/brief",
			description: "Deterministic cluster network brief built from live agent/health/insights aggregates. No packet payloads. Read-only.",
			schema:      emptySchema(),
		},
		{
			name: "netra_ai_ask", method: "POST", path: "/api/v1/ai/ask",
			description: "Ask a natural-language question about the current Netra snapshot. Answers from aggregates only. Optional LLM rewrite when NETRA_AI_API_KEY is set on the controller. Never mutates.",
			schema: objSchema(map[string]any{
				"question":  strProp("Operator question, e.g. \"why is DNS failing in kube-system?\"."),
				"namespace": strProp("Optional namespace hint included in the answer context."),
				"preferLlm": map[string]any{"type": "boolean", "description": "Hint only; the controller uses the configured provider when a key is set."},
			}, "question"),
			bodyFields: true,
		},
		{
			name: "netra_ai_draft", method: "POST", path: "/api/v1/ai/draft",
			description: "Parse a natural-language deny/rate request into a preview eBPF rule. Never applies. Review the body/CLI then use a mutating tool only if the operator explicitly wants it.",
			schema:      objSchema(map[string]any{"question": strProp("e.g. \"deny dns malware.example\" or \"rate limit 1.2.3.4 to 100 pps\".")}, "question"),
			bodyFields:  true,
		},
		{
			name: "netra_ai_digest", method: "GET", path: "/api/v1/ai/digest",
			description: "On-call digest: severity, incident fingerprint, copy-paste card. Fingerprint stays stable while only raw counters chatter.",
			schema:      emptySchema(),
		},
		{
			name: "netra_ai_suggestions", method: "GET", path: "/api/v1/ai/suggestions",
			description: "Live follow-up questions derived from the current snapshot (stale agents, DNS, exposure, lease).",
			schema:      emptySchema(),
		},
		{
			name: "netra_ai_explain", method: "POST", path: "/api/v1/ai/explain",
			description: "Narrate one structured finding (kind/subject/message/page) against the live snapshot. Read-only.",
			schema: objSchema(map[string]any{
				"kind":     strProp("Finding kind, e.g. dns-failure or kfree_skb."),
				"subject":  strProp("Workload or node subject."),
				"message":  strProp("Original finding text."),
				"severity": strProp("info|warning|critical."),
				"page":     strProp("Dashboard page the finding came from: health, drops, insights."),
				"question": strProp("Optional override question."),
			}),
			bodyFields: true,
		},
		{
			name: "netra_ai_agent", method: "POST", path: "/api/v1/ai/agent",
			description: "Run the in-process natural-language graph: classify the question, optionally preview a deny/rate/allow draft, then synthesize a brief. Same snapshot and read-only contract as netra_ai_ask. Returns a step trace. Never applies rules.",
			schema: objSchema(map[string]any{
				"question":       strProp("Operator question, e.g. \"why is DNS failing in kube-system?\" or \"deny dns malware.example\"."),
				"namespace":      strProp("Optional namespace hint included in the answer context."),
				"preferLlm":      map[string]any{"type": "boolean", "description": "Hint only; the controller uses the configured provider when a key is set."},
				"conversationId": strProp("Optional. Web/ChatOps multi-turn id; leave empty from MCP — the calling agent already has its own memory."),
			}, "question"),
			bodyFields: true,
		},
		{
			name: "netra_insights_remediations", method: "GET", path: "/api/v1/insights/remediations",
			description: "Proposed remediations combining exposure and drift findings. Always requires human review before applying (reviewRequired is always true, autoApply always false in the result).",
			schema: objSchema(map[string]any{
				"limit":  intProp("Max proposals, 1-200. Default 50."),
				"window": strProp("Rate-drift window, e.g. \"5m\". Default 5m."),
			}),
			queryParams: []string{"limit", "window"},
		},

		// Pure generators: POST endpoints that produce a manifest/preview
		// without mutating the cluster or Netra's store, and without
		// recording an audit event — safe to expose unconditionally.
		{
			name: "netra_policy_build", method: "POST", path: "/api/v1/policies/build",
			description: "Generate a CiliumNetworkPolicy manifest from a simple description, without applying it. Pass the result to netra_policy_plan then netra_policy_apply to actually apply it.",
			schema: objSchema(map[string]any{
				"name":       strProp("Policy name."),
				"namespace":  strProp("Namespace the policy applies to."),
				"selector":   map[string]any{"type": "object", "description": "Pod label selector, e.g. {\"app\":\"checkout\"}.", "additionalProperties": map[string]any{"type": "string"}},
				"kind":       strProp("Workload kind the selector targets, e.g. \"pod\"."),
				"to":         map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "Allowed egress destinations (CIDRs, FQDNs, or entities)."},
				"port":       intProp("Allowed destination port. Omit to allow all ports."),
				"protocol":   strProp("Allowed protocol, e.g. TCP or UDP. Omit for any."),
				"includeDns": map[string]any{"type": "boolean", "description": "Also allow DNS (UDP/53) egress."},
			}, "name", "namespace"),
			bodyFields: true,
		},
		{
			name: "netra_policy_lockdown", method: "POST", path: "/api/v1/policies/lockdown",
			description: "Generate a deny-all CiliumNetworkPolicy manifest for one workload, without applying it. This only produces the manifest — pass it to netra_policy_plan/netra_policy_apply to actually lock the workload down, and use netra_policy_unlock to remove an already-applied lockdown.",
			schema: objSchema(map[string]any{
				"namespace": strProp("Namespace of the workload. Default \"default\"."),
				"name":      strProp("Workload name."),
				"kind":      enumProp("Workload kind. Default \"pod\".", "pod", "vm"),
				"selector":  map[string]any{"type": "object", "description": "Pod label selector. Auto-detected from the live workload if omitted.", "additionalProperties": map[string]any{"type": "string"}},
			}, "name"),
			bodyFields: true,
		},
		{
			name: "netra_ebpf_deny_preview", method: "POST", path: "/api/v1/ebpf/deny/preview",
			description: "Review-only blast radius for a proposed emergency deny. Matches live non-stale agent flow counters, connect-attempt, DNS, TLS SNI, or sampled process events. Applies nothing, writes nothing, does not flip enforce mode. Absence of a hit is not proof the destination is unused.",
			schema: objSchema(map[string]any{
				"kind":         enumProp("Deny kind to preview.", "ip", "cidr", "port", "dns", "sni", "process"),
				"value":        strProp("IP, CIDR, port number, DNS name, SNI, or process comm."),
				"direction":    enumProp("Packet direction to match. Default both.", "egress", "ingress", "both"),
				"protocol":     enumProp("Optional L4 protocol filter for ip/cidr/port.", "TCP", "UDP", "ANY"),
				"port":         intProp("Optional destination port for kind=port when value is not the port."),
				"namespace":    strProp("Optional workload namespace filter."),
				"pod":          strProp("Optional pod name filter."),
				"workloadKind": strProp("Optional owner kind filter."),
				"workloadName": strProp("Optional owner name filter."),
				"limit":        intProp("Max hits to return, 1-200. Default 50."),
			}, "kind", "value"),
			bodyFields: true,
		},
		{
			name: "netra_ebpf_scope_preview", method: "POST", path: "/api/v1/ebpf/scope/preview",
			description: "Preview which pods would match a set of eBPF workload scopes, without changing the active scope (see netra_ebpf_scope_set to apply).",
			schema: objSchema(map[string]any{
				"scopes": map[string]any{
					"type":        "array",
					"description": "Workload scopes to test. Each may specify namespace/pod/workloadKind/workloadName/labels/cgroupId.",
					"items":       map[string]any{"type": "object"},
				},
			}, "scopes"),
			bodyFields: true,
		},
	}

	for _, t := range tools {
		if err := registerEndpointTool(srv, c, t); err != nil {
			return err
		}
	}
	if err := registerPolicySimulate(srv, c); err != nil {
		return err
	}
	if err := registerIntelPreview(srv, c); err != nil {
		return err
	}
	if err := registerIntelFeed(srv, c); err != nil {
		return err
	}
	if err := registerIntelHits(srv, c); err != nil {
		return err
	}
	if err := registerAIDestinations(srv, c); err != nil {
		return err
	}
	if err := registerAutoMitigate(srv, c); err != nil {
		return err
	}
	return registerWatchlistMatch(srv, c)
}

// registerPolicySimulate is bespoke (not table-driven) for the same reason
// registerPolicyPlan in tools_mutate.go is: /api/v1/policies/simulate takes
// the raw candidate manifest as its entire POST body, not a JSON object of
// named arguments. It's registered here, not in tools_mutate.go, because it
// mutates nothing at all — no store write, no audit event, no kube call —
// unlike netra_policy_plan, which issues a preflight receipt and so is
// gated behind NETRA_MCP_ALLOW_MUTATIONS.
func registerPolicySimulate(srv *mcpserver.Server, c *client) error {
	return srv.Register(mcpserver.Tool{
		Name:        "netra_policy_simulate",
		Description: "Evaluate a candidate CiliumNetworkPolicy manifest's egress rules against the observed dependency graph and live workload labels — read-only, applies nothing. toCIDR/toCIDRSet/toEntities/toServices/toEndpoints destinations are precisely computed; toFQDNs destinations are always \"unverified\" (never a false \"denied\"), since there is no DNS/SNI→IP correlation to confirm or rule out a match.",
		InputSchema: objSchema(map[string]any{
			"manifest": strProp("Full CiliumNetworkPolicy manifest (YAML or JSON) to simulate."),
		}, "manifest"),
		Handler: func(ctx context.Context, raw json.RawMessage) (any, bool, error) {
			var x struct {
				Manifest string `json:"manifest"`
			}
			if err := json.Unmarshal(raw, &x); err != nil {
				return fmt.Sprintf("invalid arguments: %v", err), true, nil
			}
			out, status, err := c.do(ctx, "POST", "/api/v1/policies/simulate", []byte(x.Manifest), nil)
			if err != nil {
				return nil, true, err
			}
			return httpResultToToolResult(out, status)
		},
	})
}

// registerIntelPreview posts the raw feed text as the entire body — the
// controller accepts JSON, CSV, or a plain IP/CIDR/DNS list. Preview
// applies nothing; feeding preview.entries to deny/import is a separate,
// mutation-gated tool.
func registerIntelPreview(srv *mcpserver.Server, c *client) error {
	return srv.Register(mcpserver.Tool{
		Name:        "netra_intel_preview",
		Description: "Parse a threat-intel or deny list (JSON entries, CSV type,value,direction, or bare IPs/CIDRs/DNS names) into the shape POST /api/v1/ebpf/deny/import accepts. Applies nothing.",
		InputSchema: objSchema(map[string]any{
			"text": strProp("Feed body: JSON, CSV, or newline-separated IPs/CIDRs/names."),
		}, "text"),
		Handler: func(ctx context.Context, raw json.RawMessage) (any, bool, error) {
			var x struct {
				Text string `json:"text"`
			}
			if err := json.Unmarshal(raw, &x); err != nil {
				return fmt.Sprintf("invalid arguments: %v", err), true, nil
			}
			out, status, err := c.do(ctx, "POST", "/api/v1/intel/preview", []byte(x.Text), nil)
			if err != nil {
				return nil, true, err
			}
			return httpResultToToolResult(out, status)
		},
	})
}

func registerIntelFeed(srv *mcpserver.Server, c *client) error {
	return srv.Register(mcpserver.Tool{
		Name:        "netra_intel_feed_get",
		Description: "Return the active threat-intel feed status and entries. Loading a feed (PUT) is a separate mutate tool.",
		InputSchema: emptySchema(),
		Handler: func(ctx context.Context, _ json.RawMessage) (any, bool, error) {
			out, status, err := c.do(ctx, "GET", "/api/v1/intel/feed", nil, nil)
			if err != nil {
				return nil, true, err
			}
			return httpResultToToolResult(out, status)
		},
	})
}

func registerIntelHits(srv *mcpserver.Server, c *client) error {
	return srv.Register(mcpserver.Tool{
		Name:        "netra_intel_hits",
		Description: "Match the active threat-intel feed against live agent metadata. Observe-only.",
		InputSchema: emptySchema(),
		Handler: func(ctx context.Context, _ json.RawMessage) (any, bool, error) {
			out, status, err := c.do(ctx, "GET", "/api/v1/intel/hits", nil, nil)
			if err != nil {
				return nil, true, err
			}
			return httpResultToToolResult(out, status)
		},
	})
}

func registerAIDestinations(srv *mcpserver.Server, c *client) error {
	return srv.Register(mcpserver.Tool{
		Name:        "netra_ebpf_ai_destinations",
		Description: "Observe known GenAI/MCP SaaS destinations via SNI/HTTP Host/DNS metadata. No payloads. Applies nothing.",
		InputSchema: emptySchema(),
		Handler: func(ctx context.Context, _ json.RawMessage) (any, bool, error) {
			out, status, err := c.do(ctx, "GET", "/api/v1/ebpf/ai-destinations", nil, nil)
			if err != nil {
				return nil, true, err
			}
			return httpResultToToolResult(out, status)
		},
	})
}

func registerAutoMitigate(srv *mcpserver.Server, c *client) error {
	return srv.Register(mcpserver.Tool{
		Name:        "netra_ebpf_auto_mitigate",
		Description: "Status of optional volumetric auto-mitigation (conn-rate / Shield / leased deny). Observe-only.",
		InputSchema: emptySchema(),
		Handler: func(ctx context.Context, _ json.RawMessage) (any, bool, error) {
			out, status, err := c.do(ctx, "GET", "/api/v1/ebpf/auto-mitigate", nil, nil)
			if err != nil {
				return nil, true, err
			}
			return httpResultToToolResult(out, status)
		},
	})
}

func registerWatchlistMatch(srv *mcpserver.Server, c *client) error {
	return srv.Register(mcpserver.Tool{
		Name:        "netra_watchlist_match",
		Description: "Match an intel-grammar list against current flows/events/DNS/SNI. Applies nothing.",
		InputSchema: objSchema(map[string]any{"text": strProp("Feed body.")}, "text"),
		Handler: func(ctx context.Context, raw json.RawMessage) (any, bool, error) {
			var x struct {
				Text string `json:"text"`
			}
			if err := json.Unmarshal(raw, &x); err != nil {
				return fmt.Sprintf("invalid arguments: %v", err), true, nil
			}
			out, status, err := c.do(ctx, "POST", "/api/v1/watchlist/match", []byte(x.Text), nil)
			if err != nil {
				return nil, true, err
			}
			return httpResultToToolResult(out, status)
		},
	})
}
