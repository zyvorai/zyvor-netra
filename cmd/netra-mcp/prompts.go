// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package main

import "github.com/zyvorai/netra/internal/mcpserver"

func registerPrompts(srv *mcpserver.Server) error {
	prompts := []mcpserver.Prompt{
		{
			Name:        "netra_triage",
			Description: "Triage the live Netra deployment: brief, health, drops, stale agents. Read-only.",
			Messages: []mcpserver.PromptMessage{{
				Role: "user",
				Text: "You are helping an operator triage a Netra (eBPF network observability) deployment. Call netra_ai_brief first, then netra_ai_status, netra_ebpf_health, and netra_ebpf_diagnose if the brief is not info-severity. Summarize what is actually happening. Do not call any mutating tool. Do not invent counters. Do not recommend flipping enforce mode unless the operator explicitly asks and a lease is already understood.",
			}},
		},
		{
			Name:        "netra_explain_drops",
			Description: "Explain current drops for an optional namespace/pod using Netra tools only.",
			Arguments: []mcpserver.PromptArg{
				{Name: "namespace", Description: "Kubernetes namespace to focus on.", Required: false},
				{Name: "pod", Description: "Pod name to focus on.", Required: false},
			},
			Messages: []mcpserver.PromptMessage{{
				Role: "user",
				Text: "Explain current packet drops. Namespace hint: {{namespace}}. Pod hint: {{pod}}. Use netra_ai_ask with a matching question, netra_drops_explain, and netra_ebpf_diagnose. Stay read-only. Distinguish Hubble drops from Netra deny-list / NetPol v2 / Shield drops.",
			}},
		},
		{
			Name:        "netra_draft_rule",
			Description: "Turn a deny/rate sentence into a preview rule. Never apply it.",
			Arguments: []mcpserver.PromptArg{
				{Name: "request", Description: "Operator sentence, e.g. deny dns malware.example", Required: true},
			},
			Messages: []mcpserver.PromptMessage{{
				Role: "user",
				Text: "Draft a Netra emergency rule for: {{request}}. Call netra_ai_draft first. If understood=false, ask a clarifying question. Do not call any mutating tool. Show the CLI and warnings verbatim. Remind the operator that enforce is lease-bounded.",
			}},
		},
		{
			Name:        "netra_oncall_digest",
			Description: "Produce the current on-call digest and say whether the incident fingerprint changed.",
			Messages: []mcpserver.PromptMessage{{
				Role: "user",
				Text: "Call netra_ai_digest with peek=1 if you are polling. Quote the card. If changed=true, say the fingerprint moved and quote whyChanged (the deterministic list of what changed) — lead with whyChangedProse instead if it is present. Never guess at a cause not present in those fields. Stay read-only.",
			}},
		},
		{
			Name:        "netra_congestion_triage",
			Description: "Triage kernel-network congestion (rcvbuf, listen queues, softnet, qdisc). Read-only.",
			Arguments: []mcpserver.PromptArg{
				{Name: "window", Description: "Lookback window such as 5m or 1h.", Required: false},
			},
			Messages: []mcpserver.PromptMessage{{
				Role: "user",
				Text: "Triage kernel-network congestion. Call netra_ai_congestion_brief with window={{window}}, then netra_ebpf_drops if needed. Summarize where in the stack pressure shows up. Do not recommend sysctl changes as automatic fixes. Stay read-only.",
			}},
		},
		{
			Name:        "netra_incident_timeline",
			Description: "Narrate what happened in the cluster over a time window, in order. Read-only.",
			Arguments: []mcpserver.PromptArg{
				{Name: "since", Description: "RFC3339 timestamp to start from. Omit for everything retained.", Required: false},
			},
			Messages: []mcpserver.PromptMessage{{
				Role: "user",
				Text: "Call netra_incidents_timeline with since={{since}}. Present the entries in chronological order as a short narrative. Each entry is either an audit-log action or a cluster-health-signature change — say which. Do not invent an entry, a cause, or a timestamp the tool did not return. Stay read-only.",
			}},
		},
		{
			Name:        "netra_policy_review",
			Description: "Review insight-generated policy drafts, including a traffic-aware blast-radius check. Never apply them.",
			Arguments: []mcpserver.PromptArg{
				{Name: "namespace", Description: "Namespace to review.", Required: false},
				{Name: "workload", Description: "Workload name to review.", Required: false},
			},
			Messages: []mcpserver.PromptMessage{{
				Role: "user",
				Text: "Review Netra policy drafts for namespace={{namespace}} workload={{workload}}. Call netra_insights_recommendations first, then netra_insights_policy_review with each candidate's id — it already resolves the governing live policy, diffs against it, and checks live traffic against every destination the diff would remove, so don't re-derive blast radius by hand from netra_insights_remediations. Explain the risk level, the diff, and which removed destinations show active live traffic vs. couldn't be correlated (FQDN/entity destinations honestly can't be checked — never claim they're safe to remove just because no CIDR match was found). Do not call netra_policy_apply, netra_ebpf_mode, or any other mutating tool. Remind the operator that plan→apply with a preflight token is mandatory.",
			}},
		},
		{
			Name:        "netra_tls_triage",
			Description: "Triage rare JA3 and ECH-blind findings. Observe-only metadata, no decrypt.",
			Messages: []mcpserver.PromptMessage{{
				Role: "user",
				Text: "Triage TLS ClientHello fingerprints and ECH/missing-SNI blindness. Call netra_ebpf_tls_fingerprint_risk then netra_insights_ech_blind. Summarize rare JA3, ECH sightings, and nodes. Do not invent payloads. Stay read-only.",
			}},
		},
		{
			Name:        "netra_security_review",
			Description: "Review security optimizer, incidents, and intel hits. Suggest only — never apply deny.",
			Messages: []mcpserver.PromptMessage{{
				Role: "user",
				Text: "Call netra_security_optimizer, netra_security_incidents, and netra_intel_hits (or netra_intel_dns_hits). Correlate subjects. Never delete a rule, apply a deny, or quarantine. Stay read-only.",
			}},
		},
		{
			Name:        "netra_metrics_oncall",
			Description: "On-call metrics triage: alerts, anomalies, and congestion brief. Read-only.",
			Arguments: []mcpserver.PromptArg{
				{Name: "window", Description: "Congestion lookback such as 5m or 1h.", Required: false},
			},
			Messages: []mcpserver.PromptMessage{{
				Role: "user",
				Text: "Call netra_metrics_alerts, netra_metrics_anomalies, and netra_ai_congestion_brief with window={{window}}. Summarize raised alerts and anomalous metrics. Do not ack or silence. Stay read-only.",
			}},
		},
		{
			Name:        "netra_netlink_churn",
			Description: "Triage RTNL / route / neigh churn. Read-only netlink recorder.",
			Messages: []mcpserver.PromptMessage{{
				Role: "user",
				Text: "Call netra_netlink_findings and netra_netlink. Summarize requester attribution (comm/pid/cgroup) and interface churn. Never mutate routes. Stay read-only.",
			}},
		},
		{
			Name:        "netra_ai_destinations_review",
			Description: "Review GenAI / MCP destination catalog matches. Observe-only.",
			Messages: []mcpserver.PromptMessage{{
				Role: "user",
				Text: "Call netra_ebpf_ai_destinations. List matched hosts by category. Remind the operator this is hostname metadata only — no prompts or payloads. Stay read-only; do not draft a deny unless asked.",
			}},
		},
		{
			Name:        "netra_shadow_saas",
			Description: "Review shadow SaaS and app-category hits. Observe-only.",
			Messages: []mcpserver.PromptMessage{{
				Role: "user",
				Text: "Call netra_insights_shadow_saas and netra_ebpf_app_categories. Summarize unsanctioned hosts and categories. Stay read-only.",
			}},
		},
		{
			Name:        "netra_capture_status",
			Description: "Summarize live capture status and recent summaries. Read-only.",
			Messages: []mcpserver.PromptMessage{{
				Role: "user",
				Text: "Call netra_capture_status and netra_capture_summaries. Report active captures and recent artifacts. Stay read-only.",
			}},
		},
		{
			Name:        "netra_fleet_rollcall",
			Description: "Fleet roll-call across clusters and metric fleet view. Read-only.",
			Messages: []mcpserver.PromptMessage{{
				Role: "user",
				Text: "Call netra_fleet, netra_fleet_clusters, and netra_metrics_fleet. Summarize cluster health. Stay read-only.",
			}},
		},
	}
	for _, p := range prompts {
		if err := srv.RegisterPrompt(p); err != nil {
			return err
		}
	}
	return nil
}
