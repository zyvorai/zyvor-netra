// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package main

// cliCommand is one netractl argv covered by the mock CI gate and (when
// !Mutating && !Streaming) the remote full suite. Args are without the
// binary name. FileKind, when set, asks the test harness to write a temp
// fixture and replace the literal "$FILE" token in Args.
type cliCommand struct {
	Name      string
	Args      []string
	Local     bool // help / no API
	Mutating  bool // skipped on live remote unless NETRA_CLI_ALLOW_MUTATE=1
	Streaming bool // long-lived stream; mock OK, remote suite skips
	Optional  bool // remote: structured HTTP error still counts as PASS (feature off / needs live ids)
	FileKind  string
}

// allCLICommands is the exhaustive netractl surface used by CI.
// Prefer one representative mutating example per family rather than every
// deny/allow variant — those already have focused unit tests.
func allCLICommands() []cliCommand {
	out := []cliCommand{
		// Cluster / lifecycle (help only — Helm needs a real chart+cluster)
		{Name: "help", Args: []string{"--help"}, Local: true},
		{Name: "status-help", Args: []string{"status", "--help"}, Local: true},
		{Name: "install-help", Args: []string{"install", "--help"}, Local: true},
		{Name: "upgrade-help", Args: []string{"upgrade", "--help"}, Local: true},
		{Name: "uninstall-help", Args: []string{"uninstall", "--help"}, Local: true},
		{Name: "install-cli-help", Args: []string{"install-cli", "--help"}, Local: true},
		{Name: "features-help", Args: []string{"features", "--help"}, Local: true},

		{Name: "status-json", Args: []string{"status", "--json"}},
		{Name: "features-list", Args: []string{"features", "list", "--json"}},

		{Name: "audit", Args: []string{"audit"}},
		{Name: "audit-summary", Args: []string{"audit", "summary"}},

		{Name: "export-audit", Args: []string{"export", "audit", "--limit", "5"}},
		{Name: "export-events", Args: []string{"export", "events", "--limit", "5"}},
		{Name: "export-flows", Args: []string{"export", "flows", "--limit", "5"}},
		{Name: "export-blocks", Args: []string{"export", "blocks", "--limit", "5"}},
		{Name: "export-status", Args: []string{"export", "status"}},

		{Name: "report", Args: []string{"report", "--format", "json"}},
		{Name: "report-prevention", Args: []string{"report", "prevention"}},
		{Name: "playbooks", Args: []string{"playbooks", "--format", "json"}},
		{Name: "handoff", Args: []string{"handoff", "--format", "json"}},

		{Name: "fleet", Args: []string{"fleet"}},
		{Name: "fleet-clusters", Args: []string{"fleet-clusters"}},
		{Name: "fleet-tenants", Args: []string{"fleet-tenants"}},
		{Name: "compliance", Args: []string{"compliance"}},
		{Name: "node-resources", Args: []string{"node-resources"}},
		{Name: "netlink-state", Args: []string{"netlink", "state"}},
		{Name: "netlink-events", Args: []string{"netlink", "events", "--since", "30m", "--limit", "20"}},
		{Name: "netlink-findings", Args: []string{"netlink", "findings"}},
		{Name: "metrics-help", Args: []string{"metrics", "--help"}, Local: true},
		{Name: "metrics-nodes", Args: []string{"metrics", "nodes", "--json"}, Optional: true},
		{Name: "metrics-contexts", Args: []string{"metrics", "contexts", "--json"}, Optional: true},
		{Name: "metrics-query", Args: []string{"metrics", "query", "system.cpu", "--after", "-60", "--json"}, Optional: true},
		{Name: "metrics-top", Args: []string{"metrics", "top", "--json"}, Optional: true},
		{Name: "metrics-anomalies", Args: []string{"metrics", "anomalies", "--json"}, Optional: true},
		{Name: "metrics-evidence", Args: []string{"metrics", "evidence", "ebpf.kernel_drops", "--json"}, Optional: true},
		{Name: "metrics-fleet", Args: []string{"metrics", "fleet", "--json"}, Optional: true},
		{Name: "metrics-alerts", Args: []string{"metrics", "alerts", "--json"}, Optional: true},
		{Name: "scorecard", Args: []string{"scorecard"}},
		{Name: "talkers", Args: []string{"talkers"}},
		{Name: "namespaces", Args: []string{"namespaces"}},
		{Name: "heat", Args: []string{"heat"}},
		{Name: "protocols", Args: []string{"protocols"}},
		{Name: "baselines", Args: []string{"baselines"}},
		{Name: "ports", Args: []string{"ports"}},
		{Name: "dnsboard", Args: []string{"dnsboard"}},
		{Name: "lease", Args: []string{"lease"}},
		{Name: "drops", Args: []string{"drops"}},

		{Name: "capture-status", Args: []string{"capture", "status"}},

		{Name: "intel-feed", Args: []string{"intel", "feed"}},
		{Name: "intel-hits", Args: []string{"intel", "hits"}},
		{Name: "intel-dns-hits", Args: []string{"intel", "dns-hits"}},
		{Name: "intel-preview", Args: []string{"intel", "preview", "$FILE"}, FileKind: "intel"},
		{Name: "watchlist-match", Args: []string{"watchlist", "match", "$FILE"}, FileKind: "watchlist"},

		{Name: "flows-summary", Args: []string{"flows", "summary"}},
		{Name: "flows-watch", Args: []string{"flows", "watch"}, Streaming: true},

		// Policy (read + dry-run)
		{Name: "policy-list", Args: []string{"policy", "list"}},
		{Name: "policy-gitops-status", Args: []string{"policy", "gitops", "status"}, Optional: true},
		{Name: "policy-history", Args: []string{"policy", "history", "default", "demo"}},
		{Name: "policy-build", Args: []string{"policy", "build", "--name", "ci-demo", "--namespace", "default", "--selector", "app=web", "--kind", "cidr", "--to", "10.0.0.0/8", "--port", "443"}},
		{Name: "policy-plan", Args: []string{"policy", "plan", "$FILE"}, FileKind: "policy"},
		{Name: "policy-simulate", Args: []string{"policy", "simulate", "$FILE"}, FileKind: "policy"},
		{Name: "policy-apply-dry-run", Args: []string{"policy", "apply", "$FILE", "--dry-run"}, FileKind: "policy"},
		{Name: "policy-archive-export", Args: []string{"policy", "archive", "export", "$FILE"}, FileKind: "out", Mutating: true},

		// AI (read-only + ask)
		{Name: "ai-status", Args: []string{"ai", "status"}},
		{Name: "ai-brief", Args: []string{"ai", "brief"}},
		{Name: "ai-digest", Args: []string{"ai", "digest"}},
		{Name: "ai-suggestions", Args: []string{"ai", "suggestions"}},
		{Name: "ai-ask", Args: []string{"ai", "ask", "what is the cluster mode?"}},
		{Name: "ai-draft", Args: []string{"ai", "draft", "deny egress to 203.0.113.1"}},
		{Name: "ai-agent", Args: []string{"ai", "agent", "summarize talkers"}},
		{Name: "ai-explain", Args: []string{"ai", "explain", "drop", "sample"}},

		// Incidents
		{Name: "incidents", Args: []string{"incidents"}},
		{Name: "incidents-timeline", Args: []string{"incidents", "timeline"}},

		// Explain with fixture input
		{Name: "explain-all", Args: []string{"explain", "--all", "--input", "$FILE", "--format", "json"}, FileKind: "explain"},
	}

	out = append(out, ebpfReadCommands()...)
	out = append(out, insightsReadCommands()...)
	out = append(out, mutatingExamples()...)
	return out
}

func ebpfReadCommands() []cliCommand {
	names := []string{
		"stats", "summary", "coverage", "reasons", "census", "health",
		"capdrift", "nsdrift", "exehash", "path", "drops",
		"kernel-network", "attachments", "sysctl-audit", "dns-findings", "scan-findings",
		"ai-destinations", "app-categories", "auto-mitigate",
		"tls-fingerprints", "tls-fingerprint-risk", "encrypted-dns", "ipv6",
		"shield", "interfaces", "diagnose", "l7", "capabilities", "workloads",
	}
	out := make([]cliCommand, 0, len(names)+5)
	for _, n := range names {
		out = append(out, cliCommand{Name: "ebpf-" + n, Args: []string{"ebpf", n}})
	}
	out = append(out,
		cliCommand{Name: "ebpf-maps", Args: []string{"ebpf", "maps", "--json"}},
		cliCommand{Name: "ebpf-sysctl", Args: []string{"ebpf", "sysctl"}},
		cliCommand{Name: "ebpf-kernel-network-window", Args: []string{"ebpf", "kernel-network", "5m"}},
		cliCommand{Name: "ebpf-scope-show", Args: []string{"ebpf", "scope", "show"}},
		cliCommand{Name: "ebpf-rules-list", Args: []string{"ebpf", "rules", "list"}},
		cliCommand{Name: "ebpf-deny-preview", Args: []string{"ebpf", "deny-preview", "ip", "203.0.113.50", "egress"}},
	)
	for i := range out {
		switch out[i].Name {
		case "ebpf-scan-findings", "ebpf-dns-findings":
			out[i].Optional = true // feature-gated; Conflict when disabled is OK
		}
	}
	return out
}

func insightsReadCommands() []cliCommand {
	names := []string{
		"summary", "dependencies", "drift", "rates", "rate-drift", "exposure",
		"remediations", "protocol-downgrades", "new-since-start", "health-trend",
		"recommendations", "zero-trust", "microseg", "shadow-saas", "experience",
		"destination-risk", "policy-packs", "identity-drafts", "ech-blind",
		"exfil", "lateral", "category-deny",
	}
	out := make([]cliCommand, 0, len(names)+6)
	for _, n := range names {
		out = append(out, cliCommand{Name: "insights-" + n, Args: []string{"insights", n}})
	}
	out = append(out,
		cliCommand{Name: "insights-rate-baseline-show", Args: []string{"insights", "rate-baseline", "show"}},
		cliCommand{Name: "insights-baseline-show", Args: []string{"insights", "baseline", "show"}},
		cliCommand{Name: "insights-blast-radius", Args: []string{"insights", "blast-radius", "ns/pod", "1"}, Optional: true},
		cliCommand{Name: "insights-policy-review", Args: []string{"insights", "policy-review", "rec-ci"}, Optional: true},
		cliCommand{Name: "insights-dependencies-limit", Args: []string{"insights", "dependencies", "10"}},
		cliCommand{Name: "insights-rates-window", Args: []string{"insights", "rates", "5m"}},
	)
	return out
}

func mutatingExamples() []cliCommand {
	return []cliCommand{
		{Name: "ebpf-mode-observe", Args: []string{"ebpf", "mode", "observe"}, Mutating: true},
		{Name: "ebpf-deny-add", Args: []string{"ebpf", "deny", "add", "203.0.113.99", "egress"}, Mutating: true},
		{Name: "ebpf-deny-del", Args: []string{"ebpf", "deny", "del", "203.0.113.99"}, Mutating: true},
		{Name: "ebpf-allow-add", Args: []string{"ebpf", "allow", "add", "203.0.113.100"}, Mutating: true},
		{Name: "ebpf-allow-del", Args: []string{"ebpf", "allow", "del", "203.0.113.100"}, Mutating: true},
		{Name: "ebpf-dns-add", Args: []string{"ebpf", "dns", "add", "ci.example.com"}, Mutating: true},
		{Name: "ebpf-dns-del", Args: []string{"ebpf", "dns", "del", "ci.example.com"}, Mutating: true},
		{Name: "ebpf-process-add", Args: []string{"ebpf", "process", "add", "curl"}, Mutating: true},
		{Name: "ebpf-process-del", Args: []string{"ebpf", "process", "del", "curl"}, Mutating: true},
		{Name: "ebpf-rate-set", Args: []string{"ebpf", "rate", "set", "10.0.0.9", "100", "1000"}, Mutating: true},
		{Name: "ebpf-rate-del", Args: []string{"ebpf", "rate", "del", "10.0.0.9"}, Mutating: true},
		{Name: "ebpf-syn-drop-add", Args: []string{"ebpf", "syn-drop", "add", "203.0.113.9", "egress"}, Mutating: true},
		{Name: "ebpf-syn-drop-del", Args: []string{"ebpf", "syn-drop", "del", "203.0.113.9", "egress"}, Mutating: true},
		{Name: "ebpf-capability-add", Args: []string{"ebpf", "capability", "add", "CAP_NET_RAW"}, Mutating: true},
		{Name: "ebpf-capability-del", Args: []string{"ebpf", "capability", "del", "CAP_NET_RAW"}, Mutating: true},
		{Name: "ebpf-conn-rate-limit-add", Args: []string{"ebpf", "conn-rate-limit", "add", "--namespace", "ci", "--per-second", "10"}, Mutating: true},
		{Name: "ebpf-shield-set", Args: []string{"ebpf", "shield", "set", "--mode", "off"}, Mutating: true},
		{Name: "ebpf-scope-all", Args: []string{"ebpf", "scope", "all"}, Mutating: true},
		{Name: "insights-baseline-capture", Args: []string{"insights", "baseline", "capture"}, Mutating: true},
		{Name: "insights-rate-baseline-capture", Args: []string{"insights", "rate-baseline", "capture"}, Mutating: true},
		{Name: "intel-apply", Args: []string{"intel", "apply"}, Mutating: true},
		{Name: "capture-start", Args: []string{"capture", "start", "ci-node", "--duration", "1s"}, Mutating: true},
		{Name: "capture-stop", Args: []string{"capture", "stop", "ci-node"}, Mutating: true},
	}
}
