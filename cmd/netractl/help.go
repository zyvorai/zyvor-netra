// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package main

import (
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"
)

type helpCmd struct {
	name string
	desc string
}

type helpSection struct {
	title string
	cmds  []helpCmd
}

func helpSections() []helpSection {
	return []helpSection{
		{
			title: "🚀  Cluster",
			cmds: []helpCmd{
				{"status [--json] [--wait]", "Cluster health board (agents, hooks, features)"},
				{"install [flags]", "Helm install (agent+TLS on; installs CLI to PATH)"},
				{"upgrade [flags]", "Helm upgrade --reuse-values"},
				{"uninstall --yes", "Helm uninstall"},
				{"install-cli [--prefix DIR]", "Install this binary onto PATH only"},
				{"features list", "Show capability catalog on/off"},
				{"features enable|disable NAME --yes", "Toggle via Helm (or --api)"},
			},
		},
		{
			title: "🔍  Investigate",
			cmds: []helpCmd{
				{"explain …", "Passive evidence for pod/node/docker/dns/destination"},
				{"fleet | fleet-clusters | fleet-tenants", "Agent inventory / multi-cluster"},
				{"scorecard | talkers | handoff", "Shift board, top destinations, handoff pack"},
				{"namespaces | protocols | baselines | ports | dnsboard", "Traffic breakdowns"},
				{"node-resources | lease | compliance", "Host pressure, enforce lease, checks"},
				{"capture start|stop|status …", "Filtered per-node packet capture"},
			},
		},
		{
			title: "🩺  Diagnostics",
			cmds: []helpCmd{
				{"ebpf summary|health|path|drops|l7|…", "Datapath counters and diagnostics"},
				{"ebpf kernel-network [5m]", "Windowed kernel network pressure"},
				{"ebpf attachments [--node N]", "BPF programs attached per interface + hook drift"},
				{"netlink state|events|findings …", "Route, link, address and neighbor changes + what is wrong now"},
				{"metrics nodes|contexts|query|top|anomalies|alerts", "Per-second host, network, workload and app metrics"},
				{"metrics ack|silence|unsilence", "Acknowledge or silence metric alerts (notifications only)"},
				{"ebpf sysctl-audit | dns-findings | scan-findings", "Hardening + detectors"},
				{"ebpf coverage | census | maps | capabilities", "Hook coverage + map inventory"},
				{"drops [explain]", "Drop explain from policy + kernel"},
				{"insights … | incidents …", "Baselines, drift, joined incidents"},
			},
		},
		{
			title: "🛡️  Control (leased)",
			cmds: []helpCmd{
				{"ebpf mode observe|enforce [lease]", "Fail-open enforce lease"},
				{"ebpf deny|allow|cidr|port|dns|sni|…", "Datapath deny/allow lists"},
				{"ebpf shield … | netpol … | quarantine …", "Shield, NetPol, quarantine"},
				{"ebpf rules list|get|patch|delete|…", "Durable rule history"},
				{"ebpf scope show|all|selected|set", "Workload enforce scope"},
			},
		},
		{
			title: "📜  Policy (Cilium optional)",
			cmds: []helpCmd{
				{"policy list|build|plan|simulate|apply …", "CNP workbench with receipts"},
				{"policy gitops status|resync …", "Mounted-dir GitOps"},
				{"policy history|archive|rollback|delete …", "Revision control"},
				{"flows watch|summary|history …", "Live sample plus queryable flow history"},
			},
		},
		{
			title: "🧰  Ops & AI",
			cmds: []helpCmd{
				{"audit | audit summary", "Controller audit trail"},
				{"export … | report | playbooks", "SIEM export and operator briefs"},
				{"intel … | watchlist …", "Threat intel preview / match"},
				{"ai status|brief|ask|agent|draft|…", "Read-only AI surfaces"},
			},
		},
	}
}

func usage() {
	printUsage(os.Stdout)
}

func printUsage(w io.Writer) {
	file, _ := w.(*os.File)
	if file == nil {
		file = os.Stdout
	}
	if bannerEnabled() && useColor(file) {
		printBanner(file)
	} else if bannerEnabled() && isTTY(file) {
		printBanner(file)
	}

	fmt.Fprintln(w, colorize(file, ansiBold+zyvorOrange, "netractl")+" — Netra operator CLI")
	fmt.Fprintln(w, colorize(file, ansiDim, "👁️  observe  ·  🩺  diagnose  ·  🛡️  contain  ·  fail open"))
	fmt.Fprintln(w)
	fmt.Fprintln(w, colorize(file, ansiBold, "📖  Usage"))
	fmt.Fprintln(w, "  netractl <command> [flags]")
	fmt.Fprintln(w)

	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	for _, sec := range helpSections() {
		fmt.Fprintln(tw, colorize(file, ansiBold+ansiCyan, sec.title))
		for _, c := range sec.cmds {
			cmd := colorize(file, ansiGreen, "  "+c.name)
			fmt.Fprintf(tw, "%s\t%s\n", cmd, colorize(file, ansiDim, c.desc))
		}
		fmt.Fprintln(tw)
	}
	_ = tw.Flush()

	fmt.Fprintln(w, colorize(file, ansiBold, "⚙️  Environment"))
	envLines := []struct{ k, v string }{
		{"NETRA_URL", "controller URL (default https://127.0.0.1:30870)"},
		{"NETRA_API_KEY", "bearer (or ~/.netra/api-key)"},
		{"NETRA_TLS_INSECURE", "skip verify for chart self-signed cert"},
		{"NETRA_CLI_COLOR", "true|false (default: color on TTY)"},
		{"NETRA_CLI_NO_BANNER", "set to hide Zyvor banner"},
		{"NO_COLOR", "disable color (https://no-color.org)"},
	}
	tw = tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	for _, e := range envLines {
		fmt.Fprintf(tw, "  %s\t%s\n", colorize(file, ansiGreen, e.k), colorize(file, ansiDim, e.v))
	}
	_ = tw.Flush()
	fmt.Fprintln(w)
	fmt.Fprintln(w, colorize(file, ansiDim, "📚  Docs: docs/netractl.md  ·  make install  ·  netractl status"))
}

// usagePlain is the dense legacy dump for tests / NETRA_CLI_HELP=plain.
func usagePlain(w io.Writer) {
	fmt.Fprintln(w, strings.TrimSpace(`netractl explain --docker NAME --node NODE | --pod NS/NAME | --node NODE --pid PID | --destination IP[:PORT] | --dns NAME | --all [--format json] [--input FILE]
  status [--json] [--wait]
  install | upgrade | uninstall --yes | install-cli [--prefix DIR]
  features list | features enable NAME --yes | features disable NAME --yes
  audit | audit summary
  export audit|events|flows|blocks|status [--format json|jsonl|cef|syslog|otlp|otlp-trace] [--limit N] [--include anomaly,incident,audit]
  report [--format markdown|json]
  playbooks [--format markdown|json]
  intel preview FILE
  watchlist match FILE
  fleet | fleet-clusters | fleet-tenants | node-resources | handoff [--format markdown|json] | scorecard | talkers
  netlink state|events [--node NODE] [--kind link|address|route|neighbor|overrun] [--since 30m] [--limit N]
  netlink findings [--node NODE] [--window 15m]
  metrics nodes|contexts|query CONTEXT|top|anomalies|alerts [--node N] [--after -600] [--points N] [--group-by dimension|chart|node|label:KEY] [--json]
  metrics ack ALERT_ID | metrics silence [--rule G] [--node G] [--chart G] --for 2h [--comment T] | metrics unsilence ID
  namespaces | protocols | baselines | ports | dnsboard | lease
  capture start NODE [--protocol tcp|udp|icmp|icmpv6] [--host IP] [--port N] [--snaplen N] [--max-pps N] [--duration 60s]
  capture stop NODE | capture status
  policy list [namespace] | policy list --namespace NAMESPACE
  policy build --name NAME --namespace NAMESPACE --selector key=value --kind fqdn|cidr|entity --to DEST [--to DEST] [--port PORT] [--protocol TCP|UDP] [--include-dns]
  policy plan <file> | policy plan --file FILE
  policy simulate <file> | policy simulate --file FILE
  policy apply <file> [--dry-run] [--confirm-risk high|critical] | policy apply --file FILE [--dry-run] [--confirm-risk high|critical]
  policy gitops status | policy gitops resync <file> [--confirm-risk high|critical]
  policy history <namespace> <name>
  policy archive export <file>
  policy archive import <file> [--mode merge|replace]
  policy rollback <namespace> <name> <revision> [--dry-run] [--confirm-risk high|critical]
  policy delete <namespace> <name>
  flows watch|summary [--verdict X --direction X --protocol X --namespace X --pod X --to IP/CIDR]
  flows history [--since 1h --namespace NS --pod POD --peer IP --protocol tcp --app mysql --node NODE --limit N]
  drops [explain]
  ebpf … | insights … | incidents … | ai …`))
}
