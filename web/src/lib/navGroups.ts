// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
import type { Route } from './investigation';

export type Page = Route['page'];

export type NavLink = { page: Page; label: string; blurb: string };
export type NavGroup = { label: string; page?: Page; children?: NavLink[] };

// Menu blurbs are deliberately shorter than each page's own pageHero lede in
// App.tsx (only a couple are identical), so the two are separate copy, not
// duplicates. navGroups.test.ts guards the structural invariants instead:
// every routable page is reachable from the menu and has a label and blurb.
export const navGroups: NavGroup[] = [
  { label: 'Overview', page: 'overview' },
  {
    label: 'Investigate',
    children: [
      { page: 'connections', label: 'Connections', blurb: 'Native eBPF events, workload context, and honest explanations of observed outcomes.' },
      { page: 'workloads', label: 'Workloads', blurb: 'Explore identities and network evidence reported by Netra agents.' },
      { page: 'pods', label: 'Pods', blurb: 'Kubernetes workloads resolved from Netra’s cgroup map.' },
      { page: 'vms', label: 'VMs', blurb: 'KubeVirt and host VMM processes Netra can attribute.' },
      { page: 'explain', label: 'Explain', blurb: 'Passive, read-only evidence from agent reports, one selector away.' },
      { page: 'traffic', label: 'Traffic', blurb: 'Namespace, protocol, port, and DNS breakdowns. No payloads.' },
      { page: 'capture', label: 'Capture', blurb: 'Filtered, time-bounded packet capture per node, live.' },
    ],
  },
  {
    label: 'Diagnostics',
    children: [
      { page: 'health', label: 'Health', blurb: 'RTT, retransmits, RTOs, resets, and cleartext DNS latency from the kernel.' },
      { page: 'path', label: 'Path', blurb: 'Measured active TCP establishment and cwnd/packets-out pressure.' },
      { page: 'drops', label: 'Drops', blurb: 'Kernel skb reasons, softnet pressure, policy-drop findings, and windowed kernel-network diagnostics — see also Congestion Map for where in the stack.' },
      { page: 'congestion', label: 'Congestion Map', blurb: 'A pictorial view of the Linux network stack, colored by where the cluster is congested right now.' },
      { page: 'sysctl-audit', label: 'Sysctl Audit', blurb: 'A flat, baseline-checked inventory of network hardening and tuning sysctls — security posture, IPv6, TCP lifecycle, conntrack timeouts, ARP/bridge — separate from Congestion Map’s evidence-correlated findings.' },
      { page: 'node-resources', label: 'Node Resources', blurb: 'Per-node CPU, memory, and load average, plus per-workload cgroup CPU/memory usage — a "top"-like view, attributed to workloads rather than raw PIDs.' },
      { page: 'l7', label: 'L7', blurb: 'Best-effort SNI and HTTP Host from the datapath.' },
      { page: 'surfaces', label: 'Surfaces', blurb: 'P1–P5 observe boards: JA3, encrypted DNS, shadow SaaS, exfil, fleet tenants, and more.' },
      { page: 'features', label: 'Features', blurb: 'Enable or disable install-time capabilities (DNS detect, auto-mitigate, AI, agent coverage).' },
      { page: 'insights', label: 'Insights', blurb: 'Baselines, drift, and review-only remediation proposals.' },
      { page: 'topology', label: 'Topology', blurb: 'The observed-traffic dependency graph, live and force-directed.' },
    ],
  },
  {
    label: 'Metrics',
    children: [
      { page: 'metrics', label: 'Metrics', blurb: 'Per-second host, network, workload, app and eBPF charts, generated from what the agents collect.' },
      { page: 'metric-anomalies', label: 'Anomalies', blurb: 'Per-dimension ML anomaly rates, and “what changed here?” for any window.' },
      { page: 'metric-alerts', label: 'Metric Alerts', blurb: 'Threshold and anomaly-rate rules with hysteresis, silences and acknowledgements.' },
    ],
  },
  {
    label: 'Security',
    children: [
      { page: 'incidents', label: 'Incidents', blurb: 'Health, drift, exposure, drops, and audit signals joined by shared source.' },
      { page: 'surfaces', label: 'Surfaces', blurb: 'JA3 risk, ECH blindness, DNS intel, exfil/lateral drafts, compliance — observe-only.' },
      { page: 'ebpf', label: 'Firewall', blurb: 'Deny lists, DDoS shield, NetPol, and emergency controls in one place.' },
      { page: 'policies', label: 'Policies', blurb: 'Plan and apply CiliumNetworkPolicy when CRDs are present.' },
      { page: 'audit', label: 'Audit', blurb: 'Controller audit trail for policy and datapath actions.' },
    ],
  },
  {
    label: 'Reports',
    children: [
      { page: 'flows', label: 'Hubble', blurb: 'Optional Cilium enrichment when Hubble Relay is available.' },
      { page: 'report', label: 'Report', blurb: 'A point-in-time health, drift, and incident briefing.' },
      { page: 'scorecard', label: 'Scorecard', blurb: 'Health, stale agents, and blocked events folded into a 0–100 board.' },
      { page: 'talkers', label: 'Talkers', blurb: 'Top destination IPs by packet count. No payloads.' },
    ],
  },
  { label: 'Fleet', page: 'fleet' },
];
