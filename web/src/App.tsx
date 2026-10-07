import { useCallback, useEffect, useState } from 'react';
import Nav, { Page } from './components/Nav';
import Overview from './pages/Overview';
import Connections from './pages/Connections';
import ObservedWorkloads from './pages/ObservedWorkloads';
import Explain from './pages/Explain';
import { readRoute, routeHash } from './lib/investigation';
import Path from './pages/Path';
import Drops from './pages/Drops';
import Insights from './pages/Insights';
import Topology from './pages/Topology';
import Incidents from './pages/Incidents';
import SecurityReview from './pages/SecurityReview';
import L7 from './pages/L7';
import Policies from './pages/Policies';
import Flows from './pages/Flows';
import EBPF from './pages/EBPF';
import Health from './pages/Health';
import Audit from './pages/Audit';
import Report from './pages/Report';
import Scorecard from './pages/Scorecard';
import Talkers from './pages/Talkers';
import Fleet from './pages/Fleet';
import Surfaces from './pages/Surfaces';
import Features from './pages/Features';
import Traffic from './pages/Traffic';
import Capture from './pages/Capture';
import CongestionMap from './pages/CongestionMap';
import SysctlAudit from './pages/SysctlAudit';
import NodeResources from './pages/NodeResources';
import Workloads from './pages/Workloads';
import Metrics from './pages/Metrics';
import MetricAnomalies from './pages/MetricAnomalies';
import MetricAlerts from './pages/MetricAlerts';
import PageHero, { type HeroTint } from './components/PageHero';
import Login from './components/Login';
import { sessionAlive } from './api';
import { logout } from './auth';
import { applyTheme, readStoredTheme, toggleTheme, type Theme } from './theme';

const pageHero: Partial<Record<Page, { eyebrow: string; title: string; lede: string; tint?: HeroTint }>> = {
  connections: {
    eyebrow: 'Investigation',
    title: 'Follow every clue.',
    lede: 'Native eBPF events, workload context, and honest explanations of observed outcomes.',
  },
  workloads: {
    eyebrow: 'Investigation',
    title: 'Know the workload.',
    lede: 'Explore identities and network evidence reported by Netra agents.',
  },
  explain: {
    eyebrow: 'Investigation',
    title: 'Explain a connection.',
    lede: 'Passive, read-only evidence from agent reports — the same diagnostics as netractl explain, one selector away.',
  },
  pods: {
    eyebrow: 'Workloads',
    title: 'Pods.',
    lede: 'Kubernetes workloads resolved from Netra’s cgroup map — identity for observe and leased enforce.',
  },
  vms: {
    eyebrow: 'Workloads',
    title: 'Virtual machines.',
    lede: 'KubeVirt and host VMM processes Netra can attribute through cgroup and process metadata.',
  },
  health: {
    eyebrow: 'Network Health',
    title: 'TCP and DNS from the kernel.',
    lede: 'Sockops and packet hooks measure RTT, retransmits, RTOs, resets, and cleartext DNS latency.',
    tint: 'green',
  },
  path: {
    eyebrow: 'Path Diagnostics',
    title: 'Connect latency and pressure.',
    lede: 'Measured active TCP establishment and cwnd/packets-out pressure from standalone sockops.',
    tint: 'green',
  },
  drops: {
    eyebrow: 'Drop Diagnostics',
    title: 'Where packets disappear.',
    lede: 'Kernel skb reasons, softnet pressure, interface counters, windowed kernel-network diagnostics, and Netra policy-drop detective findings — see also Congestion Map for where in the stack.',
    tint: 'amber',
  },
  congestion: {
    eyebrow: 'Drop Diagnostics',
    title: 'Where the stack is under pressure.',
    lede: 'A pictorial view of the Linux network stack — NIC, softirq, IP, sockets, qdisc, conntrack — colored by where the cluster is congested right now, cluster-wide with per-node drill-down.',
    tint: 'amber',
  },
  'sysctl-audit': {
    eyebrow: 'Sysctl Audit',
    title: 'Network hardening, checked.',
    lede: 'A flat, baseline-checked inventory of security posture, IPv6, TCP lifecycle, conntrack timeouts, and ARP/bridge sysctls — separate from Congestion Map’s evidence-correlated findings.',
    tint: 'amber',
  },
  'node-resources': {
    eyebrow: 'Node Resources',
    title: 'CPU, memory, and load — per node.',
    lede: 'A "top"-like snapshot of host CPU, memory, and load average, plus per-workload cgroup CPU/memory usage — complements Sysctl Audit (settings) and Congestion Map (network-stack pressure) with raw compute pressure.',
    tint: 'amber',
  },
  l7: {
    eyebrow: 'L7 Metadata',
    title: 'TLS and cleartext HTTP context.',
    lede: 'Best-effort SNI and HTTP Host from the datapath — evidence for review, not a full proxy. JA3/JA4 and encrypted DNS live under Surfaces.',
    tint: 'amber',
  },
  surfaces: {
    eyebrow: 'Surfaces',
    title: 'Observe-only fit boards.',
    lede: 'P1–P5 metadata: JA3/JA4, encrypted DNS, shadow SaaS, destination risk, exfil/lateral drafts, compliance, fleet tenants — no decrypt, no payload export.',
    tint: 'purple',
  },
  features: {
    eyebrow: 'Features',
    title: 'Turn capabilities on.',
    lede: 'Install-time and controller/agent flags — DNS detect, scan detect, auto-mitigate, AI rewrite, GitOps, TLS fingerprints. Does not flip enforce or apply denies.',
    tint: 'amber',
  },
  insights: {
    eyebrow: 'Insights',
    title: 'Behavior, rates, and exposure.',
    lede: 'Baselines, drift, and review-only remediation proposals derived from exact eBPF counters.',
    tint: 'purple',
  },
  topology: {
    eyebrow: 'Insights',
    title: 'See the graph move.',
    lede: 'The same observed-traffic dependency graph, live and force-directed — drift, rate-drift, and exposure findings overlaid as node color.',
    tint: 'purple',
  },
  'security-review': { eyebrow: 'Security', title: 'Review the evidence.', lede: 'Threat feed history, deny-rule suggestions and recent security signals on the same workload. Observe only.', tint: 'red' },
  incidents: {
    eyebrow: 'Incidents',
    title: 'When signals agree.',
    lede: 'Health, drift, exposure, drops, and audit events joined by shared source — surfaced only when two or more independent signals point at the same place.',
    tint: 'red',
  },
  ebpf: {
    eyebrow: 'Firewall',
    title: 'Observe everywhere. Enforce when leased.',
    lede: 'Every configured rule in one place — deny lists, DDoS shield, and NetPol — plus emergency controls. Netra owns only /sys/fs/bpf/netra.',
    tint: 'red',
  },
  flows: {
    eyebrow: 'Hubble',
    title: 'Optional Cilium enrichment.',
    lede: 'When Hubble Relay is available, enrich the picture. Otherwise use Network Health and eBPF.',
  },
  policies: {
    eyebrow: 'Policies',
    title: 'Cilium workbench.',
    lede: 'Plan and apply CiliumNetworkPolicy when CRDs are present. Standalone eBPF controls work without Cilium.',
  },
  audit: {
    eyebrow: 'Audit',
    title: 'What changed.',
    lede: 'Controller audit trail for policy and datapath actions.',
    tint: 'red',
  },
  report: {
    eyebrow: 'Report',
    title: 'Brief the next operator.',
    lede: 'A point-in-time health, drift, and incident briefing plus review-only playbook steps. Nothing on this page applies policy.',
    tint: 'amber',
  },
  scorecard: {
    eyebrow: 'Scorecard',
    title: 'One number for the shift.',
    lede: 'Health, stale agents, detached programs, and blocked events folded into a 0–100 board. Observe-only.',
    tint: 'green',
  },
  talkers: {
    eyebrow: 'Talkers',
    title: 'Who is talking the most.',
    lede: 'Top destination IPs by packet count from current agent reports. No payloads.',
    tint: 'amber',
  },
  fleet: {
    eyebrow: 'Fleet',
    title: 'Every node, one glance.',
    lede: 'Compact per-node agent inventory plus the eBPF hook/program coverage matrix — attached vs detached, missing maps.',
    tint: 'green',
  },
  traffic: {
    eyebrow: 'Traffic',
    title: 'What the network is carrying.',
    lede: 'Namespace, protocol, port, and DNS breakdowns from current agent destination stats. No payloads.',
    tint: 'purple',
  },
  capture: {
    eyebrow: 'Capture',
    title: 'Watch the wire, live.',
    lede: 'Filtered, time-bounded packet capture per node — full packet bytes by default. A standalone, fail-open eBPF observer; never affects the datapath verdict.',
    tint: 'red',
  },
  metrics: {
    eyebrow: 'Metrics',
    title: 'Every metric, every second.',
    lede: 'Host, network, workload, application and eBPF datapath metrics, collected per second on each node and streamed live. Dashboards build themselves from what the agents report.',
    tint: 'green',
  },
  'metric-anomalies': {
    eyebrow: 'Metrics',
    title: 'What looks unusual, and what changed.',
    lede: 'Every dimension has its own unsupervised model on the node. Drag across the timeline to rank the metrics that shifted most in that window.',
    tint: 'purple',
  },
  'metric-alerts': {
    eyebrow: 'Metrics',
    title: 'Alerts that wait before they shout.',
    lede: 'Threshold and anomaly-rate rules with delays and hysteresis, delivered through the configured alert channels. Alerts never change the datapath.',
    tint: 'amber',
  },
};

export default function App() {
  // Defaults to 'overview' exactly like plain useState('overview') did when
  // there's no hash — only differs when the URL already carries a shared
  // investigation link (#page=...), so a pasted link opens directly to it.
  const [page, setPage] = useState<Page>(() => readRoute(window.location.hash).page as Page);
  const [loggedIn, setLoggedIn] = useState<boolean | null>(null);
  const [authError, setAuthError] = useState('');
  const [theme, setTheme] = useState<Theme>(() => {
    const t = readStoredTheme();
    applyTheme(t);
    return t;
  });

  useEffect(() => {
    let cancel = false;
    sessionAlive().then((ok) => {
      if (!cancel) setLoggedIn(ok);
    });
    return () => {
      cancel = true;
    };
  }, []);

  useEffect(() => {
    const onExpired = () => {
      setAuthError('Wrong username or password — the controller rejected the API token.');
      setLoggedIn(false);
    };
    window.addEventListener('netra-auth-expired', onExpired);
    return () => window.removeEventListener('netra-auth-expired', onExpired);
  }, []);

  // A Nav click shows the page and keeps the hash in step with it, via
  // replaceState: no history entry and no hashchange event, so the click
  // behaves as before. The hash must name the page because the investigation
  // filters and "Copy link" derive the page from it: with an empty hash they
  // read 'overview', so typing in a filter opened from the menu jumped the
  // user back to the Overview. The filter scope in the hash is carried over.
  const goPage = useCallback((next: Page) => {
    setPage(next);
    window.history.replaceState(null, '', routeHash(next, readRoute(window.location.hash).scope));
  }, []);

  // This listener lets the investigation feature's own navigate() calls
  // (which set the hash, for shareable links) switch the visible page too.
  useEffect(() => {
    const onHashChange = () => setPage(readRoute(window.location.hash).page as Page);
    window.addEventListener('hashchange', onHashChange);
    return () => window.removeEventListener('hashchange', onHashChange);
  }, []);

  if (loggedIn === null) return null;
  if (!loggedIn) {
    return (
      <Login
        initialError={authError}
        onLogin={() => {
          setAuthError('');
          setLoggedIn(true);
        }}
      />
    );
  }

  const body = {
    overview: <Overview onNavigate={goPage} />,
    connections: <Connections />,
    workloads: <ObservedWorkloads />,
    explain: <Explain />,
    pods: <Workloads key="pod" kind="pod" />,
    vms: <Workloads key="vm" kind="vm" />,
    health: <Health />,
    path: <Path />,
    drops: <Drops />,
    congestion: <CongestionMap />,
    'sysctl-audit': <SysctlAudit />,
    'node-resources': <NodeResources />,
    l7: <L7 />,
    surfaces: <Surfaces />,
    features: <Features />,
    insights: <Insights />,
    topology: <Topology />,
    incidents: <Incidents />,
    'security-review': <SecurityReview />,
    policies: <Policies />,
    flows: <Flows />,
    ebpf: <EBPF />,
    audit: <Audit />,
    report: <Report />,
    scorecard: <Scorecard />,
    talkers: <Talkers />,
    fleet: <Fleet />,
    traffic: <Traffic />,
    capture: <Capture />,
    metrics: <Metrics />,
    'metric-anomalies': <MetricAnomalies />,
    'metric-alerts': <MetricAlerts />,
  }[page];

  const hero = pageHero[page];

  return (
    <>
      <Nav
        page={page}
        setPage={goPage}
        theme={theme}
        onToggleTheme={() => setTheme((t) => toggleTheme(t))}
        onLogout={() => {
          logout();
          setLoggedIn(false);
        }}
      />
      <main>
        {/* Keyed on `page` so the hero and body remount (rather than just
            re-render in place) on every navigation, re-triggering their
            fadeRise/glow entrance animations — otherwise PageHero, being
            the same component type at the same tree position across page
            switches, would just update props with no visible transition. */}
        <div key={page}>
          {hero && <PageHero eyebrow={hero.eyebrow} title={hero.title} lede={hero.lede} tint={hero.tint} />}
          {body}
        </div>
      </main>
    </>
  );
}
