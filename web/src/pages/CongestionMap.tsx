import { useEffect, useMemo, useState } from 'react';
import { api } from '../api';
import ExplainFinding from '../components/ExplainFinding';
import Sparkline from '../components/Sparkline';
import PagePulse from '../components/kit/PagePulse';
import { countTone } from '../components/kit/tone';
import { navigate } from '../hooks/useInvestigation';

type KernelFinding = {
  severity: string;
  layer: string;
  signal: string;
  evidence?: string[];
  explanation: string;
  recommendation: string;
  risk: string;
  tunable?: string;
  currentValue?: string;
  suggestedValue?: string;
  applyCommand?: string;
  rollbackCommand?: string;
};
type WindowCounter = { name: string; delta: number; perSecond: number };
type KernelWindow = {
  warming: boolean;
  resetDetected?: boolean;
  resetSignals?: string[];
  seconds?: number;
  counters?: WindowCounter[];
  softnetDropped?: number;
  softnetDroppedPerSecond?: number;
  softnetTimeSqueeze?: number;
  softnetTimeSqueezePerSecond?: number;
  rxDropped?: number;
  rxDroppedPerSecond?: number;
  txDropped?: number;
  txDroppedPerSecond?: number;
  rxMissed?: number;
  rxMissedPerSecond?: number;
  qdiscDrops?: number;
  qdiscDropsPerSecond?: number;
};
type KernelTunable = { name: string; value: string };
type KernelNode = { node: string; window?: KernelWindow; findings?: KernelFinding[]; snapshot?: { tunables?: KernelTunable[] } };
type KernelResponse = { summary?: { nodes?: number; findings?: number; critical?: number; warnings?: number; warming?: number }; nodes?: KernelNode[] };

export type StageKey = 'nic-driver' | 'napi-softnet' | 'ip' | 'tcp-listen' | 'socket-receive' | 'socket-send' | 'qdisc' | 'conntrack' | 'tcp-memory' | 'tcp-quality';
export type StageColumn = 'ingress' | 'shared' | 'egress';
export type StageSeverity = 'critical' | 'warning' | 'ok' | 'warming';
export type Stage = { key: StageKey; title: string; column: StageColumn; row: number; layers: string[]; caption?: string };

// The `layers` lists below are the 12 raw Layer string literals emitted by
// internal/kerneldiag/analyze.go's `add(models.KernelNetworkFinding{Layer:
// "..."})` call sites — grepped directly, not guessed. If that file ever
// adds a 13th Layer literal, stageForLayer's test (parametrized over all 12)
// will start failing a coverage assumption and this table needs a new row.
//
// Ingress and egress are genuinely different paths through the kernel, so
// this is laid out as three columns (ingress / shared / egress) across 7
// rows, per docs/kernel-network-diagnostics.md's "Where congestion and
// drops occur" table — not a single misleadingly linear pipe.
// `ip` and `conntrack` are both "shared" (direction-agnostic), and the
// shared column is a single grid column — so they can't sit literally
// side-by-side without splitting that column. They get their own
// consecutive rows (3, 4) instead: giving both the same row/column, as an
// earlier revision of this table did, made them silently occupy the exact
// same CSS grid cell, so Conntrack painted over IP layer and hid it
// completely. Stacked-but-separate is correct; overlapping is a bug.
export const STAGES: Stage[] = [
  { key: 'nic-driver', title: 'NIC / driver ring', column: 'shared', row: 1, layers: ['nic-driver'] },
  { key: 'napi-softnet', title: 'NAPI / softirq backlog', column: 'ingress', row: 2, layers: ['softnet-backlog', 'softnet-budget'] },
  { key: 'ip', title: 'IP layer', column: 'shared', row: 3, layers: ['ip'] },
  { key: 'conntrack', title: 'Conntrack', column: 'shared', row: 4, layers: ['conntrack'] },
  { key: 'tcp-listen', title: 'TCP accept / SYN queue', column: 'ingress', row: 5, layers: ['tcp-listen'] },
  { key: 'socket-receive', title: 'Socket receive, TCP + UDP', column: 'ingress', row: 6, layers: ['tcp-receive', 'socket-receive'] },
  { key: 'socket-send', title: 'Socket send, UDP', column: 'egress', row: 6, layers: ['socket-send'] },
  { key: 'qdisc', title: 'Egress qdisc', column: 'egress', row: 7, layers: ['qdisc'], caption: 'Egress packets return through the same NIC/driver ring shown above.' },
  { key: 'tcp-memory', title: 'TCP memory pressure', column: 'shared', row: 8, layers: ['tcp-memory'] },
  // Retransmits/resets aren't cleanly ingress- or egress-only, same
  // reasoning as ip/conntrack/tcp-memory's shared placement above — row 9
  // is the first free row after the current max of 8, no collision.
  { key: 'tcp-quality', title: 'TCP connection quality', column: 'shared', row: 9, layers: ['tcp-connection-quality'] },
];

// Deliberately blank cells, rendered as muted dashed placeholders rather
// than silently omitted — this is what keeps the diagram honest about
// where the ingress/egress metaphor doesn't apply, instead of just
// prettifying a linear pipe that doesn't reflect the real packet path.
export const BLANK_CELLS: { column: StageColumn; row: number; caption: string }[] = [
  { column: 'egress', row: 2, caption: 'No egress NAPI/softirq backlog — that queue is RX-only.' },
  { column: 'egress', row: 5, caption: 'No egress SYN/accept queue — connection setup is inbound-only.' },
  { column: 'ingress', row: 7, caption: 'Ingress ends at the socket above — there is no separate ingress qdisc stage.' },
];

const SEVERITY_RANK: Record<StageSeverity, number> = { warming: 0, ok: 1, warning: 2, critical: 3 };

// One plain-English sentence each for "what this is" and "why it matters,"
// aimed at an operator who has never read a kernel networking doc — the
// technical stage titles and Layer vocabulary stay as-is (they're what an
// expert searches for), this is purely an on-demand explainer layered on
// top. Static content, no API call.
export const STAGE_GLOSSARY: Record<StageKey, { what: string; why: string }> = {
  'nic-driver': {
    what: 'The network card and its driver handing packets to the kernel.',
    why: "If packets are lost here, the OS never even saw them — nothing above this layer can recover them.",
  },
  'napi-softnet': {
    what: "The kernel's per-CPU queue that holds packets right after the NIC, before software gets to process them.",
    why: 'A full queue here usually means the CPU is too busy to keep up with incoming traffic.',
  },
  ip: {
    what: 'The IP routing and delivery layer.',
    why: 'Drops here often mean a routing problem, not a buffer size problem.',
  },
  conntrack: {
    what: 'The table that remembers each active connection so the firewall/NAT can track it.',
    why: 'If this table fills up, brand new connections can fail to establish.',
  },
  'tcp-listen': {
    what: 'The queue of incoming connection requests waiting for an application to accept() them.',
    why: 'If this overflows, clients see connection resets or timeouts before your app ever sees the request.',
  },
  'socket-receive': {
    what: 'Where data waits to be read by an application after arriving.',
    why: 'A slow application, or one reading too little too late, causes drops here — not necessarily a broken network.',
  },
  'socket-send': {
    what: 'Where an application queues data before the kernel sends it out (UDP).',
    why: 'This fills up when a sender outpaces what the network/NIC can drain.',
  },
  qdisc: {
    what: 'The traffic-shaping queue packets pass through just before leaving on the wire.',
    why: 'Drops here can be intentional (rate limiting/shaping) or a sign the outbound path is saturated.',
  },
  'tcp-memory': {
    what: "The kernel's memory budget for all TCP socket buffers on this node.",
    why: 'Running out here can abort connections regardless of any single buffer size.',
  },
  'tcp-quality': {
    what: 'How often TCP has to resend data or abandon a connection outright.',
    why: "This is usually a sign of real packet loss or an overloaded peer — there's no buffer setting that fixes it, so treat it as a signal to investigate, not a tuning knob.",
  },
};

// Friendly words shown alongside (never instead of) the technical severity
// badge — the badge stays for anyone who wants the precise term, this is
// for anyone who doesn't.
export const SEVERITY_GLOSS: Record<StageSeverity, string> = {
  critical: 'needs action now',
  warning: 'keep an eye on it',
  ok: 'healthy',
  warming: 'still measuring',
};

const layerToStage = new Map<string, StageKey>();
for (const s of STAGES) for (const l of s.layers) layerToStage.set(l, s.key);

export function stageForLayer(layer: string): StageKey | undefined {
  return layerToStage.get(layer);
}

// Empty input defaults to 'ok': stageSummaries only ever calls this with at
// least the per-node severities for every reporting node, so an empty list
// here means "no nodes reporting at all" — a fleet-visibility problem the
// rest of the dashboard (stale-agent counts) already covers, not something
// this diagram should render as 'warming' or invent a fifth state for.
export function worstSeverity(list: StageSeverity[]): StageSeverity {
  let worst: StageSeverity = 'ok';
  let worstRank = -1;
  for (const s of list) {
    if (SEVERITY_RANK[s] > worstRank) {
      worst = s;
      worstRank = SEVERITY_RANK[s];
    }
  }
  return worst;
}

// A warming node reports zero findings by construction (the controller
// zeroes counters while a node's rate window warms up) — that is NOT the
// same as "measured and healthy". Collapsing it into 'ok' would show a
// falsely clean grid right after every fleet-wide agent restart, including
// the one a fresh deploy causes. 'warming' ranks lowest in worstSeverity,
// so one real 'ok' node still wins over a warming one, but a stage where
// every contributing node is warming correctly shows 'warming', never a
// false-clean 'ok'.
export function nodeStageSeverity(node: KernelNode, stage: Stage): StageSeverity {
  const relevant = (node.findings || []).filter((f) => stage.layers.includes(f.layer));
  let worst: StageSeverity | null = null;
  for (const f of relevant) {
    const sev: StageSeverity = f.severity === 'critical' ? 'critical' : 'warning';
    if (!worst || SEVERITY_RANK[sev] > SEVERITY_RANK[worst]) worst = sev;
  }
  if (worst) return worst;
  if (!node.window || node.window.warming) return 'warming';
  return 'ok';
}

export type StageSummary = { severity: StageSeverity; perNode: { node: string; severity: StageSeverity; findings: KernelFinding[] }[] };

export function stageSummaries(nodes: KernelNode[]): Map<StageKey, StageSummary> {
  const out = new Map<StageKey, StageSummary>();
  for (const stage of STAGES) {
    const perNode = nodes.map((n) => ({
      node: n.node,
      severity: nodeStageSeverity(n, stage),
      findings: (n.findings || []).filter((f) => stage.layers.includes(f.layer)),
    }));
    out.set(stage.key, { severity: worstSeverity(perNode.map((p) => p.severity)), perNode });
  }
  return out;
}

function colIndex(c: StageColumn): number {
  return c === 'ingress' ? 1 : c === 'egress' ? 3 : 2;
}

// The exact counter names each analyzeNode() branch (internal/kerneldiag/
// analyze.go) sums as evidence for a given Layer, for the 5 stages driven
// by named /proc/net/snmp|netstat counters rather than a dedicated window
// field. Kept 1:1 with analyze.go's `counters["..."]` lookups so a stage's
// "live" number is always the same evidence a finding would cite — never a
// number invented for the sake of filling the card.
const STAGE_COUNTER_NAMES: Partial<Record<StageKey, string[]>> = {
  'socket-receive': ['TcpExt.TCPBacklogDrop', 'TcpExt.TCPRcvQDrop', 'TcpExt.TCPZeroWindowDrop', 'Udp.RcvbufErrors', 'Udp.MemErrors'],
  'socket-send': ['Udp.SndbufErrors'],
  'tcp-listen': ['TcpExt.ListenDrops', 'TcpExt.ListenOverflows', 'TcpExt.TCPReqQFullDrop', 'TcpExt.TCPDeferAcceptDrop'],
  'tcp-memory': ['TcpExt.TCPMemoryPressures', 'TcpExt.TCPAbortOnMemory', 'TcpExt.TCPWqueueTooBig'],
  ip: ['Ip.InDiscards', 'Ip.OutDiscards', 'IpExt.InNoRoutes', 'IpExt.OutNoRoutes'],
  'tcp-quality': ['Tcp.RetransSegs', 'Tcp.OutRsts', 'Tcp.EstabResets'],
};

export type StageRate = { perSecond: number; delta: number };

// The per-window rate computation for a single stage, extracted out of
// stageLiveRate so KernelNetworkSparkline's per-pair windows (a single
// node's trend over time, not an aggregate across nodes) can reuse the
// exact same evidence-counter logic instead of re-deriving it. `conntrack`
// has no window-based rate at all (it's a point-in-time table-utilization
// gauge, not a counter delta) and deliberately returns null rather than a
// fabricated 0 — the UI shows its ceiling from a tunable instead, see
// conntrackCeiling.
export function stageRateForWindow(w: KernelWindow, stage: StageKey): StageRate | null {
  if (stage === 'conntrack') return null;
  if (stage === 'nic-driver') {
    return {
      perSecond: (w.rxMissedPerSecond || 0) + (w.rxDroppedPerSecond || 0) + (w.txDroppedPerSecond || 0),
      delta: (w.rxMissed || 0) + (w.rxDropped || 0) + (w.txDropped || 0),
    };
  }
  if (stage === 'napi-softnet') {
    return {
      perSecond: (w.softnetDroppedPerSecond || 0) + (w.softnetTimeSqueezePerSecond || 0),
      delta: (w.softnetDropped || 0) + (w.softnetTimeSqueeze || 0),
    };
  }
  if (stage === 'qdisc') {
    return { perSecond: w.qdiscDropsPerSecond || 0, delta: w.qdiscDrops || 0 };
  }
  const names = STAGE_COUNTER_NAMES[stage];
  if (!names) return null;
  let perSecond = 0;
  let delta = 0;
  for (const c of w.counters || []) {
    if (names.includes(c.name)) {
      perSecond += c.perSecond || 0;
      delta += c.delta || 0;
    }
  }
  return { perSecond, delta };
}

// A live cluster-wide rate for a stage, aggregated only from nodes whose
// window has settled (warming nodes contribute no rate — same reasoning as
// nodeStageSeverity).
export function stageLiveRate(nodes: KernelNode[], stage: StageKey): StageRate | null {
  let perSecond = 0;
  let delta = 0;
  let any = false;
  for (const n of nodes) {
    const w = n.window;
    if (!w || w.warming) continue;
    const r = stageRateForWindow(w, stage);
    if (!r) return r; // conntrack/unknown stage: null for every node, so null overall
    any = true;
    perSecond += r.perSecond;
    delta += r.delta;
  }
  return any ? { perSecond, delta } : null;
}

export function formatStageRate(rate: StageRate | null): string | null {
  if (!rate) return null;
  const rounded = Math.round(rate.delta).toLocaleString();
  const perSecond = rate.perSecond >= 10 ? Math.round(rate.perSecond).toLocaleString() : rate.perSecond.toFixed(2);
  return `${rounded} in this window · ${perSecond}/s across cluster`;
}

// conntrack has no per-window rate (see stageLiveRate); instead surface the
// table ceiling straight from the same node snapshot already fetched, so
// the conntrack card still shows a real number instead of just a badge.
// analyzeNode() only emits a finding at >=75% utilization — this caption
// makes that threshold visible even while the table is comfortably under it.
export function conntrackCeiling(nodes: KernelNode[]): string | null {
  for (const n of nodes) {
    const t = (n.snapshot?.tunables || []).find((x) => x.name === 'net.netfilter.nf_conntrack_max');
    if (t && t.value) return t.value;
  }
  return null;
}

type Brief = { headline: string; severity: string; summary: string };

function ListenQueuesStrip() {
  const [rows, setRows] = useState<Array<{ node?: string; listen?: number; synRecv?: number; backlog?: number; address?: string }>>([]);
  const [err, setErr] = useState('');
  useEffect(() => {
    const load = () =>
      api<any>('/api/v1/listen-queues')
        .then((d) => {
          const list = d?.top || d?.queues || d?.items || d?.nodes || [];
          setRows(Array.isArray(list) ? list.slice(0, 12) : []);
          setErr('');
        })
        .catch((e) => setErr(String(e.message || e)));
    load();
    const t = setInterval(load, 15000);
    return () => clearInterval(t);
  }, []);
  return (
    <section className="card span3">
      <p className="eyebrow">LISTEN QUEUES</p>
      <h2 className="card-title">inet_diag backlog depth</h2>
      <p>Observe-only TCP listen queue snapshots. Never changes backlog tunables.</p>
      {err && <p className="warning">{err}</p>}
      {!err && rows.length === 0 && <p className="empty-state">No listen-queue samples yet.</p>}
      <div className="list">
        {rows.map((r, i) => (
          <div className="agent wide" key={i}>
            <b>{r.node || r.address || `queue ${i + 1}`}</b>
            <small>
              {[r.address, r.listen != null ? `listen ${r.listen}` : '', r.synRecv != null ? `synRecv ${r.synRecv}` : '', r.backlog != null ? `backlog ${r.backlog}` : '']
                .filter(Boolean)
                .join(' · ')}
            </small>
          </div>
        ))}
      </div>
    </section>
  );
}

function StackHistogramsStrip() {
  const [nodes, setNodes] = useState<any[]>([]);
  const [err, setErr] = useState('');
  useEffect(() => {
    const load = () =>
      api<any>('/api/v1/ebpf/stack-histograms')
        .then((d) => {
          setNodes(Array.isArray(d?.nodes) ? d.nodes.slice(0, 8) : []);
          setErr('');
        })
        .catch((e) => setErr(String(e.message || e)));
    load();
    const t = setInterval(load, 15000);
    return () => clearInterval(t);
  }, []);
  return (
    <section className="card span3">
      <p className="eyebrow">STACK HISTOGRAMS</p>
      <h2 className="card-title">Softirq / softnet / listen-depth buckets</h2>
      <p>Observe-only pressure buckets from agent reports — not entry→exit softirq latency.</p>
      {err && <p className="warning">{err}</p>}
      {!err && nodes.length === 0 && <p className="empty-state">No stack histogram samples yet.</p>}
      <div className="list">
        {nodes.map((n) => (
          <div className="agent wide" key={n.node}>
            <b>{n.node}</b>
            <small>
              {[
                n.softirqNetRx != null ? `NET_RX ${n.softirqNetRx}` : '',
                n.softnetDropped != null ? `softnet drop ${n.softnetDropped}` : '',
                n.softnetTimeSqueeze != null ? `squeeze ${n.softnetTimeSqueeze}` : '',
                n.listenOverflows != null ? `listen overflow ${n.listenOverflows}` : '',
              ]
                .filter(Boolean)
                .join(' · ')}
            </small>
          </div>
        ))}
      </div>
    </section>
  );
}

export default function CongestionMap() {
  const [kernel, setKernel] = useState<KernelResponse>();
  const [kernelWindow, setKernelWindow] = useState('5m');
  const [err, setErr] = useState('');
  const [selected, setSelected] = useState<StageKey | null>(null);
  const [brief, setBrief] = useState<Brief>();
  const [glossaryOpen, setGlossaryOpen] = useState<StageKey | null>(null);

  const load = () =>
    api<KernelResponse>(`/api/v1/ebpf/kernel-network?window=${encodeURIComponent(kernelWindow)}`)
      .then((k) => {
        setKernel(k);
        setErr('');
      })
      .catch((e) => setErr(String(e)));

  const loadBrief = () =>
    api<Brief>(`/api/v1/ai/congestion-brief?window=${encodeURIComponent(kernelWindow)}`)
      .then(setBrief)
      .catch(() => {
        // The brief is a plain-English convenience on top of the grid below,
        // which already shows the same data — a failed fetch here should
        // never block or blank the page, so it fails silently.
      });

  useEffect(() => {
    load();
    const t = setInterval(load, 5000);
    return () => clearInterval(t);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [kernelWindow]);

  useEffect(() => {
    loadBrief();
    const t = setInterval(loadBrief, 30000);
    return () => clearInterval(t);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [kernelWindow]);

  const nodes = useMemo(() => kernel?.nodes || [], [kernel]);
  const summaries = useMemo(() => stageSummaries(nodes), [nodes]);
  const ceiling = useMemo(() => conntrackCeiling(nodes), [nodes]);
  const selectedStage = selected ? STAGES.find((s) => s.key === selected) : undefined;
  const selectedSummary = selected ? summaries.get(selected) : undefined;

  // One representative node's trend, not a multi-node overlay — the worst-
  // severity node on the selected stage, matching what an operator would
  // actually want to check first.
  const worstNode = useMemo(() => {
    if (!selectedSummary) return undefined;
    let best: { node: string; severity: StageSeverity } | undefined;
    for (const p of selectedSummary.perNode) {
      if (!best || SEVERITY_RANK[p.severity] > SEVERITY_RANK[best.severity]) best = p;
    }
    return best?.node;
  }, [selectedSummary]);

  const [sparkline, setSparkline] = useState<KernelWindow[]>([]);
  useEffect(() => {
    if (!worstNode || !selectedStage) {
      setSparkline([]);
      return;
    }
    api<{ node: string; windows: KernelWindow[] }>(
      `/api/v1/ebpf/kernel-network/sparkline?node=${encodeURIComponent(worstNode)}&points=30`,
    )
      .then((r) => setSparkline(r.windows || []))
      .catch(() => setSparkline([]));
  }, [worstNode, selectedStage]);

  const sparklineValues = useMemo(() => {
    if (!selectedStage) return [];
    return sparkline
      .filter((w) => !w.warming)
      .map((w) => stageRateForWindow(w, selectedStage.key)?.perSecond ?? 0);
  }, [sparkline, selectedStage]);

  const ks = kernel?.summary || {};
  const hot = [...summaries.values()].filter((x: any) => x.severity === 'critical' || x.severity === 'warning').length;
  return (
    <div className="grid">
      <PagePulse
        headline={kernel ? ((ks.critical || 0) ? `${ks.critical} critical pressure point${ks.critical === 1 ? '' : 's'} in the stack.` : (ks.warnings || 0) ? `${ks.warnings} stack warning${ks.warnings === 1 ? '' : 's'}, nothing critical.` : 'No layer of the stack is under pressure.') : undefined}
        tone={kernel ? ((ks.critical || 0) ? 'bad' : (ks.warnings || 0) ? 'warn' : 'ok') : undefined}
        tick={kernel}
        error={err || undefined}
        figures={[
          { label: 'fresh nodes', value: kernel ? (ks.nodes || 0) : undefined },
          { label: 'critical', value: kernel ? (ks.critical || 0) : undefined, tone: kernel ? ((ks.critical || 0) ? 'bad' : 'ok') : undefined },
          { label: 'warnings', value: kernel ? (ks.warnings || 0) : undefined, tone: kernel ? countTone(ks.warnings || 0) : undefined },
          { label: 'stages under pressure', value: kernel ? hot : undefined, tone: kernel ? countTone(hot) : undefined },
          { label: 'warming nodes', value: kernel ? (ks.warming || 0) : undefined },
        ]}
      />
      {err && (
        <section className="card span3">
          <p className="warning">{err}</p>
        </section>
      )}
      {brief && (
        <section className="card span3">
          <p className="eyebrow">IN PLAIN ENGLISH</p>
          <h2 className="card-title">
            <span className={`severity-badge ${brief.severity === 'info' ? 'info' : brief.severity}`}>{brief.severity}</span>{' '}
            {brief.headline}
          </h2>
          <p>{brief.summary}</p>
        </section>
      )}
      <ListenQueuesStrip />
      <StackHistogramsStrip />
      <section className="card span3">
        <p className="eyebrow">CONGESTION MAP</p>
        <h2 className="card-title">Where the stack is under pressure</h2>
        <p>
          Every layer of the Linux network stack a packet can pass through, colored by the worst finding across the
          cluster right now. Ingress (receive) and egress (send) are genuinely different paths through the kernel —
          this diagram doesn't pretend otherwise. Click a stage for the per-node detail behind it.
        </p>
        <label>
          Diagnostic window
          <select value={kernelWindow} onChange={(e) => setKernelWindow(e.target.value)}>
            <option value="1m">1 minute</option>
            <option value="5m">5 minutes</option>
            <option value="15m">15 minutes</option>
            <option value="1h">1 hour</option>
          </select>
        </label>
        {!nodes.length && !err && <p className="empty-state">No kernel-network reports yet.</p>}
        {Boolean(nodes.length) && (
          <div className="congestion-grid">
            <span className="congestion-col-label" style={{ gridColumn: 1 }}>
              INGRESS
            </span>
            <span className="congestion-col-label" style={{ gridColumn: 3 }}>
              EGRESS
            </span>
            {STAGES.map((stage) => {
              const summary = summaries.get(stage.key);
              const sev = summary?.severity || 'ok';
              const rate = sev === 'warming' ? null : formatStageRate(stageLiveRate(nodes, stage.key));
              const glossary = STAGE_GLOSSARY[stage.key];
              return (
                <div
                  key={stage.key}
                  className={`stage-cell ${sev}${selected === stage.key ? ' selected' : ''}`}
                  style={{ gridColumn: colIndex(stage.column), gridRow: stage.row + 1 }}
                >
                  <button
                    type="button"
                    className="stage-glossary-trigger"
                    aria-label={`What is ${stage.title}?`}
                    onClick={(e) => {
                      e.stopPropagation();
                      setGlossaryOpen(glossaryOpen === stage.key ? null : stage.key);
                    }}
                  >
                    ?
                  </button>
                  <button
                    type="button"
                    className="stage-cell-body"
                    onClick={() => setSelected(selected === stage.key ? null : stage.key)}
                  >
                    <span className="stage-cell-title">{stage.title}</span>
                    {sev === 'warming' ? (
                      <span className="stage-cell-warming">warming</span>
                    ) : (
                      <span>
                        <span className={`severity-badge ${sev === 'ok' ? 'info' : sev}`}>{sev}</span>{' '}
                        <small className="stage-cell-gloss">{SEVERITY_GLOSS[sev]}</small>
                      </span>
                    )}
                    {rate && <small className="stage-cell-rate">{rate}</small>}
                    {stage.key === 'conntrack' && ceiling && (
                      <small className="stage-cell-rate">ceiling: {Number(ceiling).toLocaleString()} entries — findings fire above 75% utilization</small>
                    )}
                    {stage.caption && <small>{stage.caption}</small>}
                  </button>
                  {glossaryOpen === stage.key && glossary && (
                    <div className="explain-pop stage-glossary-pop">
                      <p>
                        <b>{stage.title}</b>
                      </p>
                      <p>{glossary.what}</p>
                      <p className="ask-netra-meta">{glossary.why}</p>
                      <button type="button" className="btn-secondary" onClick={() => setGlossaryOpen(null)}>
                        Close
                      </button>
                    </div>
                  )}
                </div>
              );
            })}
            {BLANK_CELLS.map((b) => (
              <div
                key={`${b.column}-${b.row}`}
                className="stage-cell blank"
                style={{ gridColumn: colIndex(b.column), gridRow: b.row + 1 }}
              >
                <small>{b.caption}</small>
              </div>
            ))}
          </div>
        )}
      </section>

      {selectedStage && selectedSummary && (
        <section className="card span3">
          <p className="eyebrow">STAGE DETAIL</p>
          <h2 className="card-title">{selectedStage.title}</h2>
          {sparklineValues.length >= 2 && worstNode && (
            <p className="sparkline-row">
              <Sparkline values={sparklineValues} />
              <small className="stage-cell-gloss">
                trend on {worstNode} (worst node for this stage), last {sparklineValues.length} intervals
              </small>
            </p>
          )}
          <div className="list">
            {selectedSummary.perNode.every((p) => p.findings.length === 0) && (
              <p className="empty-state">No current findings at this stage on any node.</p>
            )}
            {selectedSummary.perNode.map((p) =>
              p.findings.map((f, i) => (
                <div className="agent wide" key={`${p.node}-${f.signal}-${i}`}>
                  <b>{f.signal}</b>
                  <span className={`severity-badge ${f.severity}`}>{f.severity}</span>{' '}
                  <small className="stage-cell-gloss">
                    {SEVERITY_GLOSS[f.severity === 'critical' ? 'critical' : 'warning']}
                  </small>
                  <span>{p.node}</span>
                  <small>{(f.evidence || []).join(' · ')}</small>
                  <small>{f.explanation}</small>
                  <small>{f.recommendation}</small>
                  {f.tunable && (
                    <small>
                      {f.tunable}: {f.currentValue || 'unavailable'}
                      {f.suggestedValue ? ` → canary ${f.suggestedValue}` : ''}
                    </small>
                  )}
                  {f.applyCommand && <code>{f.applyCommand}</code>}
                  {f.rollbackCommand && <code>rollback: {f.rollbackCommand}</code>}
                  <small className="warning">Risk: {f.risk}</small>
                  <div className="toolbar">
                    <button className="btn-secondary" onClick={() => navigate('capture', { node: p.node })}>Capture on {p.node}</button>
                  </div>
                  <ExplainFinding
                    page="congestion"
                    kind={f.signal}
                    subject={`${p.node}/${f.layer}`}
                    message={`${f.explanation} ${f.recommendation}`}
                    severity={f.severity}
                  />
                </div>
              )),
            )}
          </div>
        </section>
      )}
    </div>
  );
}
