// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

import { useEffect, useMemo, useState } from 'react';
import { api } from '../api';
import MetricChart from '../components/MetricChart';
import MetricEvidence, { type EvidenceTarget } from '../components/MetricEvidence';
import { useMetricStream } from '../hooks/useMetricStream';
import { familyOf, groupContexts, streamId, windows, type ContextInfo, type StreamQuery } from '../lib/metrics';

type NodeInfo = { node: string; lastIngest: string; stats?: { series?: number } };

/** Charts drawn per instance before a context collapses into one chart. */
const MAX_INSTANCES = 6;
const MAX_CHARTS = 40;

export type ChartSpec = { q: StreamQuery; title: string; subtitle: string; labels?: Record<string, string> };

export function chartsFor(contexts: ContextInfo[], node: string, split: string, window: number): ChartSpec[] {
  const points = window <= 900 ? Math.min(window, 300) : 360;
  const out: ChartSpec[] = [];
  for (const c of contexts) {
    const charts = c.charts.filter((ch) => !node || ch.node === node);
    const ids = [...new Set(charts.map((ch) => ch.chart))];
    const nodes = node ? [node] : undefined;
    if (node && ids.length > 1 && ids.length <= MAX_INSTANCES) {
      for (const id of ids) {
        const inst = charts.find((ch) => ch.chart === id);
        const lbl = inst?.labels ? Object.entries(inst.labels).map(([k, v]) => `${k}=${v}`).join(' ') : '';
        out.push({ q: { id: streamId(c.context, node, id), context: c.context, charts: [id], nodes, window, points }, title: c.title || c.context, subtitle: lbl || id, labels: inst?.labels });
      }
      continue;
    }
    const groupBy = ids.length > MAX_INSTANCES ? 'chart' : split;
    out.push({
      q: { id: streamId(c.context, node, groupBy), context: c.context, nodes, window, points, groupBy },
      title: c.title || c.context,
      subtitle: `${c.context}${ids.length > 1 ? ` · ${ids.length} instances` : ''}${groupBy !== 'dimension' ? ` · by ${groupBy}` : ''}`,
    });
  }
  return out.slice(0, MAX_CHARTS);
}

export default function Metrics() {
  const [nodes, setNodes] = useState<NodeInfo[]>([]);
  const [contexts, setContexts] = useState<ContextInfo[]>([]);
  const [node, setNode] = useState('');
  const [family, setFamily] = useState('');
  const [win, setWin] = useState(300);
  const [split, setSplit] = useState('dimension');
  const [filter, setFilter] = useState('');
  const [err, setErr] = useState('');
  const [evidence, setEvidence] = useState<{ id: string; target: EvidenceTarget } | null>(null);

  useEffect(() => {
    const load = () => {
      api<{ nodes: NodeInfo[] }>('/api/v1/metrics/nodes')
        .then((d) => setNodes(d.nodes || []))
        .catch((e) => setErr(String(e.message || e)));
      api<{ contexts: ContextInfo[] }>('/api/v1/metrics/contexts')
        .then((d) => {
          setContexts(d.contexts || []);
          setErr('');
        })
        .catch((e) => setErr(String(e.message || e)));
    };
    load();
    const t = setInterval(load, 30000);
    return () => clearInterval(t);
  }, []);

  const visible = useMemo(() => {
    const f = filter.trim().toLowerCase();
    return contexts.filter((c) => (!node || c.charts.some((ch) => ch.node === node)) && (!f || c.context.toLowerCase().includes(f) || (c.title || '').toLowerCase().includes(f)));
  }, [contexts, node, filter]);
  const groups = useMemo(() => groupContexts(visible), [visible]);
  const fam = family && visible.some((c) => familyOf(c) === family) ? family : groups[0]?.families[0]?.family || '';
  const famContexts = useMemo(() => visible.filter((c) => familyOf(c) === fam), [visible, fam]);
  const charts = useMemo(() => chartsFor(famContexts, node, node ? 'dimension' : split, win), [famContexts, node, split, win]);
  const queries = useMemo(() => charts.map((c) => c.q), [charts]);
  const { results, live, error } = useMetricStream(queries);

  return (
    <div className="grid">
      {(err || error) && (
        <section className="card span3">
          <p className="warning">{err || error}</p>
        </section>
      )}
      <div className="span3">
        <div className="metrics-toolbar">
          <select value={node} onChange={(e) => setNode(e.target.value)} aria-label="Node">
            <option value="">All nodes ({nodes.length})</option>
            {nodes.map((n) => (
              <option key={n.node} value={n.node}>
                {n.node}
              </option>
            ))}
          </select>
          <div className="metrics-seg" role="group" aria-label="Time window">
            {windows.map((w) => (
              <button type="button" key={w.label} className={win === w.seconds ? 'active' : ''} onClick={() => setWin(w.seconds)}>
                {w.label}
              </button>
            ))}
          </div>
          {!node && (
            <div className="metrics-seg" role="group" aria-label="Split fleet charts by">
              {['dimension', 'node'].map((s) => (
                <button type="button" key={s} className={split === s ? 'active' : ''} onClick={() => setSplit(s)}>
                  by {s}
                </button>
              ))}
            </div>
          )}
          <input placeholder="Filter metrics…" value={filter} onChange={(e) => setFilter(e.target.value)} aria-label="Filter metrics" />
          <span className={`metrics-live${live ? ' on' : ''}`}>{live ? 'live · 1s' : win > 3600 ? 'polling' : 'connecting…'}</span>
        </div>
        {contexts.length === 0 && !err && <p className="empty-state">No metrics yet. Agents stream per-second metrics once NETRA_METRICS_ENABLED is on (the default).</p>}
        {contexts.length > 0 && (
          <div className="metrics-layout">
            <nav className="card metrics-side" aria-label="Metric families">
              {groups.map((g) => (
                <div key={g.section}>
                  <h3>{g.section}</h3>
                  {g.families.map((f) => (
                    <button type="button" key={f.family} className={f.family === fam ? 'active' : ''} onClick={() => setFamily(f.family)}>
                      {f.family}
                      <small>{f.contexts.length}</small>
                    </button>
                  ))}
                </div>
              ))}
            </nav>
            <div className="metrics-charts">
              {charts.map((c) => (
                <section className="card" key={c.q.id}>
                  <MetricChart
                    result={results[c.q.id]}
                    title={c.title}
                    subtitle={c.subtitle}
                    highlight={evidence?.id === c.q.id ? [evidence.target.after, evidence.target.before] : undefined}
                    onHighlight={(after, before) => setEvidence({ id: c.q.id, target: { context: c.q.context, node: node || undefined, labels: c.labels, after, before } })}
                  />
                  {evidence?.id === c.q.id ? (
                    <MetricEvidence target={evidence.target} onClose={() => setEvidence(null)} />
                  ) : (
                    <div className="metric-chart-actions">
                      <button
                        type="button"
                        title="Flows, drops, captures and co-anomalies for this window (drag on the chart to pick a range)"
                        onClick={() => {
                          const now = Math.floor(Date.now() / 1000);
                          setEvidence({ id: c.q.id, target: { context: c.q.context, node: node || undefined, labels: c.labels, after: now - win, before: now } });
                        }}
                      >
                        Evidence
                      </button>
                    </div>
                  )}
                </section>
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
