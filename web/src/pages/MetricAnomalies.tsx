// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

import { useEffect, useMemo, useState } from 'react';
import { api } from '../api';
import MetricChart from '../components/MetricChart';
import { useMetricStream } from '../hooks/useMetricStream';
import { formatValue, streamId, windows, type MetricResult } from '../lib/metrics';

type Ranked = { node: string; context: string; chart: string; dimension: string; units?: string; anomalyRate: number; score: number };
type NodeRate = { node: string; anomalyRate: number; dimensions: number; anomalousDimensions: number; timeline?: { t: number; rate: number | null }[] };
type Summary = { after: number; before: number; nodes: NodeRate[] | null; ranked: Ranked[] | null; correlated?: Ranked[] | null; highlightAfter?: number; highlightBefore?: number };

/** The per-node anomaly timeline as a chart result, one line per node. */
export function timelineResult(s: Summary): MetricResult | undefined {
  const nodes = s.nodes || [];
  const ts = nodes[0]?.timeline?.map((p) => p.t) || [];
  if (!ts.length) return undefined;
  return {
    context: 'anomaly.rate',
    title: 'Node anomaly rate',
    units: '%',
    tier: 0,
    interval: ts.length > 1 ? ts[1] - ts[0] : 1,
    after: s.after,
    before: s.before,
    timestamps: ts,
    dimensions: nodes.map((n) => ({ name: n.node, values: (n.timeline || []).map((p) => p.rate), anomalyRate: (n.timeline || []).map(() => null), series: n.dimensions })),
    matched: nodes.length,
  };
}

export default function MetricAnomalies() {
  const [win, setWin] = useState(3600);
  const [data, setData] = useState<Summary>();
  const [hl, setHl] = useState<[number, number] | undefined>();
  const [pick, setPick] = useState<Ranked | undefined>();
  const [err, setErr] = useState('');

  useEffect(() => {
    const load = () => {
      const p = new URLSearchParams({ after: String(-win), top: '50' });
      if (hl) {
        p.set('highlight_after', String(hl[0]));
        p.set('highlight_before', String(hl[1]));
      }
      api<Summary>(`/api/v1/metrics/anomalies?${p}`)
        .then((d) => {
          setData(d);
          setErr('');
        })
        .catch((e) => setErr(String(e.message || e)));
    };
    load();
    const t = setInterval(load, hl ? 60000 : 10000);
    return () => clearInterval(t);
  }, [win, hl]);

  const timeline = useMemo(() => (data ? timelineResult(data) : undefined), [data]);
  const rows = hl ? data?.correlated || [] : data?.ranked || [];
  const pickQuery = useMemo(
    () => (pick ? [{ id: streamId(pick.context, pick.node, pick.chart), context: pick.context, charts: [pick.chart], nodes: [pick.node], window: win, points: 300 }] : []),
    [pick, win]
  );
  const { results } = useMetricStream(pickQuery);

  return (
    <div className="grid">
      {err && (
        <section className="card span3">
          <p className="warning">{err}</p>
        </section>
      )}
      <div className="span3 metrics-toolbar">
        <div className="metrics-seg" role="group" aria-label="Time window">
          {windows.slice(1, 6).map((w) => (
            <button
              type="button"
              key={w.label}
              className={win === w.seconds ? 'active' : ''}
              onClick={() => {
                setWin(w.seconds);
                setHl(undefined);
              }}
            >
              {w.label}
            </button>
          ))}
        </div>
        {hl ? (
          <button type="button" className="btn-secondary" onClick={() => setHl(undefined)}>
            Clear highlight
          </button>
        ) : (
          <span className="kit-caption">Drag across the timeline to ask “what changed here?”</span>
        )}
      </div>
      <section className="card span3">
        <MetricChart result={timeline} title="Anomaly rate per node" subtitle="share of samples flagged by the per-dimension models" height={180} onHighlight={(a, b) => setHl([a, b])} highlight={hl} />
      </section>
      <section className="card span3">
        <p className="eyebrow">NODES</p>
        <table className="metric-table">
          <thead>
            <tr>
              <th>Node</th>
              <th>Anomaly rate</th>
              <th className="num">Anomalous / scored dimensions</th>
            </tr>
          </thead>
          <tbody>
            {(data?.nodes || []).map((n) => (
              <tr key={n.node}>
                <td>{n.node}</td>
                <td>
                  <div className="metric-bar" title={formatValue(n.anomalyRate, '%')}>
                    <span style={{ width: `${Math.min(100, n.anomalyRate * 5)}%` }} />
                  </div>
                  {formatValue(n.anomalyRate, '%')}
                </td>
                <td className="num">
                  {n.anomalousDimensions} / {n.dimensions}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        {data && !(data.nodes || []).length && <p className="empty-state">No scored metrics in this window yet.</p>}
      </section>
      <section className="card span3">
        <p className="eyebrow">{hl ? 'WHAT CHANGED IN THE HIGHLIGHT' : 'MOST ANOMALOUS'}</p>
        <h2 className="card-title">{hl ? 'Ranked by distribution shift versus the preceding baseline (Kolmogorov–Smirnov)' : 'Dimensions ranked by anomaly rate'}</h2>
        <table className="metric-table">
          <thead>
            <tr>
              <th>#</th>
              <th>Node</th>
              <th>Chart</th>
              <th>Dimension</th>
              <th className="num">Anomaly rate</th>
              <th className="num">Score</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((r, i) => (
              <tr key={`${r.node}|${r.chart}|${r.dimension}`} className="clickable" onClick={() => setPick(r)}>
                <td>{i + 1}</td>
                <td>{r.node}</td>
                <td>{r.chart}</td>
                <td>{r.dimension}</td>
                <td className="num">{formatValue(r.anomalyRate, '%')}</td>
                <td className="num">{r.score.toFixed(2)}</td>
              </tr>
            ))}
          </tbody>
        </table>
        {data && rows.length === 0 && <p className="empty-state">{hl ? 'Nothing changed noticeably in that window.' : 'No anomalous dimensions in this window.'}</p>}
      </section>
      {pick && (
        <section className="card span3">
          <MetricChart result={results[pickQuery[0].id]} title={pick.chart} subtitle={`${pick.node} · ${pick.context}`} highlight={hl} />
        </section>
      )}
    </div>
  );
}
