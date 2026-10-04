// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

import { useCallback, useEffect, useState } from 'react';
import { api, errorMessage } from '../api';
import { formatValue } from '../lib/metrics';

type Alert = {
  id: string;
  rule: string;
  node: string;
  context: string;
  chart: string;
  dimension?: string;
  status: string;
  value: number | null;
  units?: string;
  class?: string;
  info?: string;
  since: string;
  silenced?: boolean;
  acked?: boolean;
  ackedBy?: string;
};
type Transition = { time: string; id: string; rule: string; node: string; chart: string; from: string; to: string; value: number | null; units?: string; silenced?: boolean };
type Silence = { id: string; rule?: string; node?: string; chart?: string; until: string; comment?: string; createdBy?: string };
type Rule = { name: string; context: string; lookup: string; warn?: string; crit?: string; class?: string; info?: string; source: string };
type Snapshot = {
  active: Alert[];
  history: Transition[];
  rules: Rule[];
  silences: Silence[];
  stats: { rules: number; instances: number; warning: number; critical: number; evaluations: number };
};

export function since(iso: string, now = Date.now()): string {
  const s = Math.max(0, Math.round((now - new Date(iso).getTime()) / 1000));
  if (s < 60) return `${s}s`;
  if (s < 3600) return `${Math.round(s / 60)}m`;
  if (s < 86400) return `${(s / 3600).toFixed(1)}h`;
  return `${(s / 86400).toFixed(1)}d`;
}

export default function MetricAlerts() {
  const [snap, setSnap] = useState<Snapshot>();
  const [err, setErr] = useState('');
  const [note, setNote] = useState('');

  const load = useCallback(() => {
    api<Snapshot>('/api/v1/metrics/alerts?history=100')
      .then((d) => {
        setSnap(d);
        setErr('');
      })
      .catch((e) => setErr(String(e.message || e)));
  }, []);

  useEffect(() => {
    load();
    const t = setInterval(load, 5000);
    return () => clearInterval(t);
  }, [load]);

  const act = (p: Promise<unknown>, done: string) =>
    p
      .then(() => {
        setNote(done);
        load();
      })
      .catch((e) => setErr(String(e.message || e)));

  const ack = (a: Alert) => act(api(`/api/v1/metrics/alerts/${encodeURIComponent(a.id)}/ack`, { method: 'POST' }), `Acknowledged ${a.rule} on ${a.node}.`);
  const silence = (a: Alert) =>
    act(
      api('/api/v1/metrics/alerts/silences', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ rule: a.rule, node: a.node, chart: a.chart, duration: '2h', comment: 'silenced from the dashboard' }),
      }),
      `Silenced ${a.rule} on ${a.node} for 2 hours.`
    );
  const unsilence = (s: Silence) =>
    act(
      fetch(`/api/v1/metrics/alerts/silences/${encodeURIComponent(s.id)}`, { method: 'DELETE' }).then(async (r) => {
        if (!r.ok) throw new Error(errorMessage(await r.text()) || r.statusText);
      }),
      'Silence removed.'
    );

  const st = snap?.stats;
  return (
    <div className="grid">
      {err && (
        <section className="card span3">
          <p className="warning">{err}</p>
        </section>
      )}
      {note && <p className="kit-caption span3">{note}</p>}
      <section className="card span3">
        <p className="eyebrow">RAISED</p>
        <h2 className="card-title">
          {st ? `${st.critical} critical · ${st.warning} warning` : 'Loading…'}
          {st && <span className="kit-caption"> — {st.rules} rules over {st.instances} instances</span>}
        </h2>
        {snap && snap.active.length === 0 && <p className="empty-state">Nothing raised. Every evaluated instance is clear.</p>}
        {snap && snap.active.length > 0 && (
          <table className="metric-table">
            <thead>
              <tr>
                <th>Status</th>
                <th>Alert</th>
                <th>Node</th>
                <th>Chart</th>
                <th className="num">Value</th>
                <th>For</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {snap.active.map((a) => (
                <tr key={a.id}>
                  <td>
                    <span className={`metric-status ${a.status}`}>{a.status}</span>
                  </td>
                  <td>
                    <b>{a.rule}</b>
                    {a.info && <div className="kit-caption">{a.info}</div>}
                    {a.silenced && <div className="kit-caption">silenced</div>}
                    {a.acked && <div className="kit-caption">acknowledged{a.ackedBy ? ` by ${a.ackedBy}` : ''}</div>}
                  </td>
                  <td>{a.node}</td>
                  <td>
                    {a.chart}
                    {a.dimension ? ` / ${a.dimension}` : ''}
                  </td>
                  <td className="num">{formatValue(a.value, a.units)}</td>
                  <td>{since(a.since)}</td>
                  <td>
                    {!a.acked && (
                      <button type="button" className="btn-secondary" onClick={() => ack(a)}>
                        Ack
                      </button>
                    )}
                    {!a.silenced && (
                      <button type="button" className="btn-secondary" onClick={() => silence(a)}>
                        Silence 2h
                      </button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </section>
      {snap && snap.silences.length > 0 && (
        <section className="card span3">
          <p className="eyebrow">SILENCES</p>
          <table className="metric-table">
            <thead>
              <tr>
                <th>Rule</th>
                <th>Node</th>
                <th>Chart</th>
                <th>Until</th>
                <th>By</th>
                <th>Comment</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {snap.silences.map((s) => (
                <tr key={s.id}>
                  <td>{s.rule || '*'}</td>
                  <td>{s.node || '*'}</td>
                  <td>{s.chart || '*'}</td>
                  <td>{new Date(s.until).toLocaleString()}</td>
                  <td>{s.createdBy}</td>
                  <td>{s.comment}</td>
                  <td>
                    <button type="button" className="btn-secondary" onClick={() => unsilence(s)}>
                      Remove
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </section>
      )}
      <section className="card span3">
        <p className="eyebrow">HISTORY</p>
        <table className="metric-table">
          <thead>
            <tr>
              <th>When</th>
              <th>Alert</th>
              <th>Node</th>
              <th>Chart</th>
              <th>Change</th>
              <th className="num">Value</th>
            </tr>
          </thead>
          <tbody>
            {(snap?.history || []).map((h, i) => (
              <tr key={`${h.id}-${h.time}-${i}`}>
                <td>{new Date(h.time).toLocaleTimeString()}</td>
                <td>{h.rule}</td>
                <td>{h.node}</td>
                <td>{h.chart}</td>
                <td>
                  <span className={`metric-status ${h.from}`}>{h.from}</span> → <span className={`metric-status ${h.to}`}>{h.to}</span>
                  {h.silenced && <span className="kit-caption"> (silenced)</span>}
                </td>
                <td className="num">{formatValue(h.value, h.units)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </section>
      <section className="card span3">
        <details>
          <summary>
            {snap?.rules.length || 0} rules loaded (built-in pack plus NETRA_METRICALERT_DIR)
          </summary>
          <table className="metric-table">
            <thead>
              <tr>
                <th>Rule</th>
                <th>Context</th>
                <th>Lookup</th>
                <th>Warn</th>
                <th>Crit</th>
                <th>Source</th>
              </tr>
            </thead>
            <tbody>
              {(snap?.rules || []).map((r) => (
                <tr key={r.name} title={r.info}>
                  <td>{r.name}</td>
                  <td>{r.context}</td>
                  <td>{r.lookup}</td>
                  <td>
                    <code>{r.warn}</code>
                  </td>
                  <td>
                    <code>{r.crit}</code>
                  </td>
                  <td>{r.source}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </details>
      </section>
    </div>
  );
}
