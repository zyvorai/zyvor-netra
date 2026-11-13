// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

import { useCallback, useEffect, useState } from 'react';
import { api } from '../api';
import { navigate, useRoute } from '../hooks/useInvestigation';

type HistoryRec = {
  observedAt?: string;
  namespace?: string;
  pod?: string;
  peer?: string;
  port?: number;
  appProtocol?: string;
  protocol?: string;
  comm?: string;
  pid?: number;
  packets?: number;
  blocked?: number;
  bytes?: number;
};
type History = { records?: HistoryRec[]; limitations?: string[] };
type RED = {
  window?: string;
  rows?: Array<{
    namespace?: string;
    pod?: string;
    ratePerSec?: number;
    errors?: number;
    avgSrttUs?: number;
    http5xx?: number;
    appProtocols?: string[];
  }>;
  limitations?: string[];
};
type Traces = { spans?: Array<{ name?: string; parentId?: string; calleePod?: string; comm?: string; inferred?: boolean }>; limitations?: string[] };
type Profiles = { profiles?: Array<{ name?: string; samples?: number; note?: string }>; limitations?: string[] };
type KernelNotes = { notes?: Array<{ kind?: string; message?: string; node?: string }>; limitations?: string[] };
type WorkloadEvents = { events?: Array<{ observedAt?: string; kind?: string; message?: string; namespace?: string; pod?: string }>; limitations?: string[] };

export default function FlowObservePage() {
  const route = useRoute();
  const [since, setSince] = useState('1h');
  const [limit, setLimit] = useState(50);
  const [namespace, setNamespace] = useState(route.scope.namespace || '');
  const [pod, setPod] = useState(route.scope.pod || '');
  const [peer, setPeer] = useState(route.scope.query || '');
  const [history, setHistory] = useState<History>();
  const [red, setRed] = useState<RED>();
  const [traces, setTraces] = useState<Traces>();
  const [profiles, setProfiles] = useState<Profiles>();
  const [kernel, setKernel] = useState<KernelNotes>();
  const [events, setEvents] = useState<WorkloadEvents>();
  const [err, setErr] = useState('');
  const [tick, setTick] = useState(0);

  const load = useCallback(() => {
    const hq = new URLSearchParams({ since, limit: String(limit) });
    if (namespace) hq.set('namespace', namespace);
    if (pod) hq.set('pod', pod);
    if (peer) hq.set('peer', peer);
    const weq = new URLSearchParams();
    if (namespace) weq.set('namespace', namespace);
    if (pod) weq.set('pod', pod);
    Promise.all([
      api<History>(`/api/v1/flows/history?${hq}`),
      api<RED>('/api/v1/insights/red?window=5m'),
      api<Traces>('/api/v1/insights/traces?since=15m'),
      api<Profiles>('/api/v1/insights/profiles').catch(() => ({ profiles: [] })),
      api<KernelNotes>('/api/v1/insights/kernel-notes').catch(() => ({ notes: [] })),
      api<WorkloadEvents>(`/api/v1/insights/workload-events${weq.toString() ? `?${weq}` : ''}`).catch(() => ({ events: [] })),
    ])
      .then(([h, r, t, p, k, w]) => {
        setHistory(h);
        setRed(r);
        setTraces(t);
        setProfiles(p);
        setKernel(k);
        setEvents(w);
        setErr('');
        setTick((n) => n + 1);
      })
      .catch((e) => setErr(String(e.message || e)));
  }, [since, limit, namespace, pod, peer]);

  useEffect(() => {
    load();
    const t = setInterval(load, 10000);
    return () => clearInterval(t);
  }, [load]);

  const limits = [...(history?.limitations || []), ...(red?.limitations || []), ...(traces?.limitations || [])];

  return (
    <div className="grid">
      <section className="card span3">
        <p className="eyebrow">FILTERS</p>
        <h2 className="card-title">Native flow observe{tick ? ` · refreshed` : ''}</h2>
        <div className="filters" style={{ display: 'flex', gap: '0.75rem', flexWrap: 'wrap' }}>
          <label>
            Since
            <select value={since} onChange={(e) => setSince(e.target.value)}>
              {['15m', '1h', '6h', '24h'].map((s) => (
                <option key={s} value={s}>
                  {s}
                </option>
              ))}
            </select>
          </label>
          <label>
            Limit
            <select value={limit} onChange={(e) => setLimit(Number(e.target.value))}>
              {[20, 50, 100, 200].map((n) => (
                <option key={n} value={n}>
                  {n}
                </option>
              ))}
            </select>
          </label>
          <label>
            Namespace
            <input value={namespace} onChange={(e) => setNamespace(e.target.value)} />
          </label>
          <label>
            Pod
            <input value={pod} onChange={(e) => setPod(e.target.value)} />
          </label>
          <label>
            Peer
            <input value={peer} onChange={(e) => setPeer(e.target.value)} />
          </label>
          <button type="button" onClick={load}>
            Refresh
          </button>
          <button type="button" className="btn-secondary" onClick={() => navigate('flows')}>
            Hubble stream
          </button>
        </div>
        {err && <p className="warning">{err}</p>}
      </section>

      <section className="card span3">
        <p className="eyebrow">FLOW HISTORY</p>
        <h2 className="card-title">{(history?.records || []).length} records</h2>
        {(history?.records || []).length === 0 && <p className="empty-state">No flow history for this filter. First samples are baselines and are not shown.</p>}
        <table className="metric-table">
          <thead>
            <tr>
              <th>When</th>
              <th>Workload</th>
              <th>Peer</th>
              <th>Proto</th>
              <th>Process</th>
              <th className="num">Packets</th>
              <th className="num">Blocked</th>
              <th />
            </tr>
          </thead>
          <tbody>
            {(history?.records || []).map((rec, i) => (
              <tr key={`${rec.observedAt}-${i}`}>
                <td>{rec.observedAt ? new Date(rec.observedAt).toLocaleTimeString() : '—'}</td>
                <td>
                  {rec.namespace ? `${rec.namespace}/` : ''}
                  {rec.pod || 'unattributed'}
                </td>
                <td>
                  {rec.peer}:{rec.port}
                </td>
                <td>{rec.appProtocol || rec.protocol || '—'}</td>
                <td>
                  {rec.comm || '—'}
                  {rec.pid ? ` · ${rec.pid}` : ''}
                </td>
                <td className="num">{rec.packets || 0}</td>
                <td className="num">{rec.blocked || 0}</td>
                <td>
                  <button
                    type="button"
                    className="btn-secondary"
                    onClick={() =>
                      navigate('investigate', {
                        namespace: rec.namespace || '',
                        pod: rec.pod || '',
                        query: rec.peer || '',
                      })
                    }
                  >
                    Investigate
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </section>

      <section className="card span3">
        <p className="eyebrow">RED · {red?.window || '5m'}</p>
        <h2 className="card-title">Workload rate, errors, latency</h2>
        <table className="metric-table">
          <thead>
            <tr>
              <th>Workload</th>
              <th>Apps</th>
              <th className="num">Rate/s</th>
              <th className="num">Errors</th>
              <th className="num">HTTP 5xx</th>
              <th className="num">Avg SRTT µs</th>
            </tr>
          </thead>
          <tbody>
            {(red?.rows || []).slice(0, 40).map((row, i) => (
              <tr key={i}>
                <td>
                  {row.namespace ? `${row.namespace}/` : ''}
                  {row.pod || 'unattributed'}
                </td>
                <td>{(row.appProtocols || []).join(', ') || '—'}</td>
                <td className="num">{(row.ratePerSec || 0).toFixed(2)}</td>
                <td className="num">{row.errors || 0}</td>
                <td className="num">{row.http5xx || 0}</td>
                <td className="num">{row.avgSrttUs || 0}</td>
              </tr>
            ))}
          </tbody>
        </table>
        {(red?.rows || []).length === 0 && <p className="empty-state">No workload rate in this window.</p>}
      </section>

      <section className="card span3">
        <p className="eyebrow">INFERRED PATHS</p>
        <h2 className="card-title">Guessed parent/child hops (labeled)</h2>
        <div className="list">
          {(traces?.spans || []).length === 0 && <p className="empty-state">No linked hops in the last 15 minutes.</p>}
          {(traces?.spans || []).slice(0, 40).map((sp, i) => (
            <div className="agent wide" key={i}>
              <b>{sp.name}</b>
              <span>{sp.calleePod ? `→ ${sp.calleePod}` : ''}</span>
              <small>
                {sp.parentId ? 'child · ' : ''}
                {sp.comm || ''}
                {sp.inferred ? ' · inferred' : ''}
              </small>
            </div>
          ))}
        </div>
      </section>

      <section className="card span3">
        <p className="eyebrow">PROFILES · KERNEL NOTES · WORKLOAD EVENTS</p>
        <h2 className="card-title">Extra observe boards</h2>
        <div className="list">
          {(profiles?.profiles || []).slice(0, 8).map((p, i) => (
            <div className="agent wide" key={`p-${i}`}>
              <b>{p.name || 'profile'}</b>
              <span>{p.samples ?? 0} samples</span>
              <small>{p.note || ''}</small>
            </div>
          ))}
          {(kernel?.notes || []).slice(0, 8).map((n, i) => (
            <div className="agent wide" key={`k-${i}`}>
              <b>{n.kind || 'kernel'}</b>
              <span className="truncate">{n.message}</span>
              <small>{n.node || ''}</small>
            </div>
          ))}
          {(events?.events || []).slice(0, 12).map((ev, i) => (
            <div className="agent wide" key={`e-${i}`}>
              <b>{ev.kind || 'event'}</b>
              <span className="truncate">
                {[ev.namespace, ev.pod].filter(Boolean).join('/') || '—'} · {ev.message}
              </span>
              <small>{ev.observedAt ? new Date(ev.observedAt).toLocaleString() : ''}</small>
            </div>
          ))}
          {(profiles?.profiles || []).length + (kernel?.notes || []).length + (events?.events || []).length === 0 && (
            <p className="empty-state">No profiles, kernel notes, or workload events in scope.</p>
          )}
        </div>
        {limits[0] && <p className="kit-caption">{limits[0]}</p>}
      </section>
    </div>
  );
}
