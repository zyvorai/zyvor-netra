// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

import { useEffect, useState } from 'react';
import { api } from '../api';
import PagePulse from '../components/kit/PagePulse';
import {
  driftHeadline,
  driftQuery,
  edgeLabel,
  humanBytes,
  shiftHeadline,
  shiftQuery,
  type BaselineMode,
  type DriftReport,
  type ShiftReport,
} from '../lib/flowDrift';

export default function FlowDrift() {
  const [drift, setDrift] = useState<DriftReport>();
  const [shift, setShift] = useState<ShiftReport>();
  const [recent, setRecent] = useState('1h');
  const [baseline, setBaseline] = useState('144h');
  const [publicOnly, setPublicOnly] = useState(false);
  const [mode, setMode] = useState<BaselineMode>('average');
  const [err, setErr] = useState('');
  const [tick, setTick] = useState(0);

  useEffect(() => {
    const load = () => {
      const q = driftQuery(recent, baseline, publicOnly);
      const qs = shiftQuery(recent, baseline, mode);
      Promise.allSettled([
        api<DriftReport>(`/api/v1/insights/dependency-drift${q}`),
        api<ShiftReport>(`/api/v1/insights/volume-shift${qs}`),
      ]).then(([d, s]) => {
        if (d.status === 'fulfilled') setDrift(d.value);
        if (s.status === 'fulfilled') setShift(s.value);
        const failed = [d, s].filter((x) => x.status === 'rejected') as PromiseRejectedResult[];
        setErr(failed.map((x) => String(x.reason?.message || x.reason)).join('; '));
        setTick(Date.now());
      });
    };
    load();
    const t = setInterval(load, 30000);
    return () => clearInterval(t);
  }, [recent, baseline, publicOnly, mode]);

  const newEdges = drift?.newEdges || [];
  const gone = drift?.vanishedEdges || [];
  const shifts = shift?.shifts || [];
  const notReady = drift?.ready === false;

  return (
    <div className="grid">
      <PagePulse
        tick={tick || undefined}
        error={err || undefined}
        tone={drift ? (notReady ? 'warn' : drift.newPublicEgress ? 'warn' : 'ok') : undefined}
        headline={drift ? driftHeadline(drift) : undefined}
        figures={[
          { label: 'new dependencies', value: drift?.newTotal || 0, tone: drift?.newTotal ? 'warn' : undefined },
          { label: 'new public egress', value: drift?.newPublicEgress || 0, tone: drift?.newPublicEgress ? 'warn' : undefined },
          { label: 'gone quiet', value: drift?.vanishedTotal || 0 },
          { label: 'volume shifts', value: shift?.total || 0 },
        ]}
      />

      <section className="card span3">
        <p className="eyebrow">FLOW HISTORY COMPARISON</p>
        <h2 className="card-title">What is new compared with normal</h2>
        <p>
          Compares the recent window with the baseline before it, from the retained flow history. Absence from the history is a lead, not proof: it is bounded in age and rows,
          and a restarted pod shows as a new private peer. Read-only; nothing is blocked. Also available as <code>netractl insights dependency-drift</code> and the{' '}
          <code>netra_insights_dependency_drift</code> MCP tool.
        </p>
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.75rem', alignItems: 'center' }}>
          <label>
            Recent <input value={recent} onChange={(e) => setRecent(e.target.value)} style={{ width: '5rem' }} placeholder="1h" />
          </label>
          <label>
            Baseline <input value={baseline} onChange={(e) => setBaseline(e.target.value)} style={{ width: '5rem' }} placeholder="144h" />
          </label>
          <label>
            <input type="checkbox" checked={publicOnly} onChange={(e) => setPublicOnly(e.target.checked)} /> public peers only
          </label>
          <label>
            Volume baseline{' '}
            <select value={mode} onChange={(e) => setMode(e.target.value as BaselineMode)}>
              <option value="average">average</option>
              <option value="same-time">same time of day</option>
            </select>
          </label>
        </div>
        {notReady && <p className="warning">{driftHeadline(drift)}. Nothing is listed as new until the baseline is long enough.</p>}
        {(drift?.truncated || drift?.listsTruncated) && <p className="warning">The history or a list was cut to its bounds; counts may be low.</p>}
      </section>

      <section className="card span3">
        <p className="eyebrow">NEW DEPENDENCIES</p>
        <h2 className="card-title">Seen in the recent window, not in the baseline</h2>
        {!notReady && newEdges.length === 0 && <p className="empty-state">No new dependencies.</p>}
        <div className="list">
          {newEdges.map((e, i) => (
            <div className="agent wide" key={i}>
              <b>{edgeLabel(e)}</b>
              <span className={`severity-badge ${e.attention ? 'warning' : 'info'}`}>{e.attention ? 'new public egress' : e.peerClass}</span>
              <small>
                {humanBytes(e.bytes)} · {e.observations} observation{e.observations === 1 ? '' : 's'} · first {new Date(e.firstSeen).toLocaleString()}
              </small>
            </div>
          ))}
        </div>
      </section>

      <section className="card span3">
        <p className="eyebrow">GONE QUIET</p>
        <h2 className="card-title">Regular in the baseline, absent now</h2>
        {!notReady && gone.length === 0 && <p className="empty-state">Nothing regular went quiet.</p>}
        <div className="list">
          {gone.map((e, i) => (
            <div className="agent wide" key={i}>
              <b>{edgeLabel(e)}</b>
              <span className="severity-badge info">{e.peerClass}</span>
              <small>
                {e.observations} observations in the baseline · last {new Date(e.lastSeen).toLocaleString()}
              </small>
            </div>
          ))}
        </div>
      </section>

      <section className="card span3">
        <p className="eyebrow">VOLUME SHIFTS</p>
        <h2 className="card-title">{shift ? shiftHeadline(shift) : 'Byte rate against baseline'}</h2>
        {shift?.ready !== false && shifts.length === 0 && <p className="empty-state">No workload moved past the threshold.</p>}
        <div className="list">
          {shifts.map((s, i) => (
            <div className="agent wide" key={i}>
              <b>
                {s.namespace ? s.namespace + '/' : ''}
                {s.workload} ({s.direction})
              </b>
              <span className={`severity-badge ${s.kind === 'drop' ? 'info' : 'warning'}`}>
                {s.kind === 'unusual-time' ? 'unusual time' : `${s.kind} ${s.ratio}x`}
              </span>
              <small>
                {humanBytes(s.recentBytesPerHour)}/h now vs {humanBytes(s.baselineBytesPerHour)}/h before
              </small>
            </div>
          ))}
        </div>
        <p className="empty-state">
          {mode === 'same-time'
            ? 'Compared with the median of the same time on earlier days. There is no day-of-week model.'
            : 'The baseline is one average: a nightly or business-hours cycle can look like a shift. Try the same-time-of-day baseline.'}
        </p>
      </section>
    </div>
  );
}
