// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

import { useEffect, useMemo, useState } from 'react';
import { api } from '../api';
import { navigate } from '../hooks/useInvestigation';
import PagePulse from '../components/kit/PagePulse';
import { countTone } from '../components/kit/tone';

type FP = {
  ja3?: string;
  ja4?: string;
  sni?: string;
  ech?: boolean;
  node?: string;
  count?: number;
  firstSeen?: string;
  lastSeen?: string;
};
type Risk = {
  ja3?: string;
  ja4?: string;
  sni?: string;
  node?: string;
  count?: number;
  ech?: boolean;
  severity?: string;
  reasons?: string[];
};
type Board = { fingerprints?: FP[]; stats?: Record<string, number> };
type RiskBoard = { items?: Risk[]; count?: number; uniqueJa3?: number; echSightings?: number; rare?: number; note?: string };

export default function TlsFingerprints() {
  const [board, setBoard] = useState<Board>();
  const [risk, setRisk] = useState<RiskBoard>();
  const [err, setErr] = useState('');
  const [filter, setFilter] = useState('');
  const [tab, setTab] = useState<'risk' | 'all'>('risk');
  const [tick, setTick] = useState(0);

  useEffect(() => {
    const load = () => {
      Promise.all([
        api<Board>('/api/v1/ebpf/tls-fingerprints?limit=200'),
        api<RiskBoard>('/api/v1/ebpf/tls-fingerprints/risk?limit=200'),
      ])
        .then(([b, r]) => {
          setBoard(b);
          setRisk(r);
          setErr('');
          setTick(Date.now());
        })
        .catch((e) => setErr(String(e.message || e)));
    };
    load();
    const t = setInterval(load, 15000);
    return () => clearInterval(t);
  }, []);

  const q = filter.trim().toLowerCase();
  const riskRows = useMemo(
    () =>
      (risk?.items || []).filter(
        (r) =>
          !q ||
          (r.ja3 || '').toLowerCase().includes(q) ||
          (r.ja4 || '').toLowerCase().includes(q) ||
          (r.sni || '').toLowerCase().includes(q) ||
          (r.node || '').toLowerCase().includes(q) ||
          (r.reasons || []).some((x) => x.toLowerCase().includes(q))
      ),
    [risk, q]
  );
  const allRows = useMemo(
    () =>
      (board?.fingerprints || []).filter(
        (r) =>
          !q ||
          (r.ja3 || '').toLowerCase().includes(q) ||
          (r.ja4 || '').toLowerCase().includes(q) ||
          (r.sni || '').toLowerCase().includes(q) ||
          (r.node || '').toLowerCase().includes(q)
      ),
    [board, q]
  );

  const rare = risk?.rare || 0;
  const ech = risk?.echSightings || 0;

  return (
    <div className="grid">
      <PagePulse
        tick={tick || undefined}
        error={err || undefined}
        tone={rare || ech ? 'warn' : tick ? 'ok' : undefined}
        headline={tick ? `${risk?.uniqueJa3 || 0} unique JA3 · ${rare} rare · ${ech} ECH` : undefined}
        figures={[
          { label: 'unique JA3', value: risk?.uniqueJa3 || board?.stats?.uniqueJa3 },
          { label: 'rare', value: rare, tone: rare ? countTone(rare) : undefined },
          { label: 'ECH sightings', value: ech, tone: ech ? 'warn' : undefined },
          { label: 'observed', value: board?.fingerprints?.length },
        ]}
      />
      <section className="card span3">
        <p className="eyebrow">TLS / JA3</p>
        <h2 className="card-title">Client fingerprints — observe only</h2>
        <p>JA3/JA4 and SNI from the datapath. No decrypt. Risk ranks rare fingerprints and ECH sightings.</p>
        <div className="filters" style={{ display: 'flex', gap: '0.75rem', flexWrap: 'wrap', marginTop: '0.75rem' }}>
          <button type="button" className={tab === 'risk' ? 'active' : ''} onClick={() => setTab('risk')}>
            Risk ({riskRows.length})
          </button>
          <button type="button" className={tab === 'all' ? 'active' : ''} onClick={() => setTab('all')}>
            All ({allRows.length})
          </button>
          <input value={filter} onChange={(e) => setFilter(e.target.value)} placeholder="Filter JA3 / SNI / node…" aria-label="Filter fingerprints" />
          <button type="button" className="btn-secondary" onClick={() => navigate('detect')}>
            Detect
          </button>
          <button type="button" className="btn-secondary" onClick={() => navigate('security-review')}>
            Security Review
          </button>
          <button type="button" className="btn-secondary" onClick={() => navigate('surfaces')}>
            Surfaces
          </button>
        </div>
        {risk?.note && <p className="kit-caption">{risk.note}</p>}
      </section>

      {tab === 'risk' ? (
        <section className="card span3">
          <p className="eyebrow">JA3 RISK</p>
          <table className="metric-table">
            <thead>
              <tr>
                <th>Severity</th>
                <th>SNI</th>
                <th>JA3</th>
                <th>JA4</th>
                <th>Node</th>
                <th className="num">Count</th>
                <th>Reasons</th>
              </tr>
            </thead>
            <tbody>
              {riskRows.map((r, i) => (
                <tr key={`${r.ja3}-${r.node}-${i}`}>
                  <td>
                    <span className={`severity-badge ${r.severity || 'warning'}`}>{r.severity || 'info'}</span>
                    {r.ech ? <span className="kit-caption"> ECH</span> : null}
                  </td>
                  <td>{r.sni || '—'}</td>
                  <td>
                    <code title={r.ja3}>{r.ja3 ? `${r.ja3.slice(0, 16)}…` : '—'}</code>
                  </td>
                  <td>
                    <code title={r.ja4}>{r.ja4 ? `${r.ja4.slice(0, 18)}…` : '—'}</code>
                  </td>
                  <td>{r.node || '—'}</td>
                  <td className="num">{r.count || 0}</td>
                  <td>{(r.reasons || []).join('; ')}</td>
                </tr>
              ))}
            </tbody>
          </table>
          {riskRows.length === 0 && <p className="empty-state">No risk-ranked fingerprints match this filter.</p>}
        </section>
      ) : (
        <section className="card span3">
          <p className="eyebrow">ALL FINGERPRINTS</p>
          <table className="metric-table">
            <thead>
              <tr>
                <th>SNI</th>
                <th>JA3</th>
                <th>JA4</th>
                <th>Node</th>
                <th className="num">Count</th>
                <th>Last seen</th>
              </tr>
            </thead>
            <tbody>
              {allRows.map((r, i) => (
                <tr key={`${r.ja3}-${r.node}-${i}`}>
                  <td>
                    {r.sni || '—'}
                    {r.ech ? ' · ECH' : ''}
                  </td>
                  <td>
                    <code title={r.ja3}>{r.ja3 ? `${r.ja3.slice(0, 16)}…` : '—'}</code>
                  </td>
                  <td>
                    <code title={r.ja4}>{r.ja4 ? `${r.ja4.slice(0, 18)}…` : '—'}</code>
                  </td>
                  <td>{r.node || '—'}</td>
                  <td className="num">{r.count || 0}</td>
                  <td>{r.lastSeen ? new Date(r.lastSeen).toLocaleString() : '—'}</td>
                </tr>
              ))}
            </tbody>
          </table>
          {allRows.length === 0 && <p className="empty-state">No fingerprints observed yet.</p>}
        </section>
      )}
    </div>
  );
}
