// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

import { useEffect, useState } from 'react';
import { api } from '../api';
import PagePulse from '../components/kit/PagePulse';
import { classTone, headline, splitEntries, type ChangeEntry, type ChangesResult } from '../lib/changes';

const when = (e: ChangeEntry) => (e.at ? new Date(e.at).toLocaleTimeString() : '—');

export default function WhatChanged() {
  const [data, setData] = useState<ChangesResult>();
  const [since, setSince] = useState('1h');
  const [lead, setLead] = useState('10m');
  const [node, setNode] = useState('');
  const [err, setErr] = useState('');
  const [tick, setTick] = useState(0);

  useEffect(() => {
    const load = () => {
      const q = new URLSearchParams({ since, lead });
      if (node.trim()) q.set('node', node.trim());
      api<ChangesResult>(`/api/v1/incidents/changes?${q}`)
        .then((d) => {
          setData(d);
          setErr('');
          setTick(Date.now());
        })
        .catch((e) => setErr(String(e.message || e)));
    };
    load();
    const t = setInterval(load, 15000);
    return () => clearInterval(t);
  }, [since, lead, node]);

  const { timed, state } = splitEntries(data?.entries);
  const suspects = data?.suspects || [];
  const gaps = data?.gaps || [];

  return (
    <div className="grid">
      <PagePulse
        tick={tick || undefined}
        error={err || undefined}
        tone={data ? (suspects.length ? 'warn' : 'ok') : undefined}
        headline={data ? headline(data) : undefined}
        figures={[
          { label: 'changes', value: data?.counts?.change || 0 },
          { label: 'breaks', value: data?.counts?.break || 0, tone: data?.counts?.break ? 'warn' : undefined },
          { label: 'gaps', value: gaps.length, tone: gaps.length ? 'warn' : undefined },
        ]}
      />

      <section className="card span3">
        <p className="eyebrow">WHAT CHANGED</p>
        <h2 className="card-title">What changed, then what broke</h2>
        <p>
          Audit actions, netlink changes, BPF attachment findings, drops, metric anomaly bursts and alert transitions in
          one order. A suspect is a change that came first, not a proven cause. Read-only.
        </p>
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.75rem', marginTop: '0.75rem' }}>
          <label>
            Since <input value={since} onChange={(e) => setSince(e.target.value)} size={6} />
          </label>
          <label>
            Lead <input value={lead} onChange={(e) => setLead(e.target.value)} size={6} />
          </label>
          <label>
            Node <input value={node} onChange={(e) => setNode(e.target.value)} placeholder="optional" />
          </label>
        </div>
        {err && <p className="warning">{err}</p>}
        {data?.caveat && <p className="empty-state">{data.caveat}</p>}
      </section>

      {gaps.length > 0 && (
        <section className="card span3">
          <p className="eyebrow">GAPS</p>
          <h2 className="card-title">What this timeline cannot see</h2>
          <ul>
            {gaps.map((g, i) => (
              <li key={i}>{g}</li>
            ))}
          </ul>
        </section>
      )}

      <section className="card span3">
        <p className="eyebrow">SUSPECTS</p>
        <h2 className="card-title">Breaks and the changes just before them</h2>
        {suspects.length === 0 && <p className="empty-state">No break had a recorded change inside the lead window.</p>}
        <div className="list">
          {suspects.map((s, i) => (
            <div className="agent wide" key={i}>
              <b>{s.break.summary}</b>
              <span className={`severity-badge ${classTone(s.break)}`}>{s.break.source}</span>
              <small>
                {when(s.break)} · {s.sameNode ? 'same node' : 'cluster-wide or other node'}
              </small>
              <ul>
                {s.changes.map((c, j) => (
                  <li key={j}>
                    {when(c)} {c.source}: {c.summary}
                  </li>
                ))}
              </ul>
            </div>
          ))}
        </div>
      </section>

      <section className="card span3">
        <p className="eyebrow">TIMELINE</p>
        <h2 className="card-title">In order</h2>
        {timed.length === 0 && !err && <p className="empty-state">Nothing recorded in this window.</p>}
        <div className="list">
          {timed.map((e, i) => (
            <div className="agent wide" key={i}>
              <b>{e.summary}</b>
              <span className={`severity-badge ${classTone(e)}`}>{e.class}</span>
              <small>{[when(e), e.source, e.node].filter(Boolean).join(' · ')}</small>
            </div>
          ))}
        </div>
      </section>

      {state.length > 0 && (
        <section className="card span3">
          <p className="eyebrow">CURRENT STATE</p>
          <h2 className="card-title">Level-triggered findings (no event time)</h2>
          <div className="list">
            {state.map((e, i) => (
              <div className="agent wide" key={i}>
                <b>{e.summary}</b>
                <span className={`severity-badge ${classTone(e)}`}>{e.source}</span>
                <small>{e.node}</small>
              </div>
            ))}
          </div>
        </section>
      )}
    </div>
  );
}
