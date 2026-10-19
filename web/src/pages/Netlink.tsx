// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
import { useEffect, useMemo, useState } from 'react';
import { api } from '../api';
import PagePulse from '../components/kit/PagePulse';
import { countTone } from '../components/kit/tone';

type Finding = {
  severity?: string;
  kind?: string;
  signal?: string;
  message?: string;
  node?: string;
  subject?: string;
  explanation?: string;
};

type Event = {
  observedAt?: string;
  node?: string;
  kind?: string;
  action?: string;
  interface?: string;
  family?: string;
  destination?: string;
  origin?: string;
};

export default function Netlink() {
  const [node, setNode] = useState('');
  const [kind, setKind] = useState('');
  const [events, setEvents] = useState<Event[]>([]);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [err, setErr] = useState('');
  const [tick, setTick] = useState(0);

  const load = () => {
    const q = new URLSearchParams({ view: 'events', limit: '100', since: '1h' });
    if (node.trim()) q.set('node', node.trim());
    if (kind.trim()) q.set('kind', kind.trim());
    Promise.all([
      api<{ events?: Event[] }>(`/api/v1/netlink?${q}`),
      api<{ findings?: Finding[] } | Finding[]>(`/api/v1/netlink/findings?window=1h${node.trim() ? `&node=${encodeURIComponent(node.trim())}` : ''}`),
    ])
      .then(([ev, fd]) => {
        setEvents(ev.events || []);
        const list = Array.isArray(fd) ? fd : fd.findings || [];
        setFindings(list);
        setErr('');
        setTick((t) => t + 1);
      })
      .catch((e) => setErr(String(e)));
  };

  useEffect(() => {
    load();
    const t = setInterval(load, 10000);
    return () => clearInterval(t);
  }, [node, kind]);

  const critical = useMemo(() => findings.filter((f) => (f.severity || '').toLowerCase() === 'critical').length, [findings]);
  const warnings = useMemo(() => findings.filter((f) => (f.severity || '').toLowerCase() === 'warning').length, [findings]);

  return (
    <div className="grid">
      <PagePulse
        headline={
          findings.length
            ? `${critical} critical · ${warnings} warning netlink finding${findings.length === 1 ? '' : 's'} in the last hour.`
            : events.length
              ? `${events.length} route/link/neighbor change${events.length === 1 ? '' : 's'} recorded — no active findings.`
              : 'Read-only RTNL change recorder. Netra never mutates routes, links, or neighbors.'
        }
        tone={critical ? 'bad' : warnings ? 'warn' : undefined}
        tick={tick}
        error={err || undefined}
        figures={[
          { label: 'events (1h)', value: events.length },
          { label: 'findings', value: findings.length, tone: findings.length ? countTone(findings.length) : undefined },
          { label: 'critical', value: critical, tone: critical ? 'bad' : undefined },
          { label: 'warnings', value: warnings, tone: warnings ? 'warn' : undefined },
        ]}
      />

      <section className="card span3">
        <p className="eyebrow">FILTERS</p>
        <h2 className="card-title">Node and event kind</h2>
        <p>Pod veth churn is normal and rarely becomes a finding. Focus on host uplinks, default routes, and failed neighbors.</p>
        <div className="filters" style={{ display: 'flex', flexWrap: 'wrap', gap: '0.75rem', marginTop: '0.75rem' }}>
          <label>
            Node <input value={node} onChange={(e) => setNode(e.target.value)} placeholder="optional" />
          </label>
          <label>
            Kind{' '}
            <select value={kind} onChange={(e) => setKind(e.target.value)}>
              <option value="">all</option>
              <option value="link">link</option>
              <option value="address">address</option>
              <option value="route">route</option>
              <option value="neighbor">neighbor</option>
              <option value="overrun">overrun</option>
            </select>
          </label>
          <button type="button" onClick={load}>
            Refresh
          </button>
        </div>
      </section>

      {err && (
        <section className="card span3">
          <p className="warning">{err}</p>
        </section>
      )}

      <section className="card span3">
        <p className="eyebrow">FINDINGS</p>
        <h2 className="card-title">What is wrong now</h2>
        {findings.length === 0 && <p className="empty-state">No netlink findings in this window.</p>}
        <div className="list">
          {findings.slice(0, 40).map((f, i) => (
            <div className="agent wide" key={i}>
              <b>{f.signal || f.kind || 'finding'}</b>
              <span className={`severity-badge ${f.severity || 'info'}`}>{f.severity || 'info'}</span>
              <span>{f.node || f.subject || '—'}</span>
              <small>{f.message || f.explanation || ''}</small>
            </div>
          ))}
        </div>
      </section>

      <section className="card span3">
        <p className="eyebrow">TIMELINE</p>
        <h2 className="card-title">Recent RTNL changes</h2>
        {events.length === 0 && <p className="empty-state">No events in the last hour.</p>}
        {events.length > 0 && (
          <div className="datatable-scroll">
            <div className="datahead obs">
              <span>WHEN</span>
              <span>NODE</span>
              <span>KIND</span>
              <span>ACTION</span>
              <span>DETAIL</span>
            </div>
            {events.slice(0, 100).map((e, i) => (
              <div className="datarow obs" key={i}>
                <span>{e.observedAt ? new Date(e.observedAt).toLocaleTimeString() : '—'}</span>
                <span>{e.node || '—'}</span>
                <span>{e.kind || '—'}</span>
                <span>{e.action || '—'}</span>
                <span className="truncate" title={[e.interface, e.destination, e.family, e.origin].filter(Boolean).join(' · ')}>
                  {[e.interface, e.destination, e.family, e.origin].filter(Boolean).join(' · ') || '—'}
                </span>
              </div>
            ))}
          </div>
        )}
      </section>
    </div>
  );
}
