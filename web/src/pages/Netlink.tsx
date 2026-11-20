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

type Actor = {
  confidence?: string;
  comm?: string;
  pid?: number;
  cgroupId?: number;
  namespace?: string;
  pod?: string;
  workload?: string;
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
  actor?: Actor;
};

type StateNode = {
  node?: string;
  links?: number;
  addresses?: number;
  routes?: number;
  neighbors?: number;
  actor?: { available?: boolean; note?: string };
};

export default function Netlink() {
  const [node, setNode] = useState('');
  const [kind, setKind] = useState('');
  const [view, setView] = useState<'events' | 'state'>('events');
  const [events, setEvents] = useState<Event[]>([]);
  const [stateNodes, setStateNodes] = useState<StateNode[]>([]);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [err, setErr] = useState('');
  const [tick, setTick] = useState(0);

  const load = () => {
    const q = new URLSearchParams({ view, limit: '100', since: '1h' });
    if (node.trim()) q.set('node', node.trim());
    if (kind.trim() && view === 'events') q.set('kind', kind.trim());
    Promise.all([
      api<{ events?: Event[]; nodes?: StateNode[] }>(`/api/v1/netlink?${q}`),
      api<{ findings?: Finding[] } | Finding[]>(`/api/v1/netlink/findings?window=1h${node.trim() ? `&node=${encodeURIComponent(node.trim())}` : ''}`),
    ])
      .then(([ev, fd]) => {
        setEvents(ev.events || []);
        setStateNodes(ev.nodes || []);
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
  }, [node, kind, view]);

  const critical = useMemo(() => findings.filter((f) => (f.severity || '').toLowerCase() === 'critical').length, [findings]);
  const warnings = useMemo(() => findings.filter((f) => (f.severity || '').toLowerCase() === 'warning').length, [findings]);

  const actorLabel = (e: Event) => {
    const a = e.actor;
    if (!a) return e.origin || '';
    const who = [a.comm, a.pid != null ? `pid ${a.pid}` : '', a.namespace && a.pod ? `${a.namespace}/${a.pod}` : a.workload || '']
      .filter(Boolean)
      .join(' · ');
    return who || e.origin || '';
  };

  return (
    <div className="grid">
      <PagePulse
        headline={
          findings.length
            ? `${critical} critical · ${warnings} warning netlink finding${findings.length === 1 ? '' : 's'} in the last hour.`
            : events.length || stateNodes.length
              ? view === 'state'
                ? `${stateNodes.length} node state snapshot${stateNodes.length === 1 ? '' : 's'}.`
                : `${events.length} route/link/neighbor change${events.length === 1 ? '' : 's'} recorded — no active findings.`
              : 'Read-only RTNL change recorder. Netra never mutates routes, links, or neighbors.'
        }
        tone={critical ? 'bad' : warnings ? 'warn' : undefined}
        tick={tick}
        error={err || undefined}
        figures={[
          { label: view === 'state' ? 'nodes' : 'events (1h)', value: view === 'state' ? stateNodes.length : events.length },
          { label: 'findings', value: findings.length, tone: findings.length ? countTone(findings.length) : undefined },
          { label: 'critical', value: critical, tone: critical ? 'bad' : undefined },
          { label: 'warnings', value: warnings, tone: warnings ? 'warn' : undefined },
        ]}
      />

      <section className="card span3">
        <p className="eyebrow">FILTERS</p>
        <h2 className="card-title">Node, kind, and view</h2>
        <p>Requester attribution (comm/pid/cgroup→pod) is recorded when origin is process — never argv or environ.</p>
        <div className="filters" style={{ display: 'flex', flexWrap: 'wrap', gap: '0.75rem', marginTop: '0.75rem' }}>
          <label>
            View{' '}
            <select value={view} onChange={(e) => setView(e.target.value as 'events' | 'state')}>
              <option value="events">events</option>
              <option value="state">state</option>
            </select>
          </label>
          <label>
            Node <input value={node} onChange={(e) => setNode(e.target.value)} placeholder="optional" />
          </label>
          {view === 'events' && (
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
          )}
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

      {view === 'state' ? (
        <section className="card span3">
          <p className="eyebrow">STATE</p>
          <h2 className="card-title">Per-node RTNL snapshot</h2>
          {stateNodes.length === 0 && <p className="empty-state">No state snapshots yet.</p>}
          <table className="metric-table">
            <thead>
              <tr>
                <th>Node</th>
                <th className="num">Links</th>
                <th className="num">Addresses</th>
                <th className="num">Routes</th>
                <th className="num">Neighbors</th>
                <th>Actor sensor</th>
              </tr>
            </thead>
            <tbody>
              {stateNodes.map((n) => (
                <tr key={n.node}>
                  <td>{n.node}</td>
                  <td className="num">{n.links ?? '—'}</td>
                  <td className="num">{n.addresses ?? '—'}</td>
                  <td className="num">{n.routes ?? '—'}</td>
                  <td className="num">{n.neighbors ?? '—'}</td>
                  <td>{n.actor?.available === false ? n.actor?.note || 'unavailable' : n.actor?.note || 'ok'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </section>
      ) : (
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
                <span>WHO</span>
                <span>DETAIL</span>
              </div>
              {events.slice(0, 100).map((e, i) => (
                <div className="datarow obs" key={i}>
                  <span>{e.observedAt ? new Date(e.observedAt).toLocaleTimeString() : '—'}</span>
                  <span>{e.node || '—'}</span>
                  <span>{e.kind || '—'}</span>
                  <span>{e.action || '—'}</span>
                  <span className="truncate" title={actorLabel(e)}>
                    {actorLabel(e) || '—'}
                  </span>
                  <span className="truncate" title={[e.interface, e.destination, e.family, e.origin].filter(Boolean).join(' · ')}>
                    {[e.interface, e.destination, e.family].filter(Boolean).join(' · ') || '—'}
                  </span>
                </div>
              ))}
            </div>
          )}
        </section>
      )}
    </div>
  );
}
