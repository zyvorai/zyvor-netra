// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0
import { useEffect, useState } from 'react';
import { api } from '../api';
import PagePulse from '../components/kit/PagePulse';
import { countTone } from '../components/kit/tone';

export type Lease = {
  owner: string;
  rule: string;
  type?: string;
  leaseSeconds: number;
  createdBy?: string;
  expiresAt: string;
  remainingSeconds: number;
  extensions?: number;
  expiringSoon?: boolean;
};

export type LeaseEvent = {
  at: string;
  action: string;
  actor?: string;
  owner?: string;
  rule?: string;
  leaseSeconds?: number;
  rails?: string[];
  breakGlass?: boolean;
  reason?: string;
};

type Rails = {
  enabled?: boolean;
  config?: Record<string, string | number | boolean>;
  usage?: { activeLeases?: number; breadthV4?: number; breadthV6?: number };
  configError?: string;
};

export function formatRemaining(sec: number): string {
  if (sec <= 0) return 'expiring';
  const h = Math.floor(sec / 3600);
  const m = Math.floor((sec % 3600) / 60);
  if (h > 0) return `${h}h ${m}m`;
  if (m > 0) return `${m}m ${sec % 60}s`;
  return `${sec}s`;
}

export default function DenyLeases() {
  const [leases, setLeases] = useState<Lease[]>([]);
  const [events, setEvents] = useState<LeaseEvent[]>([]);
  const [rails, setRails] = useState<Rails | null>(null);
  const [err, setErr] = useState('');
  const [tick, setTick] = useState(0);

  const load = () => {
    Promise.all([
      api<{ items: Lease[] }>('/api/v1/ebpf/deny-leases'),
      api<{ items: LeaseEvent[] }>('/api/v1/ebpf/deny-leases/history?limit=100'),
      api<Rails>('/api/v1/ebpf/deny-leases/rails'),
    ])
      .then(([l, h, r]) => {
        setLeases(l.items || []);
        setEvents(h.items || []);
        setRails(r);
        setErr('');
        setTick((t) => t + 1);
      })
      .catch((e) => setErr(String(e)));
  };

  useEffect(() => {
    load();
    const t = setInterval(load, 10000);
    return () => clearInterval(t);
  }, []);

  const soon = leases.filter((l) => l.expiringSoon);
  const rejects = events.filter((e) => e.action === 'reject').length;

  return (
    <div className="grid">
      <PagePulse
        headline={
          soon.length
            ? `${soon.length} lease${soon.length === 1 ? '' : 's'} ending within 15 minutes — the rule is removed when the lease ends.`
            : leases.length
              ? 'Every active deny lease has more than 15 minutes left.'
              : 'No active denyset leases.'
        }
        tone={soon.length ? 'warn' : undefined}
        tick={tick}
        error={err || undefined}
        figures={[
          { label: 'active leases', value: leases.length },
          { label: 'expiring soon', value: soon.length, tone: soon.length ? countTone(soon.length) : undefined },
          { label: 'rail rejections', value: rejects, tone: rejects ? 'warn' : undefined },
          { label: 'rails', value: rails?.enabled ? 'on' : 'off' },
        ]}
      />

      <section className="card span3">
        <p className="eyebrow">EXPIRING SOON</p>
        <h2 className="card-title">Leases about to lapse</h2>
        <p>
          Read-only. Declarative denysets create leased rules; when a lease ends the controller removes the rule and fails open. Extend a lease
          by planning and applying the denyset file again with a longer <code>lease:</code>.
        </p>
        {soon.length === 0 && <p className="empty-state">Nothing expires in the next 15 minutes.</p>}
        <div className="list">
          {soon.map((l) => (
            <div className="row" key={`${l.owner}|${l.rule}`}>
              <strong>{l.owner}</strong> {l.rule} <span className="warning">{formatRemaining(l.remainingSeconds)} left</span>
            </div>
          ))}
        </div>
      </section>

      <section className="card span3">
        <p className="eyebrow">ACTIVE</p>
        <h2 className="card-title">All deny leases</h2>
        {leases.length === 0 && <p className="empty-state">No leases.</p>}
        {leases.length > 0 && (
          <table>
            <thead>
              <tr>
                <th>Denyset</th>
                <th>Rule</th>
                <th>Remaining</th>
                <th>Lease</th>
                <th>Created by</th>
              </tr>
            </thead>
            <tbody>
              {leases.map((l) => (
                <tr key={`${l.owner}|${l.rule}`}>
                  <td>{l.owner}</td>
                  <td>{l.rule}</td>
                  <td>{formatRemaining(l.remainingSeconds)}</td>
                  <td>{Math.round(l.leaseSeconds / 60)}m{l.extensions ? ` (+${l.extensions})` : ''}</td>
                  <td>{l.createdBy}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </section>

      <section className="card span3">
        <p className="eyebrow">TIMELINE</p>
        <h2 className="card-title">Create, extend, expire, revoke</h2>
        {events.length === 0 && <p className="empty-state">No lease events yet.</p>}
        <div className="list">
          {events.map((e, i) => (
            <div className="row" key={`${e.at}|${i}`}>
              <code>{new Date(e.at).toLocaleString()}</code> <strong>{e.action}</strong> {e.rule} <em>{e.owner}</em> by {e.actor || 'system'}
              {e.rails && e.rails.length > 0 && <span className="warning"> rails: {e.rails.join(', ')}</span>}
              {e.breakGlass && <span className="warning"> break-glass: {e.reason}</span>}
              {!e.breakGlass && e.reason && <span> ({e.reason})</span>}
            </div>
          ))}
        </div>
      </section>

      <section className="card span3">
        <p className="eyebrow">SAFETY RAILS</p>
        <h2 className="card-title">Lease limits</h2>
        {rails?.configError && <p className="warning">Rail configuration ignored: {rails.configError}</p>}
        <p>
          {rails?.enabled
            ? 'Limits below are enforced when a lease is created. Break-glass can waive only the catch-all and protected-destination rails.'
            : 'No rails are configured (NETRA_LEASE_* unset): lease creation behaves as before.'}
        </p>
        {rails?.config && (
          <div className="list">
            {Object.entries(rails.config).map(([k, v]) => (
              <div className="row" key={k}>
                <code>{k}</code> {String(v)}
              </div>
            ))}
            <div className="row">
              <code>in use</code> {rails.usage?.activeLeases ?? 0} leases, {rails.usage?.breadthV4 ?? 0} IPv4 addresses, {rails.usage?.breadthV6 ?? 0} IPv6 /64s
            </div>
          </div>
        )}
      </section>
    </div>
  );
}
