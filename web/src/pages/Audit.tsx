import { useEffect, useState } from 'react';
import { api } from '../api';
import BlockedEvents from '../components/BlockedEvents';
import SIEMExports from '../components/SIEMExports';
import PagePulse from '../components/kit/PagePulse';
import { auditActionClass } from '../lib/audit';

export default function Audit() {
  const [items, setItems] = useState<any[]>([]);
  const [timeline, setTimeline] = useState<any>();
  const [tick, setTick] = useState<number>();
  useEffect(() => {
    api<any>('/api/v1/audit?limit=200').then((x) => { setItems(x.items || []); setTick(Date.now()); });
    api<any>('/api/v1/incidents/timeline').then(setTimeline).catch(() => {});
  }, []);
  const dayAgo = Date.now() - 24 * 3600 * 1000;
  const lastDay = items.filter((x) => new Date(x.at).getTime() >= dayAgo).length;
  const actors = new Set(items.map((x) => x.actor)).size;
  const healthChanges = (timeline?.entries || []).filter((e: any) => e.kind === 'digest-transition').length;
  return (
    <div className="grid">
      <PagePulse
        headline={tick ? (items.length ? `${lastDay} control-plane action${lastDay === 1 ? '' : 's'} in the last 24 hours.` : 'No control-plane actions recorded yet.') : undefined}
        tick={tick}
        live={false}
        figures={[
          { label: 'audit events', value: tick ? items.length : undefined },
          { label: 'last 24h', value: tick ? lastDay : undefined },
          { label: 'actors', value: tick ? actors : undefined },
          { label: 'health changes', value: timeline ? healthChanges : undefined },
        ]}
      />
      <section className="card span3">
        <p className="eyebrow">INCIDENT TIMELINE</p>
        <h2 className="card-title">What happened, in order</h2>
        <p>Merges the audit log with cluster-health-signature transitions into plain sentences — never raw counters.</p>
        {timeline?.prose && <p>{timeline.prose}</p>}
        <div className="list">
          {(timeline?.entries || []).length === 0 && <p className="empty-state">No timeline entries yet.</p>}
          {(timeline?.entries || []).slice(0, 100).map((e: any, i: number) => (
            <div className="agent wide" key={i}>
              <b>{e.kind === 'digest-transition' ? 'health change' : 'action'}</b>
              <span>{new Date(e.at).toLocaleString()}</span>
              <small>{e.text}</small>
            </div>
          ))}
        </div>
      </section>

      <section className="card span3">
        <p className="eyebrow">CONTROL PLANE</p>
        <h2 className="card-title">Netra control-plane audit</h2>
        {items.length === 0 && <p className="empty-state">No audit events recorded yet.</p>}
        {items.length > 0 && (
          <div className="datatable-scroll">
            <div className="datahead audit">
              <span>TIME</span>
              <span>ACTOR</span>
              <span>ACTION</span>
              <span>TARGET</span>
            </div>
            {items.map((x, i) => (
              <div className="datarow audit" key={i}>
                <span>{new Date(x.at).toLocaleString()}</span>
                <span className="truncate" title={x.actor} aria-label={x.actor}>{x.actor}</span>
                <span className={auditActionClass(x.action)}>{x.action}</span>
                <span className="truncate" title={x.target || '—'} aria-label={x.target || '—'}>{x.target || '—'}</span>
              </div>
            ))}
          </div>
        )}
      </section>
      <BlockedEvents />
      <SIEMExports />
    </div>
  );
}
