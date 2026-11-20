import { useEffect, useState } from 'react';
import { api } from '../api';

type Lease = { mode?: string; scopeMode?: string; remainingSeconds?: number; active?: boolean; expired?: boolean; note?: string };

const dur = (sec: number) => (sec < 60 ? `${Math.round(sec)}s` : sec < 3600 ? `${Math.round(sec / 60)}m` : `${(sec / 3600).toFixed(1)}h`);

export default function LeaseClock() {
  const [l, setL] = useState<Lease>();
  useEffect(() => {
    const load = () => api<Lease>('/api/v1/lease').then(setL).catch(() => {});
    load();
    const t = setInterval(load, 10000);
    return () => clearInterval(t);
  }, []);
  return (
    <section className="card span3">
      <p className="eyebrow">LEASE CLOCK</p>
      <h2 className="card-title">{l?.active ? `Enforce lease: ${dur(l.remainingSeconds || 0)} remaining` : l?.expired ? 'Enforce lease expired' : 'No enforce lease'}</h2>
      <p>{l?.note || 'Observe-only. All custom enforcement auto-reverts to observe when its lease expires.'}</p>
      <div className="list">
        <div className="agent wide"><b>Mode</b><span>{l?.mode || 'observe'}</span><small>{l?.scopeMode || 'scope n/a'}</small></div>
      </div>
    </section>
  );
}
