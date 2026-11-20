import { useEffect, useState } from 'react';
import { api } from '../api';

type Baselines = {
  behaviorPresent?: boolean; behaviorAgeSeconds?: number; behaviorEntries?: number;
  ratePresent?: boolean; rateAgeSeconds?: number; rateEntries?: number;
  stale?: boolean; note?: string;
};

const dur = (sec?: number) => {
  const s = sec || 0;
  return s < 60 ? `${Math.round(s)}s` : s < 3600 ? `${Math.round(s / 60)}m` : s < 86400 ? `${(s / 3600).toFixed(1)}h` : `${(s / 86400).toFixed(1)}d`;
};

export default function BaselineAge() {
  const [b, setB] = useState<Baselines>();
  useEffect(() => {
    const load = () => api<Baselines>('/api/v1/baselines').then(setB).catch(() => {});
    load();
    const t = setInterval(load, 20000);
    return () => clearInterval(t);
  }, []);
  return (
    <section className="card span3">
      <p className="eyebrow">BASELINE AGE</p>
      <h2 className="card-title">Whether baselines exist and how old they are</h2>
      {b?.note && <p>{b.note}</p>}
      <div className="list">
        <div className="agent wide">
          <b>Behavior baseline</b>
          <span className={b?.behaviorPresent ? 'severity-badge info' : 'severity-badge warning'}>{b?.behaviorPresent ? 'captured' : 'none'}</span>
          <small>{b?.behaviorPresent ? `${dur(b.behaviorAgeSeconds)} old · ${b.behaviorEntries} entries` : 'Capture from Insights to enable drift findings.'}</small>
        </div>
        <div className="agent wide">
          <b>Rate baseline</b>
          <span className={b?.ratePresent ? (b?.stale ? 'severity-badge warning' : 'severity-badge info') : 'severity-badge warning'}>{b?.ratePresent ? (b?.stale ? 'stale' : 'captured') : 'none'}</span>
          <small>{b?.ratePresent ? `${dur(b.rateAgeSeconds)} old · ${b.rateEntries} entries` : 'Capture from Insights to enable rate-drift findings.'}</small>
        </div>
      </div>
    </section>
  );
}
