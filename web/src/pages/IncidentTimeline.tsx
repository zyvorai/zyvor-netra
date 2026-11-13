// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

import { useEffect, useState } from 'react';
import { api } from '../api';
import PagePulse from '../components/kit/PagePulse';
import { navigate } from '../hooks/useInvestigation';

type Entry = {
  kind?: string;
  at?: string;
  time?: string;
  text?: string;
  narrative?: string;
  actor?: string;
  action?: string;
  summary?: string;
};
type Resp = {
  entries?: Entry[];
  items?: Entry[];
  engine?: string;
  narrative?: string;
  generatedAt?: string;
  note?: string;
};

export default function IncidentTimeline() {
  const [data, setData] = useState<Resp>();
  const [err, setErr] = useState('');
  const [tick, setTick] = useState(0);

  useEffect(() => {
    const load = () =>
      api<Resp>('/api/v1/incidents/timeline')
        .then((d) => {
          setData(d);
          setErr('');
          setTick(Date.now());
        })
        .catch((e) => setErr(String(e.message || e)));
    load();
    const t = setInterval(load, 15000);
    return () => clearInterval(t);
  }, []);

  const rows = data?.entries || data?.items || [];

  return (
    <div className="grid">
      <PagePulse
        tick={tick || undefined}
        error={err || undefined}
        tone={tick ? 'ok' : undefined}
        headline={tick ? `${rows.length} timeline entr${rows.length === 1 ? 'y' : 'ies'}` : undefined}
        figures={[
          { label: 'entries', value: rows.length },
          { label: 'engine', value: data?.engine ? 1 : undefined },
        ]}
      />
      <section className="card span3">
        <p className="eyebrow">INCIDENT TIMELINE</p>
        <h2 className="card-title">Audit + health-signature narrative</h2>
        <p>
          Chronological merge of controller audit actions and cluster-health signature transitions. Observe-only —
          never acks, silences or applies a deny. {data?.engine ? <>Engine: <code>{data.engine}</code>.</> : null}
        </p>
        <div className="chips">
          <button type="button" className="btn-secondary" onClick={() => navigate('incidents')}>
            Incidents
          </button>
          <button type="button" className="btn-secondary" onClick={() => navigate('handoff')}>
            Handoff
          </button>
          <button type="button" className="btn-secondary" onClick={() => navigate('audit')}>
            Audit
          </button>
          <button
            type="button"
            className="btn-secondary"
            disabled={!data}
            onClick={() => {
              const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
              const url = URL.createObjectURL(blob);
              const a = document.createElement('a');
              a.href = url;
              a.download = 'netra-incident-timeline.json';
              a.click();
              URL.revokeObjectURL(url);
            }}
          >
            Export JSON
          </button>
        </div>
        {err && <p className="warning">{err}</p>}
        {data?.narrative && <p>{data.narrative}</p>}
        {data?.note && <p className="empty-state">{data.note}</p>}
      </section>

      <section className="card span3">
        <p className="eyebrow">CHRONOLOGY</p>
        <h2 className="card-title">What changed, in order</h2>
        <div className="list">
          {rows.length === 0 && !err && <p className="empty-state">No timeline entries retained yet.</p>}
          {rows.map((e, i) => (
            <div className="agent wide" key={i}>
              <b>{e.text || e.narrative || e.summary || e.action || `entry ${i + 1}`}</b>
              <span className="severity-badge info">{e.kind || 'event'}</span>
              <small>
                {[e.at || e.time, e.actor, e.action && e.text !== e.action ? e.action : '']
                  .filter(Boolean)
                  .join(' · ')}
              </small>
            </div>
          ))}
        </div>
      </section>
    </div>
  );
}
