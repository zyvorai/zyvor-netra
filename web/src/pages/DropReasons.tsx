// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

import { useEffect, useState } from 'react';
import { api } from '../api';
import PagePulse from '../components/kit/PagePulse';
import { navigate } from '../hooks/useInvestigation';

type Bucket = { action?: string; reason?: string; count?: number; packets?: number; blocked?: number };
type Resp = {
  total?: number;
  blocked?: number;
  items?: Bucket[];
  reasons?: Bucket[];
  buckets?: Bucket[];
  note?: string;
};

export default function DropReasons() {
  const [data, setData] = useState<Resp>();
  const [err, setErr] = useState('');
  const [tick, setTick] = useState(0);

  useEffect(() => {
    const load = () =>
      api<Resp>('/api/v1/ebpf/reasons')
        .then((d) => {
          setData(d);
          setErr('');
          setTick(Date.now());
        })
        .catch((e) => setErr(String(e.message || e)));
    load();
    const t = setInterval(load, 10000);
    return () => clearInterval(t);
  }, []);

  const rows = data?.items || data?.reasons || data?.buckets || [];

  return (
    <div className="grid">
      <PagePulse
        tick={tick || undefined}
        error={err || undefined}
        tone={data?.blocked ? 'warn' : tick ? 'ok' : undefined}
        headline={tick ? `${data?.total ?? rows.length} reason rows · ${data?.blocked ?? 0} blocked` : undefined}
        figures={[
          { label: 'total', value: data?.total ?? rows.length },
          { label: 'blocked', value: data?.blocked, tone: data?.blocked ? ('warn' as const) : undefined },
          { label: 'buckets', value: rows.length },
        ]}
      />
      <section className="card span3">
        <p className="eyebrow">DROP REASONS</p>
        <h2 className="card-title">FastPath action/reason histogram</h2>
        <p>No payloads. {data?.note || 'From current agent reports.'}</p>
        <div className="chips">
          <button type="button" className="btn-secondary" onClick={() => navigate('drops')}>
            Drops
          </button>
          <button type="button" className="btn-secondary" onClick={() => navigate('handoff')}>
            Handoff
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
              a.download = 'netra-reasons.json';
              a.click();
              URL.revokeObjectURL(url);
            }}
          >
            Export JSON
          </button>
        </div>
        {err && <p className="warning">{err}</p>}
        <div className="list">
          {rows.length === 0 && !err && <p className="empty-state">No reason buckets yet.</p>}
          {rows.map((r, i) => (
            <div className="agent wide" key={i}>
              <b>{r.reason || r.action || `bucket ${i + 1}`}</b>
              {r.action && r.reason && <span className="severity-badge info">{r.action}</span>}
              <small>
                n={r.count ?? r.packets ?? 0}
                {r.blocked != null ? ` · blocked ${r.blocked}` : ''}
              </small>
            </div>
          ))}
        </div>
      </section>
    </div>
  );
}
