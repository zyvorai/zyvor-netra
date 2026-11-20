// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

import { useEffect, useState } from 'react';
import { api } from '../api';
import PagePulse from '../components/kit/PagePulse';
import { navigate } from '../hooks/useInvestigation';

type Item = {
  name?: string;
  sli?: string;
  namespace?: string;
  workload?: string;
  targetPct?: number;
  window?: string;
  severity?: string;
  hasData?: boolean;
  total?: number;
  errors?: number;
  compliancePct?: number;
  budgetRemaining?: number;
  windows?: Array<{ kind?: string; longBurn?: number; shortBurn?: number; firing?: boolean }>;
};
type Resp = { enabled?: boolean; workloadSeriesEnabled?: boolean; items?: Item[] };

export default function SLO() {
  const [data, setData] = useState<Resp>();
  const [err, setErr] = useState('');
  const [tick, setTick] = useState(0);

  useEffect(() => {
    const load = () =>
      api<Resp>('/api/v1/slo')
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

  const items = data?.items || [];
  const firing = items.filter((i) => i.severity && i.severity !== 'none' && i.severity !== 'ok').length;

  return (
    <div className="grid">
      <PagePulse
        tick={tick || undefined}
        error={err || undefined}
        tone={!data?.enabled ? undefined : firing ? 'warn' : tick ? 'ok' : undefined}
        headline={
          data?.enabled === false
            ? 'No workload SLOs configured.'
            : tick
              ? `${items.length} SLO${items.length === 1 ? '' : 's'} · ${firing} burning`
              : undefined
        }
        figures={[
          { label: 'enabled', value: data?.enabled ? 1 : 0 },
          { label: 'items', value: items.length },
          { label: 'burning', value: firing, tone: firing ? ('warn' as const) : undefined },
          { label: 'prom series', value: data?.workloadSeriesEnabled ? 1 : 0 },
        ]}
      />
      <section className="card span3">
        <p className="eyebrow">WORKLOAD SLO</p>
        <h2 className="card-title">Burn from observed errors — never applies policy</h2>
        <p>
          Configure SLOs on the controller; this board is observe-only. CLI: <code>netractl slo</code>. MCP: <code>netra_slo</code>.
        </p>
        <div className="chips">
          <button type="button" className="btn-secondary" onClick={() => navigate('metrics')}>
            Metrics
          </button>
          <button type="button" className="btn-secondary" onClick={() => navigate('metric-alerts')}>
            Metric alerts
          </button>
          <button type="button" className="btn-secondary" onClick={() => navigate('ai')}>
            Ask Netra
          </button>
        </div>
        {err && <p className="warning">{err}</p>}
        {!err && data?.enabled === false && <p className="empty-state">Enable workload SLOs in operator config to populate this board.</p>}
        <div className="list">
          {items.map((it, i) => (
            <div className="agent wide" key={`${it.name}-${i}`}>
              <b>{it.name || it.workload || `slo-${i}`}</b>
              <span className={`severity-badge ${it.severity === 'page' || it.severity === 'ticket' ? 'warning' : 'info'}`}>
                {it.severity || 'none'}
              </span>
              <small>
                {[
                  it.namespace && it.workload ? `${it.namespace}/${it.workload}` : '',
                  it.sli,
                  it.targetPct != null ? `target ${it.targetPct}%` : '',
                  it.compliancePct != null ? `compliance ${Number(it.compliancePct).toFixed(2)}%` : '',
                  it.window,
                  !it.hasData ? 'no data' : '',
                ]
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
