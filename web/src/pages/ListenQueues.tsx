// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

import { useEffect, useState } from 'react';
import { api } from '../api';
import PagePulse from '../components/kit/PagePulse';
import { navigate } from '../hooks/useInvestigation';

type Top = {
  node?: string;
  addr?: string;
  address?: string;
  port?: number;
  queue?: number;
  max?: number;
  peakPct?: number;
  synRecv?: number;
  process?: string;
  comm?: string;
};
type Resp = {
  listeners?: number;
  full?: number;
  saturated?: number;
  synRecv?: number;
  nodesReporting?: number;
  nodesNotReporting?: number;
  buckets?: Record<string, number>;
  top?: Top[];
  nodes?: { node?: string; reporting?: boolean; unavailable?: string }[];
};

export default function ListenQueues() {
  const [data, setData] = useState<Resp>();
  const [stack, setStack] = useState<any>();
  const [err, setErr] = useState('');
  const [tick, setTick] = useState(0);

  useEffect(() => {
    const load = () =>
      Promise.all([api<Resp>('/api/v1/listen-queues?top=40'), api<any>('/api/v1/ebpf/stack-histograms').catch(() => null)])
        .then(([lq, sh]) => {
          setData(lq);
          setStack(sh);
          setErr('');
          setTick(Date.now());
        })
        .catch((e) => setErr(String(e.message || e)));
    load();
    const t = setInterval(load, 10000);
    return () => clearInterval(t);
  }, []);

  const top = data?.top || [];
  const bucketEntries = Object.entries(data?.buckets || {}).sort((a, b) => a[0].localeCompare(b[0]));
  const stackNodes = stack?.nodes || stack?.items || [];

  return (
    <div className="grid">
      <PagePulse
        tick={tick || undefined}
        error={err || undefined}
        tone={data?.full || data?.saturated ? 'warn' : tick ? 'ok' : undefined}
        headline={
          tick
            ? `${data?.listeners ?? 0} listeners · ${data?.saturated ?? 0} saturated · ${data?.full ?? 0} full`
            : undefined
        }
        figures={[
          { label: 'listeners', value: data?.listeners },
          { label: 'saturated', value: data?.saturated, tone: data?.saturated ? ('warn' as const) : undefined },
          { label: 'full', value: data?.full, tone: data?.full ? ('bad' as const) : undefined },
          { label: 'SYN-RECV', value: data?.synRecv },
          { label: 'nodes reporting', value: data?.nodesReporting },
        ]}
      />
      <section className="card span3">
        <p className="eyebrow">LISTEN QUEUES</p>
        <h2 className="card-title">TCP accept-queue pressure</h2>
        <p>
          Point-in-time depth from inet_diag on each agent. Observe-only — never tunes somaxconn or applies a deny.
        </p>
        <div className="chips">
          <button type="button" className="btn-secondary" onClick={() => navigate('congestion')}>
            Congestion Map
          </button>
          <button type="button" className="btn-secondary" onClick={() => navigate('drops')}>
            Drops
          </button>
          <button
            type="button"
            className="btn-secondary"
            disabled={!data}
            onClick={() => {
              const blob = new Blob([JSON.stringify({ listenQueues: data, stackHistograms: stack }, null, 2)], {
                type: 'application/json',
              });
              const url = URL.createObjectURL(blob);
              const a = document.createElement('a');
              a.href = url;
              a.download = 'netra-listen-queues.json';
              a.click();
              URL.revokeObjectURL(url);
            }}
          >
            Export JSON
          </button>
        </div>
        {err && <p className="warning">{err}</p>}
        {bucketEntries.length > 0 && (
          <div className="chips" style={{ marginTop: '0.75rem' }}>
            {bucketEntries.map(([b, n]) => (
              <span key={b} className="severity-badge info">
                fill {b}: {n}
              </span>
            ))}
          </div>
        )}
      </section>

      <section className="card span3">
        <p className="eyebrow">TOP LISTENERS</p>
        <h2 className="card-title">{top.length} deepest accept queues</h2>
        <div className="list">
          {top.length === 0 && !err && <p className="empty-state">No listeners sampled yet.</p>}
          {top.map((e, i) => {
            const pct = e.max ? Math.round(((e.queue || 0) / e.max) * 100) : e.peakPct;
            return (
              <div className="agent wide" key={i}>
                <b>
                  {e.node || '—'} · {e.addr || e.address || '*'}:{e.port ?? '—'}
                </b>
                <span className={`severity-badge ${pct != null && pct >= 80 ? 'warning' : 'info'}`}>
                  {e.queue ?? 0}/{e.max ?? '?'}
                  {pct != null ? ` · ${pct}%` : ''}
                </span>
                <small>
                  {[e.comm || e.process, e.synRecv != null ? `synRecv ${e.synRecv}` : '', e.peakPct != null ? `peak ${e.peakPct}%` : '']
                    .filter(Boolean)
                    .join(' · ')}
                </small>
              </div>
            );
          })}
        </div>
      </section>

      <section className="card span3">
        <p className="eyebrow">STACK HISTOGRAMS</p>
        <h2 className="card-title">Softirq / softnet / listen depth</h2>
        <p>
          Pressure buckets from agent reports — not entry→exit softirq latency. CLI:{' '}
          <code>netractl ebpf stack-histograms</code>.
        </p>
        <div className="list">
          {stackNodes.length === 0 && <p className="empty-state">No stack histogram samples yet.</p>}
          {stackNodes.map((n: any, i: number) => (
            <div className="agent wide" key={n.node || i}>
              <b>{n.node || `node ${i + 1}`}</b>
              <small>
                softirq NET_RX {n.softirqNetRx ?? 0} · softnet drop {n.softnetDropped ?? 0} · squeeze{' '}
                {n.softnetTimeSqueeze ?? 0} · listen overflow {n.listenOverflows ?? 0} · listen drops{' '}
                {n.listenDrops ?? 0}
              </small>
              {(n.listenDepthBuckets || []).length > 0 && (
                <small>
                  depth:{' '}
                  {(n.listenDepthBuckets || [])
                    .map((b: any) => `${b.label}=${b.count}`)
                    .join(' · ')}
                </small>
              )}
            </div>
          ))}
        </div>
      </section>
    </div>
  );
}
