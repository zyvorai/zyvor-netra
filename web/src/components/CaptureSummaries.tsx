// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

import { useEffect, useState } from 'react';
import { api } from '../api';

type Active = {
  node?: string;
  backend?: string;
  protocol?: string;
  host?: string;
  port?: number;
  requestor?: string;
  startedAt?: string;
  active?: boolean;
  summary?: { frames?: number; bytes?: number; durationSeconds?: number };
};
type Resp = { active?: Active[]; history?: Active[]; note?: string };

export default function CaptureSummaries() {
  const [data, setData] = useState<Resp>();
  const [err, setErr] = useState('');

  useEffect(() => {
    const load = () =>
      api<Resp>('/api/v1/capture/summaries?limit=30')
        .then((d) => {
          setData(d);
          setErr('');
        })
        .catch((e) => setErr(String(e.message || e)));
    load();
    const t = setInterval(load, 15000);
    return () => clearInterval(t);
  }, []);

  const active = data?.active || [];
  const hist = (data?.history || []).slice(0, 12);

  return (
    <section className="card span3">
      <p className="eyebrow">CAPTURE SUMMARIES</p>
      <h2 className="card-title">
        {active.length} active · {hist.length} recent
      </h2>
      <p>{data?.note || 'Bounded session metadata — no PCAP bytes. MCP: netra_capture_summaries.'}</p>
      {err && <p className="warning">{err}</p>}
      <div className="list">
        {active.length === 0 && hist.length === 0 && !err && <p className="empty-state">No capture sessions yet.</p>}
        {active.map((a, i) => (
          <div className="agent wide" key={`a-${a.node}-${i}`}>
            <b>{a.node || 'node'}</b>
            <span className="severity-badge ok">active</span>
            <small>
              {[a.backend, a.protocol, a.host, a.port, a.requestor, a.summary?.frames != null ? `${a.summary.frames} frames` : '']
                .filter(Boolean)
                .join(' · ')}
            </small>
          </div>
        ))}
        {hist.map((h, i) => (
          <div className="agent wide" key={`h-${h.node}-${i}`}>
            <b>{h.node || 'node'}</b>
            <span className="severity-badge info">history</span>
            <small>
              {[h.backend, h.protocol, h.host, h.port, h.requestor, h.startedAt ? new Date(h.startedAt).toLocaleString() : '']
                .filter(Boolean)
                .join(' · ')}
            </small>
          </div>
        ))}
      </div>
    </section>
  );
}
