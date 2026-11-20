import { useEffect, useState } from 'react';
import { api } from '../api';
import { navigate } from '../hooks/useInvestigation';

type History = {
  records?: Array<{
    observedAt?: string;
    namespace?: string;
    pod?: string;
    peer?: string;
    port?: number;
    appProtocol?: string;
    protocol?: string;
    comm?: string;
    pid?: number;
    packets?: number;
    blocked?: number;
  }>;
  limitations?: string[];
};

type RED = {
  window?: string;
  rows?: Array<{
    namespace?: string;
    pod?: string;
    ratePerSec?: number;
    errors?: number;
    avgSrttUs?: number;
    http5xx?: number;
    appProtocols?: string[];
  }>;
  limitations?: string[];
};

type Traces = {
  spans?: Array<{
    name?: string;
    parentId?: string;
    calleePod?: string;
    comm?: string;
    inferred?: boolean;
  }>;
  limitations?: string[];
};

export default function FlowObserve() {
  const [history, setHistory] = useState<History>();
  const [red, setRed] = useState<RED>();
  const [traces, setTraces] = useState<Traces>();
  const [error, setError] = useState('');

  useEffect(() => {
    let stop = false;
    (async () => {
      try {
        const [h, r, t] = await Promise.all([
          api<History>('/api/v1/flows/history?since=1h&limit=20'),
          api<RED>('/api/v1/insights/red?window=5m'),
          api<Traces>('/api/v1/insights/traces?since=15m'),
        ]);
        if (!stop) {
          setHistory(h);
          setRed(r);
          setTraces(t);
          setError('');
        }
      } catch (e) {
        if (!stop) setError(e instanceof Error ? e.message : 'observe boards unavailable');
      }
    })();
    return () => {
      stop = true;
    };
  }, []);

  const limits = history?.limitations || red?.limitations || [];

  return (
    <section className="card span3">
      <p className="eyebrow">FLOW HISTORY</p>
      <h2 className="card-title">Last hour, plus RED and inferred paths</h2>
      <p>
        In-memory deltas only. App protocol is a port hint. Process is comm and pid when TCP health matched. No
        payloads. For filters, polling and profiles open{' '}
        <button type="button" className="overview-link" onClick={() => navigate('flow-observe')}>
          Flow observe
        </button>
        .
      </p>
      {error && <p className="warning">{error}</p>}
      <div className="list">
        {(history?.records || []).length === 0 && <p className="empty-state">No flow history yet. The first sample of each flow is a baseline and is not shown.</p>}
        {(history?.records || []).map((rec, i) => (
          <button type="button" key={i}>
            <span>
              <b>
                {rec.namespace ? `${rec.namespace}/` : ''}
                {rec.pod || 'unattributed'}
              </b>{' '}
              → {rec.peer}:{rec.port} {rec.appProtocol || rec.protocol || ''}
              {rec.comm ? ` · ${rec.comm}` : ''}
              {rec.pid ? ` pid ${rec.pid}` : ''}
            </span>
            <span>
              {rec.packets || 0} pkts{rec.blocked ? ` · ${rec.blocked} blocked` : ''}
            </span>
          </button>
        ))}
      </div>
      <h3>RED · {red?.window || '5m'}</h3>
      <div className="list">
        {(red?.rows || []).length === 0 && <p className="empty-state">No workload rate in this window.</p>}
        {(red?.rows || []).slice(0, 8).map((row, i) => (
          <button type="button" key={i}>
            <span>
              <b>
                {row.namespace ? `${row.namespace}/` : ''}
                {row.pod || 'unattributed'}
              </b>{' '}
              {(row.appProtocols || []).join(', ')}
            </span>
            <span>
              {(row.ratePerSec || 0).toFixed(2)}/s · {row.errors || 0} errors
              {row.http5xx ? ` · ${row.http5xx} http 5xx` : ''}
              {row.avgSrttUs ? ` · ${row.avgSrttUs} µs` : ''}
            </span>
          </button>
        ))}
      </div>
      <h3>Inferred paths</h3>
      <div className="list">
        {(traces?.spans || []).length === 0 && <p className="empty-state">No linked hops in the last 15 minutes.</p>}
        {(traces?.spans || []).slice(0, 8).map((sp, i) => (
          <button type="button" key={i}>
            <span>
              <b>{sp.name}</b>
              {sp.calleePod ? ` → ${sp.calleePod}` : ''}
              {sp.parentId ? ' · child' : ''}
              {sp.comm ? ` · ${sp.comm}` : ''}
            </span>
            <span>{sp.inferred ? 'inferred' : ''}</span>
          </button>
        ))}
      </div>
      {limits.length > 0 && <p className="empty-state">{limits[0]}</p>}
    </section>
  );
}
