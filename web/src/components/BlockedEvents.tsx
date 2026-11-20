import { useEffect, useState } from 'react';
import { api } from '../api';

type BlockRecord = { at: string; severity?: string; action?: string; target?: string; subject?: string; message?: string; kind?: string; node?: string };
type Export = { count?: number; items?: BlockRecord[] };

export default function BlockedEvents() {
  const [data, setData] = useState<Export>();
  useEffect(() => {
    const load = () => api<Export>('/api/v1/export/blocks?format=json&limit=25').then(setData).catch(() => {});
    load();
    const t = setInterval(load, 20000);
    return () => clearInterval(t);
  }, []);
  return (
    <section className="card span3">
      <p className="eyebrow">BLOCKED / DROPPED EVENTS</p>
      <h2 className="card-title">{data?.count ?? 0} recent</h2>
      <p>
        SIEM export of blocked/dropped events. Also available as CEF, RFC5424 syslog, OTLP logs, or OTLP traces (one span
        per event) via <code>netractl export blocks --format &lt;json|jsonl|cef|syslog|otlp|otlp-trace&gt;</code> or{' '}
        <code>GET /api/v1/export/blocks</code>.
      </p>
      <div className="list">
        {(data?.items || []).length === 0 && <p className="empty-state">No blocked/dropped events recorded yet.</p>}
        {(data?.items || []).map((r, i) => (
          <div className="agent wide" key={i}>
            <b>{r.action || 'blocked'}</b>
            <span className={`severity-badge ${r.severity || 'warning'}`}>{r.kind || 'unknown reason'}</span>
            <small>{r.subject || r.target} on {r.node} — {new Date(r.at).toLocaleString()}</small>
          </div>
        ))}
      </div>
    </section>
  );
}
