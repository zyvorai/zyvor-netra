import { useEffect, useState } from 'react';
import { api } from '../api';

type Anomaly = { kind: string; severity: string; subject: string; message: string };

export default function NamespaceDrift() {
  const [data, setData] = useState<{ anomalies?: Anomaly[] }>();
  useEffect(() => {
    const load = () => api<{ anomalies?: Anomaly[] }>('/api/v1/ebpf/nsdrift').then(setData).catch(() => {});
    load();
    const t = setInterval(load, 20000);
    return () => clearInterval(t);
  }, []);
  return (
    <section className="card span3">
      <p className="eyebrow">NAMESPACE DRIFT</p>
      <h2 className="card-title">Network-namespace changes on tracked processes</h2>
      <p>A live process moving network namespaces after start (setns) — agent-sourced from the same periodic /proc scan capability drift uses (requires NETRA_PROCMETA_ENABLED). A change during an agent restart window is a known blind spot, surfaced below as its own finding rather than silently missed.</p>
      <div className="list">
        {(data?.anomalies || []).length === 0 && <p className="empty-state">No namespace drift observed yet.</p>}
        {(data?.anomalies || []).slice(0, 25).map((a, i) => (
          <div className="agent wide" key={i}>
            <b>{a.kind}</b><span className={`severity-badge ${a.severity}`}>{a.severity}</span><span>{a.subject}</span><small>{a.message}</small>
          </div>
        ))}
      </div>
    </section>
  );
}
