import { useEffect, useState } from 'react';
import { api } from '../api';

type Anomaly = { kind: string; severity: string; subject: string; message: string };

export default function ExeHashDrift() {
  const [data, setData] = useState<{ anomalies?: Anomaly[] }>();
  useEffect(() => {
    const load = () => api<{ anomalies?: Anomaly[] }>('/api/v1/ebpf/exehash').then(setData).catch(() => {});
    load();
    const t = setInterval(load, 20000);
    return () => clearInterval(t);
  }, []);
  return (
    <section className="card span3">
      <p className="eyebrow">EXE-HASH DRIFT</p>
      <h2 className="card-title">Executable-content changes on tracked processes</h2>
      <p>Observe-only half of exe-hash leased deny — no lease map or enforcement exists yet. A change means a process's own backing binary content changed while it was running; reading the magic /proc/PID/exe symlink directly avoids false-flagging a routine package upgrade replacing the on-disk file at that path. Requires NETRA_PROCMETA_ENABLED.</p>
      <div className="list">
        {(data?.anomalies || []).length === 0 && <p className="empty-state">No executable-content drift observed yet.</p>}
        {(data?.anomalies || []).slice(0, 25).map((a, i) => (
          <div className="agent wide" key={i}>
            <b>{a.kind}</b><span className={`severity-badge ${a.severity}`}>{a.severity}</span><span>{a.subject}</span><small>{a.message}</small>
          </div>
        ))}
      </div>
    </section>
  );
}
