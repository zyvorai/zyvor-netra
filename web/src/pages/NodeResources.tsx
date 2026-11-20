import { useEffect, useState } from 'react';
import { api } from '../api';
import PagePulse from '../components/kit/PagePulse';
import { useSeries } from '../components/kit/useSeries';

const gb = (b: number | undefined) => ((b || 0) / (1024 ** 3)).toFixed(1);
const pct = (n: number | undefined) => `${(n || 0).toFixed(0)}%`;
const dur = (sec: number) => sec < 60 ? `${Math.round(sec)}s` : sec < 3600 ? `${Math.round(sec / 60)}m` : sec < 86400 ? `${(sec / 3600).toFixed(1)}h` : `${(sec / 86400).toFixed(1)}d`;

export default function NodeResources() {
  const [data, setData] = useState<any>();
  const [err, setErr] = useState('');
  const load = () => api<any>('/api/v1/node-resources?limit=50')
    .then((d) => { setData(d); setErr(''); })
    .catch((e) => setErr(String(e)));
  useEffect(() => { load(); const t = setInterval(load, 5000); return () => clearInterval(t); }, []);

  const s = data?.summary || {};
  const nodes = data?.nodes || [];
  const topWorkloads = data?.topWorkloadsByCpu || [];
  const memPct = s.totalMemoryBytes ? ((s.usedMemoryBytes || 0) * 100) / s.totalMemoryBytes : 0;
  const cpuSeries = useSeries(data ? (s.avgCpuPercent || 0) : undefined, data);
  const memSeries = useSeries(data ? memPct : undefined, data);

  return <div className="grid">
    {err && <section className="card span3"><p className="warning">{err}</p></section>}

    <PagePulse
      headline={data ? `${pct(s.avgCpuPercent)} average CPU across ${s.nodes || 0} node${s.nodes === 1 ? '' : 's'}.` : undefined}
      tone={data && (s.avgCpuPercent || 0) >= 85 ? 'warn' : undefined}
      tick={data}
      error={err || undefined}
      figures={[
        { label: 'avg CPU', value: data ? (s.avgCpuPercent || 0) : undefined, format: (n) => `${n.toFixed(0)}%`, tone: data && (s.avgCpuPercent || 0) >= 85 ? 'warn' : undefined, series: cpuSeries },
        { label: 'memory used', value: data ? memPct : undefined, format: (n) => `${n.toFixed(0)}%`, tone: data && memPct >= 90 ? 'warn' : undefined, series: memSeries },
        { label: 'memory used / total', value: data ? `${gb(s.usedMemoryBytes)} / ${gb(s.totalMemoryBytes)} GB` : undefined },
        { label: 'nodes · cores', value: data ? `${s.nodes || 0} · ${s.totalCpuCores || 0}` : undefined },
        { label: 'busiest CPU node', value: data ? (s.highestCpuNode || '—') : undefined },
      ]}
    />
    <p className="kit-caption span3">A "top"-like snapshot: host CPU/memory/load average per node, plus per-workload cgroup v2 usage attributed to pods/containers rather than raw PIDs. {(data?.limitations || []).join(' ')}</p>

    <section className="card span3">
      <p className="eyebrow">PER-NODE</p>
      <h2 className="card-title">Host CPU, memory, and load</h2>
      {nodes.length === 0 && <p className="empty-state">No agent reports yet.</p>}
      {nodes.length > 0 && <div className="datatable-scroll">
        <div className="datahead obs"><span>NODE</span><span>CPU</span><span>LOAD 1 / 5 / 15</span><span>MEMORY</span><span>UPTIME</span></div>
        {nodes.map((n: any) => (
          <div className="datarow obs" key={n.node}>
            <span className="truncate" title={n.node}>
              {n.node} {n.stale && <span className="severity-badge warning">stale</span>}
            </span>
            <span>{pct(n.host?.cpuPercent)} · {n.host?.cpuCores || 0} cores</span>
            <span>{(n.host?.loadAvg1 || 0).toFixed(2)} / {(n.host?.loadAvg5 || 0).toFixed(2)} / {(n.host?.loadAvg15 || 0).toFixed(2)}</span>
            <span>{gb(n.host?.memoryUsedBytes)} / {gb(n.host?.memoryTotalBytes)} GB</span>
            <span>{n.host?.uptimeSeconds ? dur(n.host.uptimeSeconds) : '—'}</span>
          </div>
        ))}
      </div>}
    </section>

    <section className="card span3">
      <p className="eyebrow">TOP WORKLOADS</p>
      <h2 className="card-title">Highest CPU usage, cgroup v2-attributed</h2>
      {topWorkloads.length === 0 && <p className="empty-state">No workload resource samples yet.</p>}
      {topWorkloads.length > 0 && <div className="datatable-scroll">
        <div className="datahead obs"><span>WORKLOAD</span><span>NODE</span><span>CPU</span><span>MEMORY</span></div>
        {topWorkloads.map((w: any, i: number) => {
          const who = w.namespace ? `${w.namespace}/${w.pod}` : (w.workloadName || `cgroup ${w.cgroupId || 0}`);
          return <div className="datarow obs" key={i}>
            <span className="truncate" title={who} aria-label={who}>{who}{w.workloadKind ? ` · ${w.workloadKind}` : ''}</span>
            <span>{w.node}</span>
            <span>{pct(w.cpuPercent)}</span>
            <span>{gb(w.memoryUsedBytes)} GB{w.memoryLimitBytes ? ` / ${gb(w.memoryLimitBytes)} GB` : ''}</span>
          </div>;
        })}
      </div>}
    </section>
  </div>;
}
