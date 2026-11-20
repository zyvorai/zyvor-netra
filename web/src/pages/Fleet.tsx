import { useEffect, useState } from 'react';
import { api } from '../api';
import PagePulse from '../components/kit/PagePulse';
import { countTone } from '../components/kit/tone';
import { classifyMissingMaps } from '../lib/missingMaps';
import { navigate } from '../hooks/useInvestigation';

type FleetNode = {
  node?: string; stale?: boolean; mode?: string; ageSeconds?: number; hooks?: number; programs?: number; attached?: number; workloads?: number; destinations?: number; events?: number;
  cpuPercent?: number; memoryUsedBytes?: number; memoryTotalBytes?: number; loadAvg1?: number;
};
type Inventory = { nodes?: FleetNode[]; agentCount?: number; staleAgents?: number };

type CoverageProgram = { name: string; type?: string; attached: boolean; runCount?: number };
type CoverageNode = { node: string; stale: boolean; mode?: string; hookCount: number; programCount: number; attached: number; detached?: string[]; missingMaps?: string[]; programs?: CoverageProgram[] };
type Coverage = { nodes?: CoverageNode[]; agentCount?: number; staleAgents?: number; detachedPrograms?: number; missingMapEntries?: number; quiet?: boolean };

export default function Fleet() {
  const [inv, setInv] = useState<Inventory>();
  const [cov, setCov] = useState<Coverage>();
  const [clusters, setClusters] = useState<any>();
  const [tenants, setTenants] = useState<any>();
  const [flows, setFlows] = useState<any>();
  const [err, setErr] = useState('');
  const load = () => Promise.all([
    api<Inventory>('/api/v1/fleet'),
    api<Coverage>('/api/v1/ebpf/coverage'),
    api<any>('/api/v1/fleet/clusters'),
    api<any>('/api/v1/fleet/tenants'),
    api<any>('/api/v1/fleet/flows/history?limit=40').catch(() => null),
  ]).then(([i, c, cl, te, fl]) => {
    setInv(i); setCov(c); setClusters(cl); setTenants(te); setFlows(fl); setErr('');
  }).catch((e) => setErr(String(e)));
  useEffect(() => { load(); const t = setInterval(load, 20000); return () => clearInterval(t); }, []);
  const flowRows = flows?.records || flows?.items || flows?.flows || [];

  const agents = inv?.agentCount ?? 0;
  const stale = inv?.staleAgents ?? 0;
  const detached = cov?.detachedPrograms ?? 0;
  const missing = cov?.missingMapEntries ?? 0;
  const workloads = (inv?.nodes || []).reduce((n, x) => n + (x.workloads || 0), 0);
  return (
    <div className="grid">
      <PagePulse
        headline={inv ? (stale ? `${stale} of ${agents} agent${agents === 1 ? '' : 's'} stale.` : detached ? `${detached} program${detached === 1 ? '' : 's'} detached.` : agents ? `All ${agents} agent${agents === 1 ? '' : 's'} reporting.` : 'No agents reporting yet.') : undefined}
        tone={inv ? (stale || !agents ? 'bad' : detached || missing ? 'warn' : undefined) : undefined}
        tick={inv}
        error={err || undefined}
        figures={[
          { label: 'agents', value: inv ? agents : undefined },
          { label: 'stale', value: inv ? stale : undefined, tone: inv ? (stale ? 'bad' : 'ok') : undefined },
          { label: 'detached programs', value: cov ? detached : undefined, tone: cov ? countTone(detached) : undefined },
          { label: 'missing maps', value: cov ? missing : undefined, tone: cov ? countTone(missing) : undefined },
          { label: 'workload cgroups', value: inv ? workloads : undefined },
        ]}
      />
      <section className="card span3">
        <p className="eyebrow">FLEET</p>
        <h2 className="card-title">{inv?.agentCount ?? 0} agents · {inv?.staleAgents ?? 0} stale</h2>
        <p>Compact per-node agent inventory. Observe-only.</p>
        {err && <p className="warning">{err}</p>}
        <div className="list">
          {(inv?.nodes || []).length === 0 && <p className="empty-state">No agents reporting yet.</p>}
          {(inv?.nodes || []).map((n, i) => (
            <div className="agent wide" key={n.node || i}>
              <b>{n.node}</b>
              <span className={n.stale ? 'severity-badge warning' : 'severity-badge info'}>{n.stale ? 'stale' : n.mode || 'observe'}</span>
              <small>
                {n.hooks ?? 0} hooks · {n.attached ?? 0}/{n.programs ?? 0} programs attached · {n.workloads ?? 0} workload cgroups · {n.destinations ?? 0} destinations · {n.ageSeconds ?? 0}s since last report
                {n.memoryTotalBytes ? <> · {n.cpuPercent?.toFixed(0) ?? '—'}% cpu · {Math.round(((n.memoryUsedBytes ?? 0) / n.memoryTotalBytes) * 100)}% mem · load {n.loadAvg1?.toFixed(2) ?? '—'}</> : null}
              </small>
            </div>
          ))}
        </div>
      </section>

      <section className="card span3">
        <p className="eyebrow">PROGRAM COVERAGE</p>
        <h2 className="card-title">{cov?.quiet ? 'All programs attached' : `${cov?.detachedPrograms ?? 0} detached · ${cov?.missingMapEntries ?? 0} missing maps`}</h2>
        <p>Per-node hook/program coverage matrix: attached vs detached programs, missing maps, stale agents. Observe-only — never attaches or detaches anything itself.</p>
        <div className="list">
          {(cov?.nodes || []).length === 0 && <p className="empty-state">No coverage data yet.</p>}
          {(cov?.nodes || []).map((n) => (
            <div className="agent wide" key={n.node}>
              <b>{n.node}</b>
              <span className={n.stale ? 'severity-badge warning' : 'severity-badge info'}>{n.attached}/{n.programCount} attached</span>
              <small>
                {n.hookCount} hooks
                {(n.detached || []).length > 0 && <> · detached: {(n.detached || []).join(', ')}</>}
                {(() => {
                  const classified = classifyMissingMaps(n.missingMaps || []);
                  const bpfMaps = classified.filter((e) => e.kind === 'bpf-map').map((e) => e.raw);
                  const captureIssues = classified.filter((e) => e.kind !== 'bpf-map');
                  return (
                    <>
                      {bpfMaps.length > 0 && <> · missing maps: {bpfMaps.join(', ')}</>}
                      {captureIssues.length > 0 && (
                        <> · capture backend: {captureIssues.map((e) => (e.kind === 'afpacket-backend' ? 'AF_PACKET unavailable (needs CAP_NET_RAW)' : 'eBPF capture object not attached')).join(', ')}</>
                      )}
                    </>
                  );
                })()}
              </small>
            </div>
          ))}
        </div>
      </section>

      <section className="card span3">
        <p className="eyebrow">MULTI-CLUSTER</p>
        <h2 className="card-title">{(clusters?.clusters || clusters?.items || []).length} clusters</h2>
        <p>Read-only aggregator via <code>NETRA_FLEET_PEERS</code>. Observe-only.</p>
        <div className="list">
          {(clusters?.clusters || clusters?.items || []).length === 0 && <p className="empty-state">Only the local cluster is visible (no peers configured).</p>}
          {(clusters?.clusters || clusters?.items || []).map((c: any, i: number) => (
            <div className="agent wide" key={c.name || c.id || i}>
              <b>{c.name || c.id || `cluster ${i + 1}`}</b>
              <small>
                {[c.tenant, c.agentCount != null ? `${c.agentCount} agents` : '', c.staleAgents != null ? `${c.staleAgents} stale` : '', c.reachable === false ? 'unreachable' : '']
                  .filter(Boolean)
                  .join(' · ')}
              </small>
            </div>
          ))}
        </div>
      </section>

      <section className="card span3">
        <p className="eyebrow">TENANTS</p>
        <h2 className="card-title">{(tenants?.tenants || tenants?.items || []).length} tenant rollups</h2>
        <p>MSSP-style risk rollup from local + peer clusters. Full board also under Surfaces → Fleet.</p>
        <div className="list">
          {(tenants?.tenants || tenants?.items || []).length === 0 && <p className="empty-state">No tenant labels yet — set <code>NETRA_CLUSTER_TENANT</code> on peers.</p>}
          {(tenants?.tenants || tenants?.items || []).map((t: any, i: number) => (
            <div className="agent wide" key={t.tenant || t.name || i}>
              <b>{t.tenant || t.name || `tenant ${i + 1}`}</b>
              <span className="severity-badge info">{t.riskScore != null ? `risk ${t.riskScore}` : t.risk || '—'}</span>
              <small>
                {[t.clusterCount != null ? `${t.clusterCount} clusters` : '', t.agentCount != null ? `${t.agentCount} agents` : '']
                  .filter(Boolean)
                  .join(' · ')}
              </small>
            </div>
          ))}
        </div>
      </section>

      <section className="card span3">
        <p className="eyebrow">FLEET FLOW HISTORY</p>
        <h2 className="card-title">{flowRows.length} recent deltas across peers</h2>
        <p>
          Fan-out of <code>GET /api/v1/fleet/flows/history</code> via <code>NETRA_FLEET_PEERS</code>. Observe-only.
          CLI: <code>netractl fleet flows</code>.
        </p>
        <div className="chips">
          <button type="button" className="btn-secondary" onClick={() => navigate('flow-observe')}>
            Local flow observe →
          </button>
        </div>
        <div className="list">
          {flowRows.length === 0 && <p className="empty-state">No peer flow deltas yet (configure peers or wait for history).</p>}
          {flowRows.slice(0, 40).map((r: any, i: number) => (
            <div className="agent wide" key={i}>
              <b>
                {[r.cluster, r.namespace, r.pod].filter(Boolean).join('/') || r.node || `flow ${i + 1}`}
              </b>
              <small>
                {[
                  r.peer || r.destinationIp || r.dst,
                  r.port || r.destinationPort,
                  r.protocol,
                  r.packets != null ? `${r.packets} pkts` : '',
                  r.bytes != null ? `${r.bytes} B` : '',
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
