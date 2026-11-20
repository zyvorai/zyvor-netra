import { useMemo } from 'react';
import InvestigationFilters from '../components/InvestigationFilters';
import ConnectionTable from '../components/ConnectionTable';
import PagePulse from '../components/kit/PagePulse';
import { countTone } from '../components/kit/tone';
import { navigate, useRoute, useSnapshot } from '../hooks/useInvestigation';
import { eventRows, observedWorkloads, type Agent } from '../lib/investigation';
export default function ObservedWorkloads() {
  const { scope } = useRoute();
  const snapshot = useSnapshot<{ items: Agent[] }>('/api/v1/agents');
  const agents = snapshot.data?.items || [];
  const workloads = useMemo(() => observedWorkloads(agents, scope), [snapshot.data, scope]);
  const rows = useMemo(() => eventRows(agents, scope), [snapshot.data, scope]);
  const selected = scope.namespace && scope.pod;
  const namespaces = new Set(workloads.map((w) => w.namespace)).size;
  const nodes = new Set(workloads.map((w) => w.node)).size;
  const stale = agents.filter((a) => a.stale).length;
  const unattributed = rows.filter((e) => !e.pod).length;
  const have = snapshot.data !== undefined;
  return <div className="investigation">
    <PagePulse
      headline={have ? `${workloads.length} workload${workloads.length === 1 ? '' : 's'} across ${namespaces} namespace${namespaces === 1 ? '' : 's'}.` : undefined}
      tick={snapshot.data}
      error={snapshot.error}
      figures={[
        { label: 'workloads', value: have ? workloads.length : undefined },
        { label: 'namespaces', value: have ? namespaces : undefined },
        { label: 'nodes', value: have ? nodes : undefined },
        { label: 'stale agents', value: have ? stale : undefined, tone: have ? countTone(stale) : undefined },
        { label: 'unattributed events', value: have ? unattributed : undefined, tone: have && unattributed ? 'warn' : undefined },
      ]}
    />
    <InvestigationFilters traffic={false} />
    <section className="card"><div className="toolbar"><h2>{selected ? `${scope.namespace}/${scope.pod}` : 'Observed workloads'}</h2><button onClick={snapshot.refresh}>Refresh</button></div>
      <p>Identity from agent reports. This inventory includes observed pods and container cgroups; it does not establish guest-process identity inside VMs.</p>
      {snapshot.updatedAt && <p className="snapshot-time">Last successful fetch: {new Date(snapshot.updatedAt).toLocaleTimeString()}</p>}
      {snapshot.error && <p role="alert" className="warning">Refresh failed; any displayed data is from the last successful fetch. {snapshot.error}</p>}
      {snapshot.loading ? <p role="status">Loading workload identities…</p> : <>
        {!workloads.length && <p className="empty-state">No observed workload matches these filters. Check the namespace, pod, node, and agent reports.</p>}
        <div className="workload-cards">{workloads.slice(0, 100).map(w => {
          const agent = agents.find(a => a.node === w.node);
          return <article key={JSON.stringify([w.node, w.namespace, w.pod])} className="workload-card"><h3>{w.pod}</h3><p>{w.namespace} · {w.node}</p><p>Owner: {w.workloadKind && w.workloadName ? `${w.workloadKind}/${w.workloadName}` : 'Not reported'}</p><p>Agent: {agent?.stale === true ? 'Stale' : agent?.stale === false ? 'Reporting' : 'Freshness unknown'} · reported mode: {agent?.mode || 'Unknown'}</p><p className="snapshot-time">Agent report: {agent?.observedAt ? new Date(agent.observedAt).toLocaleString() : 'Unknown'}</p><button className="primary" onClick={() => navigate('workloads', { namespace: w.namespace || '', pod: w.pod || '', node: w.node || '', query: '' })}>Inspect workload</button></article>;
        })}</div>
        {workloads.length > 100 && <p>Showing 100 of {workloads.length} workloads. Narrow the filters to find a specific workload.</p>}
      </>}
    </section>
    {selected && <section className="card"><h2>Connection evidence</h2><p>Events for the selected identity. Traffic filters from Connections remain active when returning there.</p><div className="toolbar"><button onClick={() => navigate('connections')}>Open filtered connections</button><button onClick={() => navigate('ebpf')}>Review firewall</button></div><ConnectionTable rows={eventRows(agents, { ...scope, direction: '', protocol: '', action: '' })} /></section>}
    {!selected && rows.some(e => !e.pod) && <section className="card"><h2 className="card-title">Unattributed traffic</h2><p>Some sampled events have no pod identity. Inspect them in Connections instead of assigning them to a workload by IP.</p><button onClick={() => navigate('connections')}>Inspect connections</button></section>}
  </div>;
}
