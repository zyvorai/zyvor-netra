import { useMemo, useState } from 'react';
import InvestigationFilters from '../components/InvestigationFilters';
import ConnectionTable from '../components/ConnectionTable';
import PagePulse from '../components/kit/PagePulse';
import { countTone } from '../components/kit/tone';
import { useSeries } from '../components/kit/useSeries';
import { useRoute, useSnapshot } from '../hooks/useInvestigation';
import { eventRows, type Agent } from '../lib/investigation';
export default function Connections() {
  const [paused, setPaused] = useState(false);
  const { scope } = useRoute();
  const snapshot = useSnapshot<{ items: Agent[] }>('/api/v1/agents', paused);
  const agents = snapshot.data?.items || [];
  const rows = useMemo(() => eventRows(agents, scope), [snapshot.data, scope]);
  const blocked = rows.filter((r) => r.action === 'blocked').length;
  const stale = agents.filter((a) => a.stale).length;
  const pods = new Set(rows.filter((r) => r.pod).map((r) => `${r.namespace}/${r.pod}`)).size;
  const eventSeries = useSeries(snapshot.data ? rows.length : undefined, snapshot.data);
  const blockedSeries = useSeries(snapshot.data ? blocked : undefined, snapshot.data);
  const headline = !snapshot.data ? undefined : blocked ? `${blocked} of ${rows.length} sampled events were blocked.` : rows.length ? `${rows.length} sampled events, none blocked.` : 'No sampled events in this view.';
  return <div className="investigation">
    <PagePulse
      headline={headline}
      tone={blocked ? 'warn' : undefined}
      tick={snapshot.data}
      error={snapshot.error}
      paused={paused}
      figures={[
        { label: 'sampled events', value: snapshot.data ? rows.length : undefined, series: eventSeries },
        { label: 'blocked', value: snapshot.data ? blocked : undefined, tone: snapshot.data ? countTone(blocked) : undefined, series: blockedSeries },
        { label: 'workloads seen', value: snapshot.data ? pods : undefined },
        { label: 'agents reporting', value: snapshot.data ? `${agents.length - stale} / ${agents.length}` : undefined, tone: stale ? 'warn' : undefined },
      ]}
    />
    <InvestigationFilters /><section className="card"><div className="toolbar"><h2>Native connections</h2><button onClick={() => setPaused(p => !p)}>{paused ? 'Resume updates' : 'Pause updates'}</button><button disabled={paused} onClick={snapshot.refresh}>Refresh</button></div>
    <p>Recent sampled events from Netra agents. Refreshes every 10 seconds. {paused ? 'Updates paused.' : ''}</p>
    {snapshot.updatedAt && <p className="snapshot-time">Last successful fetch: {new Date(snapshot.updatedAt).toLocaleTimeString()}. Event times and agent freshness appear below.</p>}
    {snapshot.error && <p role="alert" className="warning">Refresh failed. Any displayed data is from the last successful fetch. {snapshot.error}</p>}
    {snapshot.loading ? <p role="status">Loading agent reports…</p> : <ConnectionTable rows={rows} />}
  </section></div>;
}
