import { useEffect, useMemo, useState } from 'react';
import { api } from '../api';
import DNSDiagnostics from '../components/DNSDiagnostics';
import ICMPDiagnostics from '../components/ICMPDiagnostics';
import ExplainFinding from '../components/ExplainFinding';
import NamespaceDrift from '../components/NamespaceDrift';
import ExeHashDrift from '../components/ExeHashDrift';
import { classifyMissingMaps, missingMapMessage } from '../lib/missingMaps';
import PagePulse from '../components/kit/PagePulse';
import RankedList from '../components/kit/RankedList';
import Section from '../components/kit/Section';
import { countTone, scoreTone } from '../components/kit/tone';
import { useSeries } from '../components/kit/useSeries';

const ms = (us: number | undefined) => ((us || 0) / 1000).toFixed((us || 0) >= 100000 ? 0 : 1);
const pct = (n: number, d: number) => d ? `${(n * 100 / d).toFixed(1)}%` : '0%';
const dur = (sec: number) => sec < 60 ? `${Math.round(sec)}s` : sec < 3600 ? `${Math.round(sec / 60)}m` : `${(sec / 3600).toFixed(1)}h`;

export default function Health() {
  const [data, setData] = useState<any>();
  const [summary, setSummary] = useState<any>();
  const [agents, setAgents] = useState<any[]>([]);
  const [capDrift, setCapDrift] = useState<any>();
  const [trend, setTrend] = useState<any>();
  const [err, setErr] = useState('');
  const load = () => Promise.all([
    api<any>('/api/v1/ebpf/health?limit=50'),
    api<any>('/api/v1/ebpf/summary'),
    api<any>('/api/v1/agents'),
    api<any>('/api/v1/ebpf/capdrift'),
    api<any>('/api/v1/insights/health-trend'),
  ]).then(([x, s, a, cd, tr]) => { setData(x); setSummary(s); setAgents(a.items || []); setCapDrift(cd); setTrend(tr); setErr(''); }).catch(e => setErr(String(e)));
  useEffect(() => { load(); const t = setInterval(load, 5000); return () => clearInterval(t); }, []);
  const s = data?.summary || {};
  const anomalies = data?.summary?.anomalies || [];
  const scoreSeries = useSeries(data ? (s.healthScore ?? 100) : undefined, data);
  const retransSeries = useSeries(data ? (s.tcpRetransmissions || 0) : undefined, data);
  const dnsFailRate = s.dnsResponses ? (s.dnsFailures || 0) / s.dnsResponses : 0;
  const drops = (field: string) => agents.flatMap((a: any) => (a[field] || []).map((c: any) => ({ ...c, node: a.node }))).sort((a: any, b: any) => (b.count || 0) - (a.count || 0));
  const icmpRows = agents.flatMap((a: any) => [
    ...(a.icmpTypes || []).map((c: any) => ({ ...c, node: a.node, fam: 'icmp' })),
    ...(a.icmp6Types || []).map((c: any) => ({ ...c, node: a.node, fam: 'icmp6' })),
  ]).sort((a: any, b: any) => (b.count || 0) - (a.count || 0));
  const resetRows = useMemo(() => (data?.signals || []).filter((x:any) => x.rst > 0).sort((a:any,b:any)=>b.rst-a.rst).slice(0,50), [data]);

  return <div className="grid">
    <PagePulse
      headline={data ? (anomalies.length ? `${anomalies.length} health signal${anomalies.length === 1 ? '' : 's'} in the latest reports.` : `Health ${s.healthScore ?? 100}/100 — TCP and DNS look normal.`) : undefined}
      tone={data && anomalies.length ? 'warn' : undefined}
      tick={data}
      error={err || undefined}
      figures={[
        { label: 'health score /100', value: data ? (s.healthScore ?? 100) : undefined, tone: data ? scoreTone(s.healthScore ?? 100) : undefined, series: scoreSeries },
        { label: 'avg SRTT', value: data ? `${ms(s.averageSrttUs)} ms` : undefined },
        { label: 'retransmits', value: data ? (s.tcpRetransmissions || 0) : undefined, series: retransSeries },
        { label: 'DNS failure rate', value: data ? pct(s.dnsFailures || 0, s.dnsResponses || 0) : undefined, tone: data ? (dnsFailRate > 0.05 ? 'warn' : 'ok') : undefined },
        { label: 'est. TCP failures', value: data ? (s.estimatedConnectFailures || 0) : undefined, tone: data ? countTone(s.estimatedConnectFailures || 0) : undefined },
      ]}
    />
    {err && <section className="card span3"><p className="warning">{err}</p></section>}

    <Section eyebrow="TCP pulse" title="Sockops connection health" span={2}>
      <div className="metrics">
        <div><b>{s.tcpConnections || 0}</b><span>connections</span></div>
        <div><b>{ms(s.averageSrttUs)} ms</b><span>avg SRTT</span></div>
        <div><b>{s.tcpRetransmissions || 0}</b><span>retransmits</span></div>
        <div><b>{s.tcpRtos || 0}</b><span>RTOs</span></div>
        <div><b>{s.tcpResets || 0}</b><span>RST packets</span></div><div><b>{s.healthScore ?? 100}</b><span>health score /100</span></div><div><b>{s.connectionAttempts || 0}</b><span>socket attempts</span></div><div><b>{s.estimatedConnectFailures || 0}</b><span>est. TCP failures</span></div>
      </div>
    </Section>

    <Section eyebrow="Trend" title="Health-score projection" span={1}
      about={<p>A linear heuristic over recent health-score samples — never a statistical guarantee. Confidence is at most "medium", never "high". History accumulates only while something polls the controller (this page, netra-mcp, or the alert poller).</p>}>
      {trend?.timeToBreachSeconds != null ? (
        <div className="metrics">
          <div><b>{dur(trend.timeToBreachSeconds)}</b><span>to breach {trend.breachThreshold}/100</span></div>
          <div><b>{trend.currentScore}</b><span>current score</span></div>
          <div><b>{trend.confidence}</b><span>confidence</span></div>
          <div><b>{trend.samples}</b><span>samples</span></div>
        </div>
      ) : <p className="empty-state">{trend?.note || 'No trend projection yet.'}</p>}
    </Section>

    <Section eyebrow="DNS pulse" title={`${pct(s.dnsFailures || 0, s.dnsResponses || 0)} of matched answers failed`} tone={data ? (dnsFailRate > 0.05 ? 'warn' : 'ok') : undefined}
      about={<p>DNS timing covers matched plain UDP/53 transactions only; DoH, DoT and TCP DNS are intentionally not inferred.</p>}>
      <div className="metrics">
        <div><b>{s.dnsQueries || 0}</b><span>queries</span></div>
        <div><b>{s.dnsResponses || 0}</b><span>matched responses</span></div>
        <div><b>{s.dnsFailures || 0}</b><span>rcode failures</span></div>
        <div><b>{ms(s.averageDnsLatencyUs)} ms</b><span>avg latency</span></div>
        <div><b>{ms(s.maxDnsLatencyUs)} ms</b><span>max latency</span></div>
      </div>
    </Section>

    <Section eyebrow="UDP pulse" title="Flows beyond DNS" span={2}
      about={<p>Cgroup-attributed UDP flow counters beyond DNS. No send-failure signal is tracked: no BPF hook Netra attaches can see a UDP send fail after the fact.</p>}>
      <div className="metrics">
        <div><b>{s.udpFlows || 0}</b><span>flows</span></div>
        <div><b>{s.udpPackets || 0}</b><span>packets</span></div>
        <div><b>{s.udpBytes || 0}</b><span>bytes</span></div>
      </div>
    </Section>

    <Section eyebrow="QUIC observed" title="UDP/443 long-header traffic" span={1}
      about={<p>A traffic-observation heuristic on UDP/443 packets matching RFC 9000's long-header wire form — <b>not SNI extraction</b>. Full QUIC SNI parsing is infeasible in BPF: RFC 9001 mandatorily applies header protection to Initial packets, requiring crypto helpers (HKDF-SHA256, AES-128/ChaCha20) that don't exist in BPF.</p>}>
      <div className="metrics">
        <div><b>{s.quicObservedFlows || 0}</b><span>UDP/443 flows</span></div>
        <div><b>{s.quicLongHeaderPackets || 0}</b><span>long-header packets</span></div>
      </div>
    </Section>

    <DNSDiagnostics agents={agents} />

    {agents.some((a: any) => (a.missingMaps || []).length) && (
      <section className="card span3">
        <p className="eyebrow">BPF OBJECT</p>
        <h2 className="card-title">Agent maps missing</h2>
        {agents.filter((a: any) => (a.missingMaps || []).length).map((a: any) => {
          const classified = classifyMissingMaps(a.missingMaps || []);
          const byKind = new Map<string, string[]>();
          for (const e of classified) byKind.set(e.kind, [...(byKind.get(e.kind) || []), e.raw]);
          return (
            <div className="agent wide" key={a.node}>
              <b>{a.node}</b>
              {[...byKind.entries()].map(([kind, raws]) => (
                <small key={kind}>
                  {missingMapMessage(kind as any)} <i>({raws.join(', ')})</i>
                </small>
              ))}
              <ExplainFinding page="health" kind="bpf-maps-missing" subject={a.node} message={(a.missingMaps || []).join(', ')} />
            </div>
          );
        })}
      </section>
    )}
    <Section eyebrow="Rate drops" title="PPS ceilings that actually fired" span={1}>
      <RankedList empty="No destination has been rate-dropped yet." limit={16} items={drops('rateDrops').map((c: any, i: number) => ({ key: c.node + c.name + i, name: c.name, count: c.count || 0, tone: 'bad' as const, detail: `${c.node} · dropped`, action: <ExplainFinding page="health" kind="rate-drop" subject={c.name} message={`${c.count} dropped at ${c.node}`} /> }))} />
    </Section>
    <Section eyebrow="Byte-rate drops" title="BPS ceilings that actually fired" span={1}>
      <RankedList empty="No destination has hit its byte-rate cap yet." limit={16} items={drops('byteRateDrops').map((c: any, i: number) => ({ key: c.node + c.name + i, name: c.name, count: c.count || 0, tone: 'bad' as const, detail: `${c.node} · dropped` }))} />
    </Section>
    <Section eyebrow="Connection-rate drops" title="New-TCP-connection caps that fired" span={1}>
      <RankedList empty="No workload has hit its connection-rate cap yet." limit={16} items={drops('connRateDrops').map((c: any, i: number) => ({ key: c.node + c.name + i, name: c.name, count: c.count || 0, tone: 'bad' as const, detail: `${c.node} · dropped` }))} />
    </Section>
    <section className="card span3">
      <p className="eyebrow">CAPABILITY DRIFT</p>
      <h2 className="card-title">Effective-capability changes on tracked processes</h2>
      <p>Agent-sourced from a periodic /proc scan (requires NETRA_PROCMETA_ENABLED) — not a live kernel credential read. A capability change during an agent restart window is a known blind spot, surfaced below as its own finding rather than silently missed.</p>
      <div className="list">
        {(capDrift?.anomalies || []).length === 0 && <p className="empty-state">No capability drift observed yet.</p>}
        {(capDrift?.anomalies || []).slice(0, 25).map((a: any, i: number) => (
          <div className="agent wide" key={i}>
            <b>{a.kind}</b><span className={`severity-badge ${a.severity}`}>{a.severity}</span><span>{a.subject}</span><small>{a.message}</small>
          </div>
        ))}
      </div>
    </section>
    <NamespaceDrift />
    <ExeHashDrift />
    <Section eyebrow="ICMP pulse" title="Type histogram from the packet path" lede="Observe-only. Cumulative since the map was last created. No ICMP payload is exported.">
      <RankedList
        limit={20}
        empty="No ICMP types recorded yet. Rebuild the agent BPF object so icmp_type_stats exists."
        items={icmpRows.map((c: any, i: number) => ({
          key: c.node + c.fam + c.name + i,
          name: `${c.fam}/${c.name}`,
          count: c.count || 0,
          detail: c.node,
          action: <ExplainFinding page="health" kind={`icmp:${c.name}`} subject={c.node} message={`${c.count} ${c.fam} ${c.name}`} />,
        }))}
      />
    </Section>

    <ICMPDiagnostics agents={agents} />

    <section className="card span3">
      <p className="eyebrow">HEALTH SIGNALS</p>
      <h2 className="card-title">Heuristic anomalies</h2>
      <p>These are deterministic operational thresholds, not ML/statistical anomaly claims.</p>
      <div className="list">
        {anomalies.length === 0 && <p className="empty-state">No threshold-based network health signals in the latest reports.</p>}
        {anomalies.slice(0, 25).map((a:any, i:number) => <div className="agent wide" key={i}><b>{a.kind}</b><span className={`severity-badge ${a.severity}`}>{a.severity}</span><span>{a.subject}</span><small>{a.message}</small><ExplainFinding page="health" kind={a.kind} subject={a.subject} message={a.message} severity={a.severity} /></div>)}
        {anomalies.length > 25 && <p className="empty-state">+{anomalies.length - 25} more not shown.</p>}
      </div>
    </section>

    <section className="card span3">
      <p className="eyebrow">TCP HEALTH</p>
      <h2 className="card-title">Sockops exact state</h2>
      {(data?.tcp || []).length === 0 && <p className="empty-state">No TCP sockops samples yet.</p>}
      {(data?.tcp || []).length > 0 && <div className="datatable-scroll">
        <div className="datahead obs"><span>WORKLOAD / PROCESS</span><span>REMOTE</span><span>RTT</span><span>LOSS SIGNALS</span><span>CONNECTION</span></div>
        {(data?.tcp || []).map((t:any, i:number) => {
          const who = `${t.namespace ? `${t.namespace}/${t.pod}` : (t.comm || `cgroup ${t.cgroupId || 0}`)}${t.pid ? ` · pid=${t.pid}` : ''}${t.exe ? ` · ${t.exe}` : ''}${t.ownershipStale ? ' · stale-owner' : ''}`;
          return <div className="datarow obs" key={i}>
            <span className="truncate" title={who} aria-label={who}>{who}</span>
            <span>{t.remoteIp}:{t.remotePort}</span>
            <span>{ms(t.srttUs)} ms · min {ms(t.minRttUs)} ms</span>
            <span>retrans {t.retransmissions} · RTO {t.rtos}</span>
            <span>active {t.activeEstablished} · passive {t.passiveEstablished} · close {t.closes}</span>
          </div>;
        })}
      </div>}
    </section>

    <section className="card span3">
      <p className="eyebrow">DNS HEALTH</p>
      <h2 className="card-title">Matched UDP/53 transactions</h2>
      {(data?.dns || []).length === 0 && <p className="empty-state">No DNS transactions matched yet.</p>}
      {(data?.dns || []).length > 0 && <div className="datatable-scroll">
        <div className="datahead obs"><span>WORKLOAD</span><span>NAME</span><span>QUERIES</span><span>FAILURES</span><span>LATENCY</span></div>
        {(data?.dns || []).map((d:any, i:number) => {
          const who = d.namespace ? `${d.namespace}/${d.pod}` : `cgroup ${d.cgroupId || 0}`;
          return <div className="datarow obs" key={i}>
            <span className="truncate" title={who} aria-label={who}>{who}</span>
            <span className="truncate" title={d.name} aria-label={d.name}>{d.name}</span>
            <span>{d.queries} / {d.responses} matched</span>
            <span>{d.failures} · {pct(d.failures, d.responses)}</span>
            <span>avg {ms(d.responses ? d.totalLatencyUs / d.responses : 0)} ms · max {ms(d.maxLatencyUs)} ms</span>
          </div>;
        })}
      </div>}
    </section>

    <section className="card span3">
      <p className="eyebrow">UDP FLOW HEALTH</p>
      <h2 className="card-title">Packets/bytes per remote endpoint</h2>
      {(data?.udp || []).length === 0 && <p className="empty-state">No cgroup-attributed UDP flows observed yet.</p>}
      {(data?.udp || []).length > 0 && <div className="datatable-scroll">
        <div className="datahead obs"><span>WORKLOAD</span><span>REMOTE</span><span>PACKETS</span><span>BYTES</span></div>
        {(data?.udp || []).map((u:any, i:number) => {
          const who = u.namespace ? `${u.namespace}/${u.pod}` : `cgroup ${u.cgroupId || 0}`;
          return <div className="datarow obs" key={i}>
            <span className="truncate" title={who} aria-label={who}>{who}</span>
            <span>{u.remoteIp}:{u.remotePort}</span>
            <span>{u.packets}</span>
            <span>{u.bytes}</span>
          </div>;
        })}
      </div>}
    </section>

    <section className="card span3">
      <p className="eyebrow">QUIC-OBSERVED FLOWS</p>
      <h2 className="card-title">UDP/443 long-header packets by remote endpoint</h2>
      {(data?.quic || []).length === 0 && <p className="empty-state">No QUIC-observed traffic yet.</p>}
      {(data?.quic || []).length > 0 && <div className="datatable-scroll">
        <div className="datahead obs"><span>WORKLOAD</span><span>REMOTE</span><span>LONG-HEADER</span><span>TOTAL UDP/443</span></div>
        {(data?.quic || []).map((q:any, i:number) => {
          const who = q.namespace ? `${q.namespace}/${q.pod}` : `cgroup ${q.cgroupId || 0}`;
          return <div className="datarow obs" key={i}>
            <span className="truncate" title={who} aria-label={who}>{who}</span>
            <span>{q.remoteIp}:{q.remotePort}</span>
            <span>{q.longHeaderPackets}</span>
            <span>{q.packets}</span>
          </div>;
        })}
      </div>}
    </section>

    <section className="card span3">
      <p className="eyebrow">TCP RESET SIGNALS</p>
      <h2 className="card-title">Handshake / reset counters</h2>
      {resetRows.length === 0 && <p className="empty-state">No TCP reset signals in the latest reports.</p>}
      {resetRows.length > 0 && <div className="datatable-scroll">
        <div className="datahead obs"><span>WORKLOAD</span><span>SYN</span><span>SYN-ACK</span><span>FIN</span><span>RST / PACKETS</span></div>
        {resetRows.map((r:any, i:number) => {
          const who = r.namespace ? `${r.namespace}/${r.pod}` : `cgroup ${r.cgroupId || 0}`;
          return <div className="datarow obs" key={i}>
            <span className="truncate" title={who} aria-label={who}>{who}</span>
            <span>{r.syn}</span><span>{r.synAck}</span><span>{r.fin}</span><span>{r.rst} / {r.packets}</span>
          </div>;
        })}
      </div>}
    </section>

    <Section eyebrow="Kernel pulse" title="What Netra sees">
      <div className="metrics">
        <div><b>{summary?.packets ?? 0}</b><span>packets</span></div>
        <div><b>{summary?.blocked ?? 0}</b><span>blocked</span></div>
        <div><b>{summary?.dnsQueries ?? 0}</b><span>DNS</span></div>
        <div><b>{summary?.socketEvents ?? 0}</b><span>socket events</span></div>
      </div>
      <div className="kit-ranked-grid">
        <RankedList title="Hooks" mono={false} limit={6} empty="No hook counters yet." items={Object.entries((summary?.hooks || {}) as Record<string, number>).map(([name, count]) => ({ name, count }))} />
        <RankedList title="Top workloads" limit={6} empty="No workload breakdown yet." items={summary?.topWorkloads || []} />
        <RankedList title="Top processes" mono={false} limit={6} empty="No process breakdown yet." items={summary?.topProcesses || []} />
        <RankedList title="Top DNS" limit={6} empty="No cleartext DNS yet." items={summary?.topDns || []} />
        <RankedList title="Block reasons" mono={false} limit={6} empty="Nothing blocked." items={(summary?.blockReasons || []).map((x: any) => ({ ...x, tone: 'bad' as const }))} />
        <RankedList title="Top blocked workloads" limit={6} empty="No blocked workloads." items={(summary?.topBlockedWorkloads || []).map((x: any) => ({ ...x, tone: 'bad' as const }))} />
      </div>
    </Section>
    <section className="card span2"><p className="eyebrow">BPF PROGRAM HEALTH</p><h2 className="card-title">Attach state and run stats</h2><p>Per-node program attach flags plus kernel run counts when BPF stats are enabled. Use this when a hook is missing after upgrade or verifier load failures.</p>{agents.map(a => <div className="agent wide" key={'prog-'+a.node}><b>{a.node}</b><span>{a.stale ? 'stale' : `${(a.programs || []).filter((p:any)=>p.attached).length}/${(a.programs || []).length} attached`}</span><small>{(a.programs || []).length === 0 ? 'no program report yet' : (a.programs || []).map((p:any) => `${p.name}${p.attached ? '' : ' (detached)'}: runs=${p.runCount || 0}`).join(' · ')}</small></div>)}</section>
    <section className="card span3"><p className="eyebrow">NETWORK HISTOGRAMS</p><h2 className="card-title">Retransmit / RTT / connect buckets</h2><p>Agent-side histograms from existing sockops samples, plus listen overflow and softirq NET_RX counters. Softirq entry→exit latency remains deferred.</p>{agents.map(a => {
      const h = a.histograms;
      if (!h) return <div className="agent wide" key={'hist-'+a.node}><b>{a.node}</b><span>—</span></div>;
      return <div className="agent wide" key={'hist-'+a.node}><b>{a.node}</b><span>retrans n={h.tcpRetransmissions?.count || 0} · srtt n={h.tcpSrttUs?.count || 0} · connect n={h.tcpConnectUs?.count || 0}</span><small>listen overflows={h.host?.listenOverflows || 0} · listen drops={h.host?.listenDrops || 0} · softirq NET_RX={h.host?.softirqNetRx || 0}</small></div>;
    })}</section>
  </div>;
}
