import { useEffect, useMemo, useState } from 'react';
import { api } from '../api';
import ExplainFinding from '../components/ExplainFinding';
import PagePulse from '../components/kit/PagePulse';
import { countTone } from '../components/kit/tone';
import { useSeries } from '../components/kit/useSeries';

const ms = (us:number|undefined) => ((us||0)/1000).toFixed((us||0)>=100000?0:1);
const pct = (n:number,d:number) => d ? `${(n*100/d).toFixed(0)}%` : '0%';
const nsToMs = (ns:number|undefined) => ((ns||0)/1e6).toFixed((ns||0)>=1e8?0:1);

// Summarizes edge-intel bucket arrays ({count,totalNs,maxNs}[]) into a
// single count/avg/max view — the buckets themselves are a log2-us
// histogram, not something worth rendering bucket-by-bucket here.
function edgeBucketSummary(buckets: any[] | undefined) {
  let count = 0, totalNs = 0, maxNs = 0;
  for (const b of buckets || []) {
    count += b.count || 0;
    totalNs += b.totalNs || 0;
    if ((b.maxNs || 0) > maxNs) maxNs = b.maxNs || 0;
  }
  return { count, avgNs: count ? totalNs / count : 0, maxNs };
}

export default function Path(){
  const [data,setData]=useState<any>(); const [err,setErr]=useState('');
  const load=()=>api<any>('/api/v1/ebpf/path?limit=100').then(x=>{setData(x);setErr('')}).catch(e=>setErr(String(e)));
  useEffect(()=>{load();const t=setInterval(load,5000);return()=>clearInterval(t)},[]);
  const s=data?.summary||{}; const anomalies=s.anomalies||[];
  const pressure=useMemo(()=>data?.pressure||[],[data]); const connect=useMemo(()=>data?.connect||[],[data]);
  const edge=data?.edgeIntel||{}; const edgeCounts=edge.counts||{};
  const edgeHandshake=useMemo(()=>edgeBucketSummary(edge.handshake),[edge]);
  const edgeRTT=useMemo(()=>edgeBucketSummary(edge.rtt),[edge]);
  const connectSeries=useSeries(data?(s.averageConnectUs||0)/1000:undefined,data);
  const flightSeries=useSeries(data?(s.packetsOut||0):undefined,data);
  const congested=s.congestedFlows||0;
  return <div className="grid">
    <PagePulse
      headline={data?(congested?`${congested} flow${congested===1?'':'s'} under congestion-window pressure.`:anomalies.length?`${anomalies.length} path signal${anomalies.length===1?'':'s'} raised.`:'Connects are clean — no transport pressure.'):undefined}
      tone={data&&(congested||anomalies.length)?'warn':undefined}
      tick={data}
      error={err||undefined}
      figures={[
        {label:'connects timed',value:data?(s.connectionsMeasured||0):undefined},
        {label:'avg connect',value:data?(s.averageConnectUs||0)/1000:undefined,format:(n)=>`${n.toFixed(n>=100?0:1)} ms`,series:connectSeries},
        {label:'max connect',value:data?`${ms(s.maxConnectUs)} ms`:undefined},
        {label:'cwnd-pressure flows',value:data?congested:undefined,tone:data?countTone(congested):undefined},
        {label:'retrans / lost out',value:data?`${s.retransOut||0} / ${s.lostOut||0}`:undefined,tone:data&&((s.retransOut||0)+(s.lostOut||0))?'warn':undefined},
        {label:'packets in flight',value:data?(s.packetsOut||0):undefined,series:flightSeries},
      ]}
    />
    {err&&<section className="card span3"><p className="warning">{err}</p></section>}
    <section className="card span3"><p className="eyebrow">PATH SIGNALS</p><h2 className="card-title">Transport-pressure findings</h2><p>Threshold-based diagnostics only. Netra does not infer router/interface drop reasons from these counters.</p><div className="list">{anomalies.length===0&&<p className="empty-state">No current path-pressure thresholds triggered.</p>}{anomalies.slice(0,25).map((a:any,i:number)=><div className="agent wide" key={i}><b>{a.kind}</b><span className={`severity-badge ${a.severity}`}>{a.severity}</span><span>{a.subject}</span><small>{a.message}</small><ExplainFinding page="path" kind={a.kind} subject={a.subject} message={a.message} severity={a.severity} /></div>)}{anomalies.length>25&&<p className="empty-state">+{anomalies.length-25} more not shown.</p>}</div></section>
    <section className="card span3">
      <p className="eyebrow">TCP PRESSURE</p><h2 className="card-title">Exact sockops transport state</h2>
      {pressure.length===0 && <p className="empty-state">No TCP pressure samples yet.</p>}
      {pressure.length>0 && <div className="datatable-scroll">
        <div className="datahead obs"><span>WORKLOAD</span><span>REMOTE</span><span>CWND / FLIGHT</span><span>LOSS</span><span>DELIVERY</span></div>
        {pressure.map((p:any,i:number)=>{
          const who = p.namespace?`${p.namespace}/${p.pod}`:`cgroup ${p.cgroupId||0}`;
          return <div className="datarow obs" key={i}><span className="truncate" title={who} aria-label={who}>{who}</span><span>{p.remoteIp}:{p.remotePort}</span><span>{p.packetsOut}/{p.sendCwnd} · {pct(p.packetsOut,p.sendCwnd)}</span><span>lost {p.lostOut} · retrans-out {p.retransOut} · total {p.totalRetrans}</span><span>{p.rateIntervalUs?Math.round(p.rateDelivered*1000000/p.rateIntervalUs):0} pkt/s · MSS {p.mss||0}</span></div>;
        })}
      </div>}
    </section>
    <section className="card span3">
      <p className="eyebrow">TCP CONNECT</p><h2 className="card-title">Establishment latency</h2>
      {connect.length===0 && <p className="empty-state">No TCP connect samples yet.</p>}
      {connect.length>0 && <div className="datatable-scroll">
        <div className="datahead obs"><span>WORKLOAD</span><span>REMOTE</span><span>ESTABLISHED</span><span>AVG</span><span>MAX</span></div>
        {connect.map((c:any,i:number)=>{
          const who = c.namespace?`${c.namespace}/${c.pod}`:`cgroup ${c.cgroupId||0}`;
          return <div className="datarow obs" key={i}><span className="truncate" title={who} aria-label={who}>{who}</span><span>{c.remoteIp}:{c.remotePort}</span><span>{c.established}</span><span>{ms(c.established?c.totalLatencyUs/c.established:0)} ms</span><span>{ms(c.maxLatencyUs)} ms</span></div>;
        })}
      </div>}
    </section>
    <section className="card span3">
      <p className="eyebrow">EDGE TCP INTEL</p><h2 className="card-title">Edge-observed handshake &amp; RTT (TCX, pre-NAT-visible)</h2>
      <p>Distinct from the socket-observed TCP pressure/connect data above (sockops, post-NAT): this comes from a passive TCX observer that also sees forwarded/NAT'd flows the local socket layer never attaches to. Off unless the agent's edge-intel BPF object attached (<code>NETRA_EDGE_INTEL</code>).</p>
      {!data?.edgeIntel && <p className="empty-state">No edge-intel data reported — likely off or unattached on every node.</p>}
      {data?.edgeIntel && <div className="metrics">
        <div><b>{edgeHandshake.count}</b><span>handshakes timed</span></div>
        <div><b>{nsToMs(edgeHandshake.avgNs)} ms</b><span>avg handshake</span></div>
        <div><b>{nsToMs(edgeHandshake.maxNs)} ms</b><span>max handshake</span></div>
        <div><b>{edgeRTT.count}</b><span>RTT samples</span></div>
        <div><b>{nsToMs(edgeRTT.avgNs)} ms</b><span>avg RTT</span></div>
        <div><b>{nsToMs(edgeRTT.maxNs)} ms</b><span>max RTT</span></div>
        <div><b>{edgeCounts.retransmit||0}</b><span>retransmits</span></div>
        <div><b>{edgeCounts.rst||0}</b><span>RSTs</span></div>
        <div><b>{edgeCounts.fin||0}</b><span>FINs</span></div>
        <div><b>{edgeCounts.flowMiss||0}</b><span>flow-table misses</span></div>
      </div>}
    </section>
  </div>
}
