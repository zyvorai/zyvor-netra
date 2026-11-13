import { useEffect, useMemo, useState } from 'react';
import { api } from '../api';
import ExplainFinding from '../components/ExplainFinding';
import PagePulse from '../components/kit/PagePulse';
import { countTone } from '../components/kit/tone';
import { useSeries } from '../components/kit/useSeries';

export default function Drops() {
  const [data, setData] = useState<any>();
  const [diag, setDiag] = useState<any>();
  const [kernel, setKernel] = useState<any>();
  const [dropInfo, setDropInfo] = useState<any>();
  const [tcpEvents, setTcpEvents] = useState<any>();
  const [kernelWindow, setKernelWindow] = useState('5m');
  const [err, setErr] = useState('');
  const load = () =>
    Promise.all([
      api<any>('/api/v1/ebpf/drops?limit=100'),
      api<any>('/api/v1/ebpf/diagnose?limit=50'),
      api<any>(`/api/v1/ebpf/kernel-network?window=${encodeURIComponent(kernelWindow)}`),
      api<any>('/api/v1/ebpf/drop-info').catch(() => null),
      api<any>('/api/v1/ebpf/tcp-events').catch(() => null),
    ])
    .then(([d, x, k, di, te]) => {
      setData(d);
      setDiag(x);
      setKernel(k);
      setDropInfo(di);
      setTcpEvents(te);
      setErr('');
    })
    .catch((e) => setErr(String(e)));
  useEffect(() => {
    load();
    const t = setInterval(load, 5000);
    return () => clearInterval(t);
  }, [kernelWindow]);
  const s = data?.summary || {};
  const nodes = useMemo(() => data?.nodes || [], [data]);
  const anomalies = s.anomalies || [];
  const findings = diag?.findings || [];
  const ds = diag?.summary || {};
  const ks = kernel?.summary || {};
  const totalDrops = (s.kernelDropEvents || 0) + (s.softnetDropped || 0) + (s.rxDropped || 0) + (s.txDropped || 0) + (s.qdiscDrops || 0);
  const kernelSeries = useSeries(data ? (s.kernelDropEvents || 0) : undefined, data);
  return (
    <div className="grid">
      {err && (
        <section className="card span3">
          <p className="warning">{err}</p>
        </section>
      )}
      <PagePulse
        headline={data ? (totalDrops ? `${totalDrops.toLocaleString()} packets dropped across the stack.` : 'No packets going missing.') : undefined}
        tone={data && totalDrops ? 'warn' : undefined}
        tick={data}
        error={err || undefined}
        figures={[
          { label: 'kernel skb drops', value: data ? (s.kernelDropEvents || 0) : undefined, tone: data ? countTone(s.kernelDropEvents || 0) : undefined, series: kernelSeries },
          { label: 'softnet dropped', value: data ? (s.softnetDropped || 0) : undefined, tone: data ? countTone(s.softnetDropped || 0) : undefined },
          { label: 'policy-drop packets', value: diag ? (ds.policyDropPackets || 0) : undefined, tone: diag ? countTone(ds.policyDropPackets || 0) : undefined },
          { label: 'iface rx / tx dropped', value: data ? `${s.rxDropped || 0} / ${s.txDropped || 0}` : undefined, tone: data && ((s.rxDropped || 0) + (s.txDropped || 0)) ? 'warn' : undefined },
          { label: 'qdisc drops', value: data ? (s.qdiscDrops || 0) : undefined, tone: data ? countTone(s.qdiscDrops || 0) : undefined },
          { label: 'conntrack entries', value: diag ? (ds.conntrackEntries || 0) : undefined },
          { label: 'exact / probable findings', value: diag ? `${ds.exactFindings || 0} / ${ds.probableFindings || 0}` : undefined },
        ]}
      />
      {ds.text && <p className="kit-caption span3">{ds.text}</p>}
      <section className="card span3">
        <p className="eyebrow">DROP INFO · KERNEL SITES</p>
        <h2 className="card-title">
          {dropInfo?.totals?.drops ?? 0} attributed drops
          {dropInfo?.nodesNotReporting ? ` · ${dropInfo.nodesNotReporting} nodes not reporting` : ''}
        </h2>
        <p>bpf drop-info attribution (reason + kernel function). Sensor may be off on some nodes.</p>
        <div className="list">
          {!(dropInfo?.reasons || []).length && <p className="empty-state">No drop-info reasons yet (sensor off or quiet).</p>}
          {(dropInfo?.reasons || []).slice(0, 12).map((r: any, i: number) => (
            <div className="agent wide" key={i}>
              <b>{r.reason || 'reason'}</b>
              <small>n={r.count ?? 0}</small>
            </div>
          ))}
          {(dropInfo?.flows || []).slice(0, 8).map((f: any, i: number) => (
            <div className="agent wide" key={`f-${i}`}>
              <b>
                {f.src}:{f.srcPort} → {f.dst}:{f.dstPort}
              </b>
              <span className="severity-badge warning">{f.reason || 'drop'}</span>
              <small>
                {[f.node, f.location, f.count != null ? `n=${f.count}` : ''].filter(Boolean).join(' · ')}
              </small>
            </div>
          ))}
        </div>
      </section>
      <section className="card span3">
        <p className="eyebrow">TCP EVENTS</p>
        <h2 className="card-title">Retransmits / RST / state transitions</h2>
        <p>Observe-only TCP tracepoint ring. May 409 when the sensor is disabled.</p>
        <div className="list">
          {!(tcpEvents?.events || tcpEvents?.items || []).length && <p className="empty-state">No TCP events in the ring (or sensor off).</p>}
          {(tcpEvents?.events || tcpEvents?.items || []).slice(0, 12).map((e: any, i: number) => (
            <div className="agent wide" key={i}>
              <b>{e.type || e.kind || e.state || 'tcp'}</b>
              <small>
                {[e.node, e.comm, e.dst || e.peer, e.count != null ? `n=${e.count}` : ''].filter(Boolean).join(' · ')}
              </small>
            </div>
          ))}
        </div>
      </section>
      <section className="card span3">
        <p className="eyebrow">KERNEL NETWORK PRESSURE</p>
        <h2 className="card-title">Buffers, queues, and congestion</h2>
        <div className="metrics">
          <div>
            <b>{ks.nodes || 0}</b>
            <span>fresh nodes</span>
          </div>
          <div>
            <b>{ks.findings || 0}</b>
            <span>evidence-backed findings</span>
          </div>
          <div>
            <b>{ks.critical || 0}</b>
            <span>critical</span>
          </div>
          <div>
            <b>{ks.warnings || 0}</b>
            <span>warnings</span>
          </div>
          <div>
            <b>{ks.warming || 0}</b>
            <span>warming nodes</span>
          </div>
        </div>
        <label>
          Diagnostic window
          <select value={kernelWindow} onChange={(e) => setKernelWindow(e.target.value)}>
            <option value="1m">1 minute</option>
            <option value="5m">5 minutes</option>
            <option value="15m">15 minutes</option>
            <option value="1h">1 hour</option>
          </select>
        </label>
        <p>
          Read-only correlation of sysctls, protocol counters, softnet, NIC, qdisc, and conntrack evidence. Suggested commands are
          temporary canaries; Netra never applies them.
        </p>
      </section>
      {(kernel?.nodes || []).map((n: any) => (
        <section className="card span3" key={`${n.node}-kernel-network`}>
          <p className="eyebrow">KERNEL NETWORK · {n.node}</p>
          {n.window?.warming && <p className="empty-state">Collecting a second report after startup or counter reset.</p>}
          {!n.window?.warming && (
            <p>
              Current interval: {Math.round(n.window?.seconds || 0)}s · {n.window?.startAt} → {n.window?.endAt}
            </p>
          )}
          {n.window?.resetDetected && (
            <p className="warning">Counter reset detected: {(n.window?.resetSignals || []).join(', ')}</p>
          )}
          {!n.window?.warming && (
            <small>
              rates/s: softnet {Number(n.window?.softnetDroppedPerSecond || 0).toFixed(3)} · squeeze{' '}
              {Number(n.window?.softnetTimeSqueezePerSecond || 0).toFixed(3)} · rx-drop{' '}
              {Number(n.window?.rxDroppedPerSecond || 0).toFixed(3)} · tx-drop{' '}
              {Number(n.window?.txDroppedPerSecond || 0).toFixed(3)} · rx-missed{' '}
              {Number(n.window?.rxMissedPerSecond || 0).toFixed(3)} · qdisc{' '}
              {Number(n.window?.qdiscDropsPerSecond || 0).toFixed(3)}
            </small>
          )}
          <div className="list">
            {!(n.findings || []).length && <p className="empty-state">No current counter evidence requires a buffer recommendation.</p>}
            {(n.findings || []).map((f: any, i: number) => (
              <div className="agent wide" key={`${f.layer}-${f.signal}-${i}`}>
                <b>{f.signal}</b>
                <span className={`severity-badge ${f.severity}`}>{f.severity}</span>
                <span>{f.layer}</span>
                <small>{(f.evidence || []).join(' · ')}</small>
                {f.windowSeconds > 0 && <small>Evidence window: {Math.round(f.windowSeconds)} seconds</small>}
                <small>{f.explanation}</small>
                <small>{f.recommendation}</small>
                {f.tunable && (
                  <small>
                    {f.tunable}: {f.currentValue || 'unavailable'}
                    {f.suggestedValue ? ` → canary ${f.suggestedValue}` : ''}
                  </small>
                )}
                {f.applyCommand && <code>{f.applyCommand}</code>}
                {f.rollbackCommand && <code>rollback: {f.rollbackCommand}</code>}
                <small className="warning">Risk: {f.risk}</small>
                <ExplainFinding
                  page="drops"
                  kind={f.signal}
                  subject={`${n.node}/${f.layer}`}
                  message={`${f.explanation} ${f.recommendation}`}
                  severity={f.severity}
                />
              </div>
            ))}
          </div>
          <details>
            <summary>Collected sysctls ({(n.snapshot?.tunables || []).length})</summary>
            <div className="list">
              {(n.snapshot?.tunables || []).map((t: any) => (
                <div className="agent wide" key={t.name}>
                  <b>{t.name}</b>
                  <code>{t.value}</code>
                  <small>{t.source}</small>
                </div>
              ))}
            </div>
          </details>
          <details>
            <summary>Current counter deltas ({(n.window?.counters || []).length})</summary>
            <div className="list">
              {(n.window?.counters || []).map((c: any) => (
                <div className="agent wide" key={c.name}>
                  <b>{c.name}</b>
                  <span>Δ {c.delta}</span>
                  <small>{Number(c.perSecond || 0).toFixed(3)} per second</small>
                </div>
              ))}
            </div>
          </details>
        </section>
      ))}
      <section className="card span3">
        <p className="eyebrow">DROP DETECTIVE</p>
        <h2 className="card-title">Policy-aware findings</h2>
        <div className="list">
          {findings.length === 0 && <p className="empty-state">No Netra policy-drop findings.</p>}
          {findings.slice(0, 25).map((f: any, i: number) => (
            <div className="agent wide" key={i}>
              <b>{f.code}</b>
              <span className={f.confidence === 'exact' ? 'blocked' : ''}>{f.confidence}</span>
              <span>
                {f.src} → {f.dst}
              </span>
              <small>
                {f.explanation} {f.suggestion}
              </small>
              {f.attributionState === 'attributed' && (
                <span className="identity-badge">
                  {f.comm || 'unknown process'}
                  {f.pid ? ` (pid ${f.pid})` : ''}
                  {f.pod ? ` · ${f.namespace ? f.namespace + '/' : ''}${f.pod}` : ''}
                </span>
              )}
              {f.attributionState === 'unattributable-ingress' && (
                <span style={{ color: 'var(--text-tertiary)' }}>not attributable (ingress)</span>
              )}
              {f.attributionState === 'unattributable-protocol' && (
                <span style={{ color: 'var(--text-tertiary)' }}>not attributable (non-TCP)</span>
              )}
              {f.attributionState === 'unmatched' && (
                <span style={{ color: 'var(--text-tertiary)' }}>process not found</span>
              )}
              <ExplainFinding page="drops" kind={f.code || 'policy-drop'} subject={`${f.src || ''} → ${f.dst || ''}`} message={`${f.explanation || ''} ${f.suggestion || ''}`} severity={f.confidence === 'exact' ? 'warning' : 'info'} />
            </div>
          ))}
          {findings.length > 25 && <p className="empty-state">+{findings.length - 25} more not shown.</p>}
        </div>
      </section>
      <section className="card span3">
        <p className="eyebrow">STACK SIGNALS</p>
        <h2 className="card-title">Queue and interface findings</h2>
        <div className="list">
          {anomalies.length === 0 && <p className="empty-state">No drop-pressure thresholds triggered.</p>}
          {anomalies.slice(0, 25).map((a: any, i: number) => (
            <div className="agent wide" key={i}>
              <b>{a.kind}</b>
              <span className={`severity-badge ${a.severity}`}>{a.severity}</span>
              <span>{a.subject}</span>
              <small>{a.message}</small>
              <ExplainFinding page="drops" kind={a.kind} subject={a.subject} message={a.message} severity={a.severity} />
            </div>
          ))}
          {anomalies.length > 25 && <p className="empty-state">+{anomalies.length - 25} more not shown.</p>}
        </div>
      </section>
      {nodes.map((n: any) => (
        <section className="card span3" key={n.node}>
          <p className="eyebrow">KERNEL DROPS</p>
          <h2 className="card-title">{n.node}</h2>
          {!(n.kernelDrops || []).length && (
            <p className="empty-state">No kfree_skb tracepoint data. The hook may be unavailable on this kernel.</p>
          )}
          {(n.kernelDrops || []).length > 0 && (
            <div className="datatable-scroll">
              <div className="datahead">
                <span>REASON</span>
                <span>PROTOCOL</span>
                <span>COUNT</span>
                <span>LAST NS</span>
              </div>
              {(n.kernelDrops || []).map((d: any, i: number) => (
                <div className="datarow" key={i}>
                  <span>{d.reasonName || `reason #${d.reason}`}</span>
                  <span>{d.protocol || 'unknown'}</span>
                  <span>{d.count}</span>
                  <span>{d.lastSeenNs || 0}</span>
                </div>
              ))}
            </div>
          )}
        </section>
      ))}
      {nodes.map((n: any) => (
        <section className="card span3" key={`${n.node}-qdisc`}>
          <p className="eyebrow">QDISC DROPS · {n.node}</p>
          {!(n.qdiscStats || []).length && <p className="empty-state">No qdisc stats available (netlink read failed or empty).</p>}
          {(n.qdiscStats || []).length > 0 && (
            <div className="datatable-scroll">
              <div className="datahead">
                <span>INTERFACE</span>
                <span>KIND</span>
                <span>DROPS</span>
                <span>OVERLIMITS</span>
              </div>
              {(n.qdiscStats || []).map((q: any, i: number) => (
                <div className="datarow" key={i}>
                  <span>{q.interface}</span>
                  <span>{q.kind}</span>
                  <span>{q.drops}</span>
                  <span>{q.overlimits || 0}</span>
                </div>
              ))}
            </div>
          )}
        </section>
      ))}
      {nodes.map((n: any) => (
        <section className="card span3" key={`${n.node}-if`}>
          <p className="eyebrow">NODE STACK · {n.node}</p>
          <p>
            softnet processed {n.stack?.softnetProcessed || 0} · dropped {n.stack?.softnetDropped || 0} · time squeeze{' '}
            {n.stack?.softnetTimeSqueeze || 0}
          </p>
          <div className="list">
            {(n.stack?.interfaces || []).map((it: any) => (
              <div className="agent wide" key={it.name}>
                <b>{it.name}</b>
                <span>rx-drop {it.rxDropped}</span>
                <span>tx-drop {it.txDropped}</span>
                <small>
                  rx-errors {it.rxErrors} · tx-errors {it.txErrors} · rx-missed {it.rxMissed} · no-handler{' '}
                  {it.rxNoHandler}
                </small>
              </div>
            ))}
          </div>
        </section>
      ))}
    </div>
  );
}
