import { useEffect, useMemo, useState } from 'react';
import { api } from '../api';
import ExplainFinding from '../components/ExplainFinding';
import PagePulse from '../components/kit/PagePulse';
import { countTone } from '../components/kit/tone';
import { useRate } from '../components/kit/useSeries';
import { useSeries } from '../components/kit/useSeries';
import { navigate } from '../hooks/useInvestigation';

export default function L7() {
  const [data, setData] = useState<any>();
  const [cfg, setCfg] = useState<any>();
  const [sni, setSNI] = useState('');
  const [err, setErr] = useState('');
  const [tlsFP, setTlsFP] = useState<any>();
  const [encDNS, setEncDNS] = useState<any>();

  const [downgrades, setDowngrades] = useState<any>();

  const load = () => Promise.all([
    api<any>('/api/v1/ebpf/l7?limit=200'),
    api<any>('/api/v1/ebpf/config'),
    api<any>('/api/v1/insights/protocol-downgrades'),
    api<any>('/api/v1/ebpf/tls-fingerprints?limit=30'),
    api<any>('/api/v1/ebpf/encrypted-dns?limit=30'),
  ]).then(([d, c, dg, fp, ed]) => {
    setData(d); setCfg(c); setDowngrades(dg); setTlsFP(fp); setEncDNS(ed); setErr('');
  }).catch(e => setErr(String(e)));

  useEffect(() => { void load(); const t = setInterval(load, 5000); return () => clearInterval(t); }, []);

  async function mutate(path: string, name: string) {
    try {
      await api(path, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ name }) });
      setSNI('');
      await load();
    } catch (e) { setErr(String(e)); }
  }

  const sum = data?.summary || {};
  const tlsRate = useRate(data ? (sum.tlsHandshakes || 0) : undefined, data);
  const tlsSeries = useSeries(tlsRate, tlsRate === undefined ? undefined : data);
  const connections = useMemo(() => (data?.connections || []).slice(0, 200), [data]);

  return <div className="grid">
    {err && <section className="card span3"><p className="warning">{err}</p></section>}

    <PagePulse
      headline={data ? ((sum.http5xx || 0) ? `${sum.http5xx} HTTP/1 5xx responses observed.` : `${(sum.uniqueSni || 0) + (sum.uniqueHttpHosts || 0)} named hosts seen — no payloads.`) : undefined}
      tone={data && (sum.http5xx || 0) ? 'warn' : undefined}
      tick={data}
      error={err || undefined}
      figures={[
        { label: 'TLS handshakes / s', value: tlsRate, series: tlsSeries },
        { label: 'unique SNI', value: data ? (sum.uniqueSni || 0) : undefined },
        { label: 'HTTP/1 requests', value: data ? (sum.httpRequests || 0) : undefined },
        { label: 'HTTP/1 5xx', value: data ? (sum.http5xx || 0) : undefined, tone: data ? countTone(sum.http5xx || 0) : undefined },
        { label: 'HTTP hosts', value: data ? (sum.uniqueHttpHosts || 0) : undefined },
        { label: 'blocked attempts', value: data ? `${sum.connectBlocked || 0} / ${sum.connectAttempts || 0}` : undefined, tone: data && (sum.connectBlocked || 0) ? 'warn' : undefined },
      ]}
    />

    <section className="card span3">
      <p className="eyebrow">PROTOCOL DOWNGRADES</p><h2 className="card-title">TLS→cleartext correlation, baseline-relative</h2>
      <p>Workload/host pairs with TLS handshake history at baseline capture time that now also show cleartext HTTP to the same host. Coexistence-tolerant correlation, not a verdict — never read a finding here as a confirmed downgrade attack or MITM.</p>
      {downgrades?.l7Degraded && (
        <p className="warning">L7 visibility is degraded on {(downgrades.l7DegradedNodes || []).join(', ') || 'one or more nodes'} — the TLS/HTTP BPF programs failed to load there. An empty result below does not mean "no downgrades"; it may only mean Netra can't see that node's TLS/HTTP traffic right now.</p>
      )}
      {!downgrades?.baselineCapturedAt && <p className="empty-state">No behavior baseline captured yet — this correlation needs one to compare against (see Insights → Behavior inventory).</p>}
      {downgrades?.baselineCapturedAt && !(downgrades.findings || []).length && <p className="empty-state">No workload/host pair with prior TLS history currently shows cleartext HTTP to the same host.</p>}
      <div className="list">
        {(downgrades?.findings || []).map((f: any, i: number) => (
          <div className={`insightrow ${f.severity}`} key={i}>
            <b>{f.severity}</b>
            <span className="truncate" title={f.source} aria-label={f.source}>{f.source}</span>
            <code>{f.host}</code>
            <small>{f.message}</small>
            <ExplainFinding page="l7" kind="protocol-downgrade" subject={f.source} message={f.message} severity={f.severity} />
          </div>
        ))}
      </div>
    </section>

    <section className="card span3">
      <p className="eyebrow">TLS SNI CONTAINMENT</p>
      <h2 className="card-title">Exact SNI deny</h2>
      <p>This is a leased emergency control. A rule only blocks when Netra successfully parses the exact SNI from a ClientHello in the current skb; unparsed, fragmented, ECH, or QUIC traffic fails open for this rule.</p>
      <div className="toolbar">
        <input aria-label="SNI to deny" value={sni} onChange={e => setSNI(e.target.value)} placeholder="telemetry.example.com" />
        <button className="primary" onClick={() => mutate('/api/v1/ebpf/sni', sni)} disabled={!sni.trim()}>Add SNI</button>
      </div>
      <div className="chips">{(cfg?.blockedSni || []).map((x: string) => <button key={x} aria-label={`Remove ${x}`} onClick={() => mutate('/api/v1/ebpf/sni/delete', x)}>{x} ×</button>)}</div>
    </section>

    <section className="card span3">
      <p className="eyebrow">JA3 / JA4</p>
      <h2 className="card-title">{tlsFP?.stats?.uniqueJa3 ?? 0} unique fingerprints</h2>
      <p>Always-on datapath ClientHello samples (and capture frames). Full boards under Diagnostics → Surfaces.</p>
      <div className="chips"><button type="button" onClick={() => navigate('surfaces', { query: 'tls' })}>Open Surfaces → TLS</button></div>
      {(tlsFP?.fingerprints || []).length === 0 && <p className="empty-state">No JA3 samples yet.</p>}
      <div className="list">
        {(tlsFP?.fingerprints || []).slice(0, 12).map((f: any, i: number) => (
          <div className="agent wide" key={f.ja3 || i}>
            <b className="truncate" title={f.ja3}>{f.sni || f.ja3}</b>
            <small>{f.ja4 || ''}{f.count != null ? ` · n=${f.count}` : ''}{f.node ? ` · ${f.node}` : ''}</small>
          </div>
        ))}
      </div>
    </section>

    <section className="card span3">
      <p className="eyebrow">ENCRYPTED DNS</p>
      <h2 className="card-title">DoT / DoH observe</h2>
      <p>Port 853 and known DoH hostnames via SNI/Host/DNS — no decryption. See Surfaces for the full board.</p>
      <div className="chips"><button type="button" onClick={() => navigate('surfaces', { query: 'encdns' })}>Open Surfaces → Encrypted DNS</button></div>
      {(() => {
        const hits = encDNS?.result?.hits || encDNS?.hits || encDNS?.result?.items || [];
        if (!hits.length) return <p className="empty-state">No DoT/DoH hits yet.</p>;
        return (
          <div className="list">
            {hits.slice(0, 12).map((h: any, i: number) => (
              <div className="agent wide" key={i}>
                <b className="truncate">{h.host || h.hostname || h.name || h.kind || 'hit'}</b>
                <small>{[h.kind, h.port, h.count != null ? `n=${h.count}` : ''].filter(Boolean).join(' · ')}</small>
              </div>
            ))}
          </div>
        );
      })()}
    </section>

    <section className="card span3">
      <p className="eyebrow">TOP IDENTITIES</p>
      <div className="chips">{(sum.topSni || []).slice(0, 12).map((x:any) => <span key={'s'+x.name}>TLS {x.name} · {x.count}</span>)}</div>
      <div className="chips">{(sum.topHttpHosts || []).slice(0, 12).map((x:any) => <span key={'h'+x.name}>HTTP {x.name} · {x.count}</span>)}</div>
      <div className="chips">{(sum.topRemotePorts || []).slice(0, 12).map((x:any) => <span key={'p'+x.name}>{x.name} · {x.count}</span>)}</div>
    </section>

    <section className="card span3">
      <p className="eyebrow">TLS CLIENTHELLO</p><h2 className="card-title">Parsed SNI metadata</h2>
      {(data?.tls || []).length === 0 && <p className="empty-state">No TLS ClientHello samples yet.</p>}
      {(data?.tls || []).length > 0 && <div className="datatable-scroll">
        <div className="datahead obs"><span>WORKLOAD</span><span>SNI</span><span>HANDSHAKES</span><span>BLOCKED</span><span>CGROUP</span></div>
        {(data?.tls || []).map((x:any, i:number) => {
          const who = x.namespace ? `${x.namespace}/${x.pod}` : 'node/unresolved';
          return <div className="datarow obs" key={i}>
            <span className="truncate" title={who} aria-label={who}>{who}</span><span className="truncate" title={x.sni} aria-label={x.sni}>{x.sni}</span><span>{x.handshakes}</span><span className={x.blocked ? 'blocked' : ''}>{x.blocked}</span><span>{x.cgroupId || 0}</span>
            <ExplainFinding page="l7" kind="sni" subject={who} message={x.sni} />
          </div>;
        })}
      </div>}
    </section>

    <section className="card span3">
      <p className="eyebrow">CLEARTEXT HTTP/1</p><h2 className="card-title">Method + host only</h2>
      {(data?.http || []).length === 0 && <p className="empty-state">No cleartext HTTP/1 samples yet.</p>}
      {(data?.http || []).length > 0 && <div className="datatable-scroll">
        <div className="datahead obs"><span>WORKLOAD</span><span>METHOD</span><span>HOST</span><span>REQUESTS</span><span>CGROUP</span></div>
        {(data?.http || []).map((x:any, i:number) => {
          const who = x.namespace ? `${x.namespace}/${x.pod}` : 'node/unresolved';
          return <div className="datarow obs" key={i}>
            <span className="truncate" title={who} aria-label={who}>{who}</span><span>{x.method}</span><span className="truncate" title={x.host} aria-label={x.host}>{x.host}</span><span>{x.requests}</span><span>{x.cgroupId || 0}</span>
            <ExplainFinding page="l7" kind="http-host" subject={who} message={`${x.method || ''} ${x.host || ''}`} />
          </div>;
        })}
      </div>}
    </section>

    <section className="card span3">
      <p className="eyebrow">HTTP/1 STATUS</p><h2 className="card-title">Status line at the start of the packet</h2>
      <p>Cleartext HTTP/1.0 and HTTP/1.1 only. A split status line, HTTP/2, and HTTP/3 are not counted. The reason phrase is not stored.</p>
      {(data?.httpStatus || []).length === 0 && <p className="empty-state">No HTTP/1 status lines yet.</p>}
      {(data?.httpStatus || []).length > 0 && <div className="datatable-scroll">
        <div className="datahead obs"><span>WORKLOAD</span><span>STATUS</span><span>CLASS</span><span>COUNT</span><span>CGROUP</span></div>
        {(data?.httpStatus || []).map((x: any, i: number) => {
          const who = x.namespace ? `${x.namespace}/${x.pod}` : 'node/unresolved';
          const klass = x.status ? `${Math.floor(x.status / 100)}xx` : '';
          return <div className="datarow obs" key={i}>
            <span className="truncate" title={who} aria-label={who}>{who}</span>
            <span className={x.status >= 500 ? 'blocked' : ''}>{x.status}</span>
            <span>{klass}</span>
            <span>{x.count}</span>
            <span>{x.cgroupId || 0}</span>
          </div>;
        })}
      </div>}
    </section>

    <section className="card span3">
      <p className="eyebrow">SOCKET ATTEMPTS</p><h2 className="card-title">Exact destination counters</h2>
      {connections.length === 0 && <p className="empty-state">No socket attempt samples yet.</p>}
      {connections.length > 0 && <div className="datatable-scroll">
        <div className="datahead obs"><span>WORKLOAD</span><span>PROTO</span><span>REMOTE</span><span>ATTEMPTS</span><span>BLOCKED</span></div>
        {connections.map((x:any, i:number) => {
          const who = x.namespace ? `${x.namespace}/${x.pod}` : `cgroup ${x.cgroupId || 0}`;
          return <div className="datarow obs" key={i}>
            <span className="truncate" title={who} aria-label={who}>{who}</span><span>{x.protocol}</span><span>{x.remoteIp}:{x.remotePort}</span><span>{x.attempts}</span><span className={x.blocked ? 'blocked' : ''}>{x.blocked}</span>
          </div>;
        })}
      </div>}
    </section>
  </div>;
}
