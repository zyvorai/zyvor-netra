import { useEffect, useMemo, useState } from 'react';
import { api } from '../api';
import ExplainFinding from '../components/ExplainFinding';
import PagePulse from '../components/kit/PagePulse';
import { countTone } from '../components/kit/tone';
import Reveal from '../components/Reveal';
import BaselineAge from '../components/BaselineAge';

type Summary = {
  dependencyEdges: number; externalEdges: number; baselineEntries: number; driftFindings: number; recommendations: number;
  rateBaselineEntries: number; rateDriftFindings: number; highExposure: number; remediationProposals: number; rateWarming: boolean;
};
type Node = { id: string; kind: string; namespace?: string; name: string; ip?: string; workloadKind?: string };
type Edge = { source: string; target: string; protocol: string; port?: number; packets: number; bytes: number; blocked: number; external?: boolean };
type Graph = { generatedAt: string; nodes: Node[]; edges: Edge[] };
type Drift = { baselineCapturedAt?: string; findings: { severity: string; kind: string; source: string; value: string; count?: number; message: string }[] };
type RateFinding = { severity: string; source: string; metric: string; baselineRate: number; currentRate: number; ratio?: number; message: string };
type RateDrift = { baselineCapturedAt?: string; window: { warming: boolean; requestedWindowSeconds: number; metrics: any[] }; findings: RateFinding[] };
type Exposure = { source: string; score: number; severity: string; externalDependencies: number; behaviorDrift: number; rateDrift: number; reasons: string[] };
type Recommendation = { id: string; kind: string; namespace: string; workloadKind?: string; workloadName: string; confidence: string; rationale: string[]; manifest?: any };
type Remediation = { id: string; source: string; severity: string; kind: string; title: string; rationale: string[]; action: Record<string, any>; reviewRequired: boolean };
type BlastRadiusNode = { id: string; hops: number };
type BlastRadiusResult = { generatedAt: string; root: string; maxHops: number; nodes: BlastRadiusNode[]; edges: Edge[]; truncated: boolean; caveat: string };
type NewSinceStartResult = { findings: { severity: string; kind: string; source: string; value: string; message: string }[]; count: number; limitation: string; note: string };

export default function Insights() {
  const [summary, setSummary] = useState<Summary | null>(null);
  const [graph, setGraph] = useState<Graph | null>(null);
  const [drift, setDrift] = useState<Drift | null>(null);
  const [rateDrift, setRateDrift] = useState<RateDrift | null>(null);
  const [exposure, setExposure] = useState<Exposure[]>([]);
  const [recommendations, setRecommendations] = useState<Recommendation[]>([]);
  const [remediations, setRemediations] = useState<Remediation[]>([]);
  const [rates, setRates] = useState<any>(null);
  const [ciliumEnabled, setCiliumEnabled] = useState(false);
  const [baseline, setBaseline] = useState<any>(null);
  const [rateBaseline, setRateBaseline] = useState<any>(null);
  const [window, setWindow] = useState('5m');
  const [msg, setMsg] = useState('');
  const [reviews, setReviews] = useState<Record<string, any>>({});
  const [reviewErr, setReviewErr] = useState<Record<string, string>>({});
  const [blastRoot, setBlastRoot] = useState('');
  const [blastHops, setBlastHops] = useState(3);
  const [blastResult, setBlastResult] = useState<BlastRadiusResult | null>(null);
  const [blastMsg, setBlastMsg] = useState('');
  const [newSinceStart, setNewSinceStart] = useState<NewSinceStartResult | null>(null);
  const [newSinceStartMsg, setNewSinceStartMsg] = useState('');

  async function refresh() {
    try {
      const q = `?window=${encodeURIComponent(window)}`;
      const [s, g, d, rd, ex, r, rb, b, rem, rt] = await Promise.all([
        api<Summary>(`/api/v1/insights/summary${q}`),
        api<Graph>('/api/v1/insights/dependencies?limit=250'),
        api<Drift>('/api/v1/insights/drift'),
        api<RateDrift>(`/api/v1/insights/rate-drift${q}`),
        api<any>(`/api/v1/insights/exposure${q}`),
        api<any>('/api/v1/insights/recommendations?limit=30'),
        api<any>('/api/v1/insights/rate-baseline'),
        api<any>('/api/v1/insights/baseline'),
        api<any>(`/api/v1/insights/remediations${q}&limit=30`),
        api<any>(`/api/v1/insights/rates${q}`),
      ]);
      setSummary(s); setGraph(g); setDrift(d); setRateDrift(rd); setExposure(ex.items || []);
      setRecommendations(r.items || []); setCiliumEnabled(Boolean(r.ciliumEnabled)); setRateBaseline(rb); setBaseline(b);
      setRemediations(rem.items || []); setRates(rt); setMsg('');
    } catch (e) { setMsg(String(e)); }
  }
  useEffect(() => { void refresh(); }, [window]);
  useEffect(() => {
    api<NewSinceStartResult>('/api/v1/insights/new-since-start')
      .then((x) => { setNewSinceStart(x); setNewSinceStartMsg(''); })
      .catch((e) => setNewSinceStartMsg(String(e)));
  }, []);

  const nodeByID = useMemo(() => new Map((graph?.nodes || []).map((n) => [n.id, n])), [graph]);
  const label = (id: string) => { const n = nodeByID.get(id); if (!n) return id; if (n.kind === 'external') return n.ip || n.name; return `${n.namespace || ''}/${n.name}`.replace(/^\//, ''); };

  async function captureBehavior() { try { const x = await api<any>('/api/v1/insights/baseline', { method: 'POST' }); setMsg(`Behavior baseline captured with ${x.baseline?.entries?.length || 0} entries.`); await refresh(); } catch (e) { setMsg(String(e)); } }
  async function clearBehavior() { if (!confirm('Clear the known-good behavior baseline?')) return; try { await api('/api/v1/insights/baseline', { method: 'DELETE', headers: { 'X-Netra-Confirm-Baseline-Clear': 'clear' } }); await refresh(); } catch (e) { setMsg(String(e)); } }
  async function captureRate() { try { const x = await api<any>(`/api/v1/insights/rate-baseline?window=${encodeURIComponent(window)}`, { method: 'POST' }); setMsg(`Rate baseline captured with ${x.baseline?.entries?.length || 0} entries.`); await refresh(); } catch (e) { setMsg(String(e)); } }
  async function clearRate() { if (!confirm('Clear the traffic-rate baseline?')) return; try { await api('/api/v1/insights/rate-baseline', { method: 'DELETE', headers: { 'X-Netra-Confirm-Rate-Baseline-Clear': 'clear' } }); await refresh(); } catch (e) { setMsg(String(e)); } }

  async function reviewRecommendation(id: string) {
    try {
      const res = await api<any>(`/api/v1/insights/policy-review?recommendationId=${encodeURIComponent(id)}`);
      setReviews((prev) => ({ ...prev, [id]: res }));
      setReviewErr((prev) => ({ ...prev, [id]: '' }));
    } catch (e) {
      setReviewErr((prev) => ({ ...prev, [id]: String(e) }));
    }
  }

  async function runBlastRadius() {
    if (!blastRoot) { setBlastMsg('Pick a root node.'); return; }
    try {
      const res = await api<BlastRadiusResult>(`/api/v1/insights/blast-radius?root=${encodeURIComponent(blastRoot)}&hops=${blastHops}`);
      setBlastResult(res); setBlastMsg('');
    } catch (e) { setBlastResult(null); setBlastMsg(String(e)); }
  }

  const driftN = summary?.driftFindings ?? 0;
  const rateN = summary?.rateDriftFindings ?? 0;
  const expN = summary?.highExposure ?? 0;
  return <div className="grid">
    <PagePulse
      headline={summary ? (driftN + rateN ? `${driftN + rateN} behavior change${driftN + rateN === 1 ? '' : 's'} to review.` : expN ? `${expN} workload${expN === 1 ? '' : 's'} highly exposed.` : 'Behavior matches the learned baseline.') : undefined}
      tone={summary && (driftN + rateN || expN) ? 'warn' : undefined}
      tick={summary}
      error={msg && /error/i.test(msg) ? msg : undefined}
      figures={[
        { label: 'dependency edges', value: summary ? (summary.dependencyEdges ?? 0) : undefined },
        { label: 'behavior drift', value: summary ? driftN : undefined, tone: summary ? countTone(driftN) : undefined },
        { label: 'rate anomalies', value: summary ? rateN : undefined, tone: summary ? countTone(rateN) : undefined },
        { label: 'high exposure', value: summary ? expN : undefined, tone: summary ? countTone(expN) : undefined },
        { label: 'recommendations', value: summary ? recommendations.length : undefined },
      ]}
    />
    <section className="card">
      <p className="eyebrow">CONTROLS</p>
      <h2 className="card-title">Rate window and baselines</h2>
      <div className="toolbar"><label>Rate window <select value={window} onChange={e => setWindow(e.target.value)}><option>1m</option><option>5m</option><option>15m</option><option>30m</option><option>1h</option></select></label><button className="btn-refresh" onClick={refresh}>Refresh</button></div>
      {msg && <p className="warning">{msg}</p>}
      {summary?.rateWarming && <p className="warning">Rate engine is warming up. At least two fresh agent reports are required before rate drift is evaluated.</p>}
    </section>

    <section className="card">
      <p className="eyebrow">KNOWN GOOD</p><h2 className="card-title">Behavior inventory</h2>
      <p>{baseline?.captured ? `Captured ${new Date(baseline.baseline?.capturedAt).toLocaleString()} · ${baseline.baseline?.entries?.length ?? 0} entries` : 'No behavior baseline captured.'}</p>
      <div className="toolbar"><button className="primary" onClick={captureBehavior}>{baseline?.captured ? 'Recapture' : 'Capture'}</button><button className="btn-secondary" onClick={clearBehavior} disabled={!baseline?.captured}>Clear</button></div>
    </section>

    <section className="card">
      <p className="eyebrow">TRAFFIC RATE</p><h2 className="card-title">Window baseline</h2>
      <p>{rateBaseline?.captured ? `Captured ${new Date(rateBaseline.baseline?.capturedAt).toLocaleString()} · ${rateBaseline.baseline?.entries?.length ?? 0} metric rates` : 'No traffic-rate baseline captured.'}</p>
      <div className="toolbar"><button className="primary" onClick={captureRate} disabled={Boolean(rateDrift?.window?.warming)}>{rateBaseline?.captured ? 'Recapture' : 'Capture'}</button><button className="btn-secondary" onClick={clearRate} disabled={!rateBaseline?.captured}>Clear</button></div>
    </section>

    <section className="card span2">
      <p className="eyebrow">RATE WINDOW</p><h2 className="card-title">Current deltas</h2>
      {rates?.warming && <p className="warning">Warming up — waiting for consecutive agent reports.</p>}
      <div className="list">{(rates?.metrics || []).slice(0, 12).map((m:any, i:number) => { const src = m.source || m.workload || '—'; return <div className="insightrow" key={`${m.source}-${m.metric}-${i}`}><b>{m.metric || m.name || 'rate'}</b><span className="truncate" title={src} aria-label={src}>{src}</span><small>{Number(m.rate ?? m.value ?? 0).toFixed(2)}/s</small></div>; })}</div>
      {!rates?.warming && !(rates?.metrics || []).length && <p className="empty-state">No rate samples in this window yet.</p>}
    </section>

    <section className="card">
      <p className="eyebrow">EXPOSURE</p><h2 className="card-title">Highest-ranked workloads</h2>
      {(exposure || []).slice(0, 8).map(x => <div className={`insightrow ${x.severity}`} key={x.source}><b>{x.score}/100 · {x.severity}</b><span className="truncate" title={x.source} aria-label={x.source}>{x.source}</span><small>{(x.reasons || []).join(' · ')}</small><ExplainFinding page="insights" kind="exposure" subject={x.source} message={(x.reasons || []).join(' · ')} severity={x.severity} /></div>)}
      {!exposure.length && <p className="empty-state">No exposure signals yet.</p>}
    </section>

    <section className="card span2">
      <p className="eyebrow">RATE DRIFT</p><h2 className="card-title">Time-window anomalies</h2>
      {!rateDrift?.baselineCapturedAt && <p>Capture a rate baseline after warm-up to compare current traffic rates.</p>}
      {(rateDrift?.findings || []).slice(0, 30).map((f, i) => <div className={`insightrow ${f.severity}`} key={`${f.source}-${f.metric}-${i}`}><b>{f.metric}</b><span className="truncate" title={f.source} aria-label={f.source}>{f.source}</span><code>{f.ratio ? `${f.ratio.toFixed(1)}×` : 'new'}</code><small>{(f.currentRate ?? 0).toFixed(2)}/s current · {(f.baselineRate ?? 0).toFixed(2)}/s baseline</small><ExplainFinding page="insights" kind={`rate-drift:${f.metric}`} subject={f.source} message={f.message || `${f.metric} rate drift`} severity={f.severity} /></div>)}
      {rateDrift?.baselineCapturedAt && !(rateDrift.findings || []).length && !rateDrift.window?.warming && <p className="empty-state">No rate changes crossed the deterministic thresholds.</p>}
    </section>

    <section className="card">
      <p className="eyebrow">BEHAVIOR DRIFT</p><h2 className="card-title">New inventory</h2>
      {(drift?.findings || []).slice(0, 20).map((f, i) => <div className={`insightrow ${f.severity}`} key={`${f.source}-${f.kind}-${f.value}-${i}`}><b>{f.kind}</b><span className="truncate" title={f.source} aria-label={f.source}>{f.source}</span><code>{f.value}</code><ExplainFinding page="insights" kind={f.kind} subject={f.source} message={f.message || f.value} severity={f.severity} /></div>)}
      {drift?.baselineCapturedAt && !(drift.findings || []).length && <p className="empty-state">No new behavior crossed noise thresholds.</p>}
    </section>

    <section className="card">
      <p className="eyebrow">NEW SINCE START</p><h2 className="card-title">First-egress-after-start correlation</h2>
      <p><small>{newSinceStart?.limitation || 'Baseline-relative correlation only — not a precise "N ms after first packet" claim.'}</small></p>
      {newSinceStartMsg && <p className="warning">{newSinceStartMsg}</p>}
      {!newSinceStartMsg && (newSinceStart?.findings || []).slice(0, 20).map((f, i) => <div className={`insightrow ${f.severity}`} key={`${f.source}-${f.kind}-${i}`}><b>{f.kind}</b><span className="truncate" title={f.source} aria-label={f.source}>{f.source}</span><code>{f.value}</code><ExplainFinding page="insights" kind={`new-since-start:${f.kind}`} subject={f.source} message={f.message || f.value} severity={f.severity} /></div>)}
      {!newSinceStartMsg && newSinceStart && !(newSinceStart.findings || []).length && <p className="empty-state">No new-destination finding correlates with a pod/workload start yet.</p>}
    </section>

    <section className="card span3">
      <p className="eyebrow">DEPENDENCY GRAPH</p><h2 className="card-title">Workload → workload/service/external</h2>
      {(graph?.edges || []).length === 0 && <p className="empty-state">No dependency edges observed yet.</p>}
      {(graph?.edges || []).length > 0 && <div className="datatable-scroll">
        <div className="datahead deps"><span>SOURCE</span><span>TARGET</span><span>NETWORK</span><span>PACKETS / BYTES</span></div>
        {(graph?.edges || []).slice(0, 100).map((e, i) => <div className="datarow deps" key={`${e.source}-${e.target}-${e.protocol}-${e.port}-${i}`}><span className="truncate" title={label(e.source)} aria-label={label(e.source)}>{label(e.source)}</span><span className="truncate" title={label(e.target)} aria-label={label(e.target)}>{label(e.target)} {e.external ? '↗' : ''}</span><span>{e.protocol}{e.port ? `/${e.port}` : ''}</span><span>{e.packets.toLocaleString()} / {e.bytes.toLocaleString()}</span></div>)}
      </div>}
    </section>

    <section className="card span3">
      <p className="eyebrow">BLAST RADIUS</p><h2 className="card-title">Multi-hop observed-traffic reachability from one node</h2>
      <p>Traces packets Netra has actually seen leaving the chosen node, hop by hop — not a policy allow/deny determination. A node showing no further hops here may still be permitted to reach destinations Netra simply hasn't observed traffic for.</p>
      <div className="toolbar">
        <label>Root <select value={blastRoot} onChange={e => setBlastRoot(e.target.value)}>
          <option value="">Select a node…</option>
          {(graph?.nodes || []).map(n => <option key={n.id} value={n.id}>{label(n.id)}</option>)}
        </select></label>
        <label>Hops <select value={blastHops} onChange={e => setBlastHops(Number(e.target.value))}>
          {[1, 2, 3, 4, 5, 6].map(h => <option key={h} value={h}>{h}</option>)}
        </select></label>
        <button className="primary" onClick={runBlastRadius} disabled={!blastRoot}>Trace</button>
      </div>
      {blastMsg && <p className="warning">{blastMsg}</p>}
      {blastResult && <>
        <p><small>{blastResult.caveat}</small></p>
        {blastResult.truncated && <p className="warning">Cut off at {blastResult.maxHops} hops — reachable nodes may extend further. Increase hops (up to 6) to see more.</p>}
        <div className="metrics">
          <div><b>{blastResult.nodes.length}</b><span>nodes reached</span></div>
          <div><b>{blastResult.edges.length}</b><span>edges used</span></div>
        </div>
        <div className="list">
          {blastResult.nodes.slice(0, 50).map(n => <div className="insightrow" key={n.id}><b>{n.hops} hop{n.hops === 1 ? '' : 's'}</b><span className="truncate" title={label(n.id)} aria-label={label(n.id)}>{label(n.id)}</span></div>)}
        </div>
        {blastResult.nodes.length > 50 && <p><small>Showing first 50 of {blastResult.nodes.length} nodes.</small></p>}
      </>}
    </section>

    <section className="card span3">
      <p className="eyebrow">REMEDIATION PROPOSALS</p><h2 className="card-title">Review-only containment and investigation drafts</h2>
      <p>Netra does not auto-execute these. A proposal is evidence plus a suggested next action, not authorization to block traffic.</p>
      <div className="recommendations">{remediations.map(r => <details key={r.id} className="recommendation"><summary><b>{r.title}</b><span>{r.severity} · {r.source}</span></summary>{r.rationale.map(x => <p key={x}>• {x}</p>)}<pre>{JSON.stringify(r.action, null, 2)}</pre></details>)}{!remediations.length && <p className="empty-state">No remediation draft currently meets the thresholds.</p>}</div>
    </section>

    <Reveal className="card span3">
      <p className="eyebrow">POLICY RECOMMENDATIONS</p><h2 className="card-title">Observed-traffic CiliumNetworkPolicy drafts</h2>
      {!ciliumEnabled && <p className="warning">Cilium integration is disabled. Drafts remain export/review only.</p>}
      <div className="recommendations">{recommendations.map(r => {
        const review = reviews[r.id];
        return <details key={r.id} className="recommendation">
          <summary><b>{r.namespace}/{r.workloadName}</b><span>{r.confidence} · {r.kind}</span></summary>
          {r.rationale.map(x => <p key={x}>• {x}</p>)}
          <pre>{JSON.stringify(r.manifest, null, 2)}</pre>
          <button type="button" className="btn-secondary" onClick={() => reviewRecommendation(r.id)}>Review against live policy</button>
          {reviewErr[r.id] && <p className="warning">{reviewErr[r.id]}</p>}
          {review && <div className="list">
            <div className="insightrow">
              <b>{review.plan.risk} risk</b>
              <span>{review.matchingPolicies.length} matching polic{review.matchingPolicies.length === 1 ? 'y' : 'ies'}{review.ambiguousMatch ? ' (ambiguous)' : ''}</span>
              <small>{(review.plan.changes || []).join(' · ') || 'No changes detected'}</small>
            </div>
            {(review.plan.warnings || []).map((w: string, i: number) => <p key={i} className="warning">{w}</p>)}
            {review.prose && <p>{review.prose}</p>}
            {(review.blastRadius || []).map((b: any, i: number) => (
              <div className={`insightrow ${b.activeTraffic ? 'warning' : 'info'}`} key={i}>
                <b>{b.kind}</b>
                <span>{b.correlated ? (b.activeTraffic ? 'active traffic' : 'no traffic observed') : 'not correlated'}</span>
                <small>{b.destination} — {b.note}</small>
              </div>
            ))}
          </div>}
        </details>;
      })}{!recommendations.length && <p className="empty-state">No policy recommendation drafts currently meet the thresholds.</p>}</div>
    </Reveal>
    <BaselineAge />
  </div>;
}
