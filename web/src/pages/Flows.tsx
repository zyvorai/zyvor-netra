import { useEffect, useRef, useState } from 'react';
import { api, authHeaders } from '../api';
import FlowObserve from '../components/FlowObserve';
import TerminalFrame from '../components/TerminalFrame';
import PagePulse from '../components/kit/PagePulse';
import RankedList from '../components/kit/RankedList';
import { countTone } from '../components/kit/tone';
import { endpointName, tuple, verdictClass } from '../lib/flow';

type Filter = {
  direction: string;
  verdict: string;
  protocol: string;
  namespace: string;
  pod: string;
  destination: string;
};

const FILTER_LABELS: Record<keyof Filter, string> = {
  direction: 'Direction',
  verdict: 'Verdict',
  protocol: 'Protocol',
  namespace: 'Namespace',
  pod: 'Pod',
  destination: 'Destination',
};

export default function Flows() {
  const [flows, setFlows] = useState<any[]>([]);
  const [drops, setDrops] = useState<any[]>([]);
  const [summary, setSummary] = useState<any>();
  const [summaryError, setSummaryError] = useState('');
  const [dropError, setDropError] = useState('');
  const [filter, setFilter] = useState<Filter>({
    direction: 'EGRESS',
    verdict: '',
    protocol: '',
    namespace: '',
    pod: '',
    destination: '',
  });
  const [run, setRun] = useState(0);
  const ctrl = useRef<AbortController | undefined>(undefined);

  async function loadSummary(f: Filter = filter) {
    try {
      const q = new URLSearchParams({
        number: '500',
        ...Object.fromEntries(Object.entries(f).filter(([, v]) => v)),
      });
      const x = await api<any>('/api/v1/flows/summary?' + q);
      setSummary(x);
      setSummaryError('');
    } catch (e) {
      setSummaryError(String(e));
    }
  }

  useEffect(() => {
    void loadSummary(filter);
  }, [run]);

  useEffect(() => {
    ctrl.current?.abort();
    const c = new AbortController();
    ctrl.current = c;
    const q = new URLSearchParams({
      number: '100',
      ...Object.fromEntries(Object.entries(filter).filter(([, v]) => v)),
    });
    (async () => {
      try {
        const r = await fetch('/api/v1/flows/stream?' + q, { headers: authHeaders(), signal: c.signal });
        if (!r.ok) throw new Error(await r.text());
        if (!r.body) return;
        const rd = r.body.getReader();
        const dec = new TextDecoder();
        let buf = '';
        while (true) {
          const res = await rd.read();
          if (res.done) break;
          buf += dec.decode(res.value, { stream: true });
          let i;
          while ((i = buf.indexOf('\n\n')) >= 0) {
            const part = buf.slice(0, i);
            buf = buf.slice(i + 2);
            const line = part.split('\n').find((v: string) => v.startsWith('data: '));
            if (line && part.includes('event: flow')) {
              const f = JSON.parse(line.slice(6));
              setFlows((old) => [f, ...old].slice(0, 250));
            }
          }
        }
      } catch (e: any) {
        if (e.name !== 'AbortError') console.error(e);
      }
    })();
    return () => c.abort();
  }, [run]);

  async function explainDrops() {
    try {
      const q = new URLSearchParams();
      if (filter.namespace) q.set('namespace', filter.namespace);
      if (filter.pod) q.set('pod', filter.pod);
      q.set('limit', '20');
      const x = await api<any>('/api/v1/drops/explain?' + q);
      setDrops(x.findings || []);
      setDropError('');
    } catch (e) {
      setDropError(String(e));
    }
  }

  const verdicts = summary?.verdicts || {};
  const protocols = summary?.protocols || {};

  const dropped = verdicts.DROPPED ?? 0;
  return (
    <div className="grid">
      <PagePulse
        headline={summary ? (dropped ? `${dropped} of ${summary.total ?? 0} sampled flows dropped.` : `${summary.total ?? 0} flows sampled, none dropped.`) : undefined}
        tone={summary && dropped ? 'warn' : undefined}
        tick={summary}
        error={summaryError || undefined}
        figures={[
          { label: 'flows sampled', value: summary ? (summary.total ?? 0) : undefined },
          { label: 'forwarded', value: summary ? (verdicts.FORWARDED ?? 0) : undefined },
          { label: 'dropped', value: summary ? dropped : undefined, tone: summary ? countTone(dropped) : undefined },
          { label: 'TCP+UDP', value: summary ? (protocols.TCP ?? 0) + (protocols.UDP ?? 0) : undefined },
          { label: 'streamed rows', value: flows.length },
        ]}
      />
      <section className="card span2">
        <p className="eyebrow">LIVE STREAM</p>
        <h2 className="card-title">Filters</h2>
        <p>
          Optional Cilium/Hubble live stream. Native flow history, RED and traces sit below — and work without Hubble.
        </p>
        <div className="filters">
          {Object.entries(filter).map(([k, v]) => (
            <label key={k}>
              {FILTER_LABELS[k as keyof Filter] || k}
              <input
                value={v}
                placeholder={k === 'direction' ? 'EGRESS' : ''}
                onChange={(e) => setFilter({ ...filter, [k]: e.target.value })}
              />
            </label>
          ))}
          <button
            className="btn-refresh"
            onClick={() => {
              setFlows([]);
              setRun((x) => x + 1);
            }}
          >
            Reconnect
          </button>
          <button className="btn-refresh" onClick={() => void loadSummary()}>Refresh summary</button>
          <button className="btn-diag" onClick={explainDrops}>Explain recent drops</button>
        </div>
      </section>

      <section className="card">
        <p className="eyebrow">FLOW SUMMARY</p>
        <h2 className="card-title">Why flows dropped</h2>
        {summaryError && <p className="warning">{summaryError}</p>}
        <RankedList
          limit={4}
          mono={false}
          empty="No drop reasons in this window."
          items={(summary?.dropReasons || []).map((x: any) => ({ name: x.name, count: x.count, tone: 'bad' as const }))}
        />
      </section>

      <div className="span3">
        <TerminalFrame title="observer.GetFlows / filtered">
          <div className="flowhead">
            <span>VERDICT</span>
            <span>DIR</span>
            <span>SOURCE → DESTINATION</span>
            <span>NETWORK</span>
          </div>
          {flows.map((f, i) => (
            <div className="flowrow" key={i}>
              <span className={verdictClass(f.verdict)}>{f.verdict}</span>
              <span className={f.trafficDirection === 'INGRESS' ? 'dir-ingress' : 'dir-egress'}>{f.trafficDirection}</span>
              <span>
                {endpointName(f.source)} → {endpointName(f.destination)}
              </span>
              <span>{tuple(f)}</span>
            </div>
          ))}
        </TerminalFrame>
      </div>

      <section className="card span2">
        <p className="eyebrow">TOP DESTINATIONS</p>
        <h2 className="card-title">From summary window</h2>
        <div className="list">
          {(summary?.topDestinations || []).length === 0 && <p className="empty-state">No destination aggregate yet — reconnect or refresh summary.</p>}
          {(summary?.topDestinations || []).map((x: any) => (
            <button key={x.name} type="button" onClick={() => setFilter({ ...filter, destination: x.name })}>
              <span>
                <b>{x.name}</b>
              </span>
              <span>{x.count}</span>
            </button>
          ))}
        </div>
      </section>

      <section className="card">
        <p className="eyebrow">PROTOCOLS</p>
        <h2 className="card-title">Sample mix</h2>
        <div className="chips">
          {Object.entries(protocols).map(([name, count]) => (
            <span key={name}>
              {name} · {String(count)}
            </span>
          ))}
        </div>
      </section>

      <FlowObserve />

      <section className="card span3">
        <p className="eyebrow">DROP EXPLAIN</p>
        <h2 className="card-title">Recent drop findings</h2>
        {dropError && <p className="warning">{dropError}</p>}
        {drops.length === 0 && (
          <p className="empty-state">Use "Explain recent drops" to fetch recent denied flows for the current namespace/pod scope.</p>
        )}
        {drops.map((d, i) => (
          <div className="dropcard" key={i}>
            <b>{d.explanation || 'Dropped flow'}</b>
            <span>
              {d.source} · {d.code || d.reason || 'unknown reason'}
            </span>
            {d.suggestion && <p>• {d.suggestion}</p>}
          </div>
        ))}
      </section>
    </div>
  );
}
