// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
import { FormEvent, useState } from 'react';
import { api } from '../api';
import PagePulse from '../components/kit/PagePulse';
import { countTone } from '../components/kit/tone';

type Hit = {
  source?: string;
  node?: string;
  destination?: string;
  direction?: string;
  protocol?: string;
  evidence?: string;
  packets?: number;
  bytes?: number;
  alreadyBlocked?: number;
};

type LiveResult = {
  hitCount?: number;
  workloads?: number;
  agentsSeen?: number;
  agentsStale?: number;
  totalPackets?: number;
  totalBytes?: number;
  truncated?: boolean;
  caveat?: string;
  hits?: Hit[];
};

type HistoryResult = {
  since?: string;
  caveat?: string;
  result?: {
    flowsSeen?: number;
    denials?: { source?: string; destination?: string; packets?: number; reason?: string }[];
    breakage?: { message?: string }[];
  };
};

const KINDS = ['ip', 'cidr', 'port', 'dns', 'sni', 'process'] as const;

export default function DenyPreview() {
  const [kind, setKind] = useState<(typeof KINDS)[number]>('cidr');
  const [value, setValue] = useState('203.0.113.0/24');
  const [direction, setDirection] = useState('egress');
  const [protocol, setProtocol] = useState('');
  const [port, setPort] = useState('');
  const [namespace, setNamespace] = useState('');
  const [since, setSince] = useState('1h');
  const [mode, setMode] = useState<'live' | 'history'>('live');
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState('');
  const [live, setLive] = useState<LiveResult | null>(null);
  const [history, setHistory] = useState<HistoryResult | null>(null);

  const run = async (e?: FormEvent) => {
    e?.preventDefault();
    setBusy(true);
    setErr('');
    const body: Record<string, unknown> = {
      kind,
      value: value.trim(),
      direction: direction || 'both',
      limit: 50,
    };
    if (protocol.trim()) body.protocol = protocol.trim().toUpperCase();
    if (port.trim()) body.port = Number(port);
    if (namespace.trim()) body.namespace = namespace.trim();
    try {
      if (mode === 'history') {
        if (kind === 'process') {
          throw new Error('process matching is live-preview only — switch to Live or use dns/sni/ip/cidr/port');
        }
        body.since = since.trim() || '1h';
        const res = await api<HistoryResult>('/api/v1/ebpf/deny/preview-history', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(body),
        });
        setHistory(res);
        setLive(null);
      } else {
        const res = await api<LiveResult>('/api/v1/ebpf/deny/preview', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(body),
        });
        setLive(res);
        setHistory(null);
      }
    } catch (ex) {
      setErr(String(ex));
    } finally {
      setBusy(false);
    }
  };

  const hits = live?.hits || [];
  const denials = history?.result?.denials || [];
  const hitCount = mode === 'live' ? live?.hitCount ?? 0 : denials.length;
  const caveat = live?.caveat || history?.caveat || '';

  return (
    <div className="grid">
      <PagePulse
        headline={
          live || history
            ? hitCount
              ? `${hitCount} observed match${hitCount === 1 ? '' : 'es'} — review only, nothing applied.`
              : 'No retained or live matches for this proposal in the window.'
            : 'Propose an emergency deny and preview blast radius against live counters or flow history.'
        }
        tone={hitCount ? 'warn' : undefined}
        tick={live || history}
        error={err || undefined}
        figures={[
          { label: 'mode', value: mode },
          { label: 'matches', value: live || history ? hitCount : undefined, tone: hitCount ? countTone(hitCount) : undefined },
          { label: 'workloads', value: live?.workloads },
          { label: 'flows seen', value: history?.result?.flowsSeen },
          { label: 'agents (stale)', value: live ? `${live.agentsSeen ?? 0} (${live.agentsStale ?? 0})` : undefined },
          { label: 'packets', value: live?.totalPackets },
        ]}
      />

      <section className="card span3">
        <p className="eyebrow">PROPOSAL</p>
        <h2 className="card-title">Emergency deny preview</h2>
        <p>
          Applies nothing. Live path uses latest non-stale agent counters; history uses the controller flowlog
          (default 7 days). Prefer live for DNS/SNI/process when historical name fields are empty.
        </p>
        <form className="filters" onSubmit={run} style={{ display: 'grid', gap: '0.75rem', marginTop: '1rem' }}>
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.75rem' }}>
            <label>
              Path{' '}
              <select value={mode} onChange={(e) => setMode(e.target.value as 'live' | 'history')}>
                <option value="live">Live counters</option>
                <option value="history">Flow history</option>
              </select>
            </label>
            <label>
              Kind{' '}
              <select value={kind} onChange={(e) => setKind(e.target.value as (typeof KINDS)[number])}>
                {KINDS.map((k) => (
                  <option key={k} value={k} disabled={mode === 'history' && k === 'process'}>
                    {k}
                  </option>
                ))}
              </select>
            </label>
            <label>
              Direction{' '}
              <select value={direction} onChange={(e) => setDirection(e.target.value)}>
                <option value="both">both</option>
                <option value="egress">egress</option>
                <option value="ingress">ingress</option>
              </select>
            </label>
            {mode === 'history' && (
              <label>
                Since <input value={since} onChange={(e) => setSince(e.target.value)} placeholder="1h" />
              </label>
            )}
          </div>
          <label>
            Value{' '}
            <input
              style={{ width: 'min(36rem, 100%)' }}
              value={value}
              onChange={(e) => setValue(e.target.value)}
              placeholder="203.0.113.0/24 or evil.example"
              required
            />
          </label>
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.75rem' }}>
            <label>
              Protocol <input value={protocol} onChange={(e) => setProtocol(e.target.value)} placeholder="TCP" />
            </label>
            <label>
              Port <input value={port} onChange={(e) => setPort(e.target.value)} placeholder="443" />
            </label>
            <label>
              Namespace <input value={namespace} onChange={(e) => setNamespace(e.target.value)} placeholder="optional" />
            </label>
          </div>
          <button type="submit" disabled={busy || !value.trim()}>
            {busy ? 'Previewing…' : 'Preview blast radius'}
          </button>
        </form>
      </section>

      {err && (
        <section className="card span3">
          <p className="warning">{err}</p>
        </section>
      )}

      {caveat && (
        <section className="card span3">
          <p className="eyebrow">CAVEAT</p>
          <h2 className="card-title">Not a production block forecast</h2>
          <p className="warning">{caveat}</p>
          {live?.truncated && <p className="empty-state">Result truncated — totals still include groups beyond the limit.</p>}
        </section>
      )}

      {mode === 'live' && live && (
        <section className="card span3">
          <p className="eyebrow">LIVE HITS</p>
          <h2 className="card-title">Observed counter groups</h2>
          {hits.length === 0 && <p className="empty-state">No live matches.</p>}
          {hits.length > 0 && (
            <div className="datatable-scroll">
              <div className="datahead obs">
                <span>SOURCE</span>
                <span>NODE</span>
                <span>DESTINATION</span>
                <span>EVIDENCE</span>
                <span>PACKETS</span>
              </div>
              {hits.map((h, i) => (
                <div className="datarow obs" key={i}>
                  <span className="truncate" title={h.source}>
                    {h.source || '—'}
                  </span>
                  <span>{h.node || '—'}</span>
                  <span className="truncate" title={h.destination}>
                    {h.destination || '—'}
                  </span>
                  <span>
                    {h.evidence || '—'}
                    {h.protocol ? ` · ${h.protocol}` : ''}
                    {h.direction ? ` · ${h.direction}` : ''}
                  </span>
                  <span>
                    {h.packets ?? 0}
                    {h.alreadyBlocked ? ` (${h.alreadyBlocked} already blocked)` : ''}
                  </span>
                </div>
              ))}
            </div>
          )}
        </section>
      )}

      {mode === 'history' && history && (
        <section className="card span3">
          <p className="eyebrow">HISTORY DENIALS</p>
          <h2 className="card-title">Flowlog matches in window</h2>
          {denials.length === 0 && <p className="empty-state">No historical matches in this window.</p>}
          {denials.length > 0 && (
            <div className="datatable-scroll">
              <div className="datahead obs">
                <span>SOURCE</span>
                <span>DESTINATION</span>
                <span>PACKETS</span>
                <span>REASON</span>
              </div>
              {denials.slice(0, 100).map((d, i) => (
                <div className="datarow obs" key={i}>
                  <span className="truncate">{d.source || '—'}</span>
                  <span className="truncate">{d.destination || '—'}</span>
                  <span>{d.packets ?? 0}</span>
                  <span>{d.reason || '—'}</span>
                </div>
              ))}
            </div>
          )}
          {(history.result?.breakage || []).length > 0 && (
            <div className="list" style={{ marginTop: '1rem' }}>
              {history.result!.breakage!.map((b, i) => (
                <div className="agent wide" key={i}>
                  <b>Breakage note</b>
                  <small>{b.message}</small>
                </div>
              ))}
            </div>
          )}
        </section>
      )}
    </div>
  );
}
