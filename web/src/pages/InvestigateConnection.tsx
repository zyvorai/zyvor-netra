// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

import { FormEvent, useEffect, useState } from 'react';
import { api } from '../api';
import ExplainFinding from '../components/ExplainFinding';
import { navigate, useRoute } from '../hooks/useInvestigation';
import { routeHash } from '../lib/investigation';

type Event = {
  ts?: string;
  source?: string;
  stage?: string;
  summary?: string;
  confidence?: string;
  link?: string;
};
type Gap = { stage?: string; reason?: string; link?: string };
type Confidence = {
  overall?: string;
  sensorAvailability?: string[];
  samplingBound?: string[];
  staleAttribution?: string[];
  retentionGaps?: string[];
  notes?: string[];
};
type Result = {
  request?: Record<string, unknown>;
  events?: Event[];
  gaps?: Gap[];
  confidence?: Confidence;
  limitations?: string[];
};

const emptyForm = { namespace: '', pod: '', peer: '', port: '', node: '', window: '15m' };

function downloadJSON(name: string, data: unknown) {
  const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = name;
  a.click();
  URL.revokeObjectURL(url);
}

export default function InvestigateConnection() {
  const route = useRoute();
  const [form, setForm] = useState({
    ...emptyForm,
    namespace: route.scope.namespace || '',
    pod: route.scope.pod || '',
    peer: route.scope.query || '',
    node: route.scope.node || '',
  });
  const [result, setResult] = useState<Result>();
  const [err, setErr] = useState('');
  const [busy, setBusy] = useState(false);
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    setForm((f) => ({
      ...f,
      namespace: route.scope.namespace || f.namespace,
      pod: route.scope.pod || f.pod,
      node: route.scope.node || f.node,
      peer: route.scope.query || f.peer,
    }));
  }, [route.scope.namespace, route.scope.pod, route.scope.node, route.scope.query]);

  const syncHash = (next = form) => {
    navigate('investigate', {
      namespace: next.namespace,
      pod: next.pod,
      node: next.node,
      query: next.peer,
    });
  };

  const run = (e?: FormEvent) => {
    e?.preventDefault();
    syncHash();
    setBusy(true);
    setErr('');
    const body: Record<string, unknown> = { window: form.window || '15m' };
    if (form.namespace) body.namespace = form.namespace;
    if (form.pod) body.pod = form.pod;
    if (form.peer) body.peer = form.peer;
    if (form.node) body.node = form.node;
    if (form.port) body.port = Number(form.port);
    api<Result>('/api/v1/investigate/connection', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    })
      .then((d) => {
        setResult(d);
        setBusy(false);
      })
      .catch((ex) => {
        setErr(String(ex.message || ex));
        setBusy(false);
      });
  };

  const copyLink = () => {
    const hash = routeHash('investigate', {
      namespace: form.namespace,
      pod: form.pod,
      node: form.node,
      query: form.peer,
      direction: '',
      protocol: '',
      action: '',
    });
    void navigator.clipboard.writeText(`${window.location.origin}${window.location.pathname}${hash}`).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    });
  };

  return (
    <div className="grid">
      <section className="card span3">
        <p className="eyebrow">SCOPE</p>
        <h2 className="card-title">Compose a failed-connection timeline</h2>
        <p>
          DNS → flow → netlink → policy → drops from existing observe APIs. No decrypt, no rule-ID-at-time-T, never
          mutates.
        </p>
        <form className="filters" style={{ display: 'flex', gap: '0.75rem', flexWrap: 'wrap', marginTop: '0.75rem' }} onSubmit={run}>
          <label>
            Namespace
            <input value={form.namespace} onChange={(e) => setForm({ ...form, namespace: e.target.value })} />
          </label>
          <label>
            Pod
            <input value={form.pod} onChange={(e) => setForm({ ...form, pod: e.target.value })} />
          </label>
          <label>
            Peer
            <input value={form.peer} onChange={(e) => setForm({ ...form, peer: e.target.value })} placeholder="IP or host" />
          </label>
          <label>
            Port
            <input value={form.port} onChange={(e) => setForm({ ...form, port: e.target.value })} inputMode="numeric" />
          </label>
          <label>
            Node
            <input value={form.node} onChange={(e) => setForm({ ...form, node: e.target.value })} />
          </label>
          <label>
            Window
            <input value={form.window} onChange={(e) => setForm({ ...form, window: e.target.value })} placeholder="15m" />
          </label>
          <button type="submit" disabled={busy}>
            {busy ? 'Investigating…' : 'Investigate'}
          </button>
          <button type="button" className="btn-secondary" onClick={copyLink}>
            {copied ? 'Copied' : 'Copy view link'}
          </button>
          {result && (
            <button type="button" className="btn-secondary" onClick={() => downloadJSON('netra-investigate.json', result)}>
              Export JSON
            </button>
          )}
          <button type="button" className="btn-secondary" onClick={() => navigate('flow-observe', { namespace: form.namespace, pod: form.pod, query: form.peer })}>
            Flow observe
          </button>
          <button type="button" className="btn-secondary" onClick={() => navigate('ai')}>
            Ask Netra
          </button>
        </form>
        {err && <p className="warning">{err}</p>}
        <div className="chips" style={{ marginTop: '0.75rem' }}>
          {['Why did this connection fail?', 'Any DNS failure before the drop?', 'Is netlink churn involved?'].map((q) => (
            <button key={q} type="button" className="btn-secondary" onClick={() => navigate('ai', { query: q })}>
              {q}
            </button>
          ))}
        </div>
      </section>

      {result && (
        <>
          <section className="card span3">
            <p className="eyebrow">CONFIDENCE</p>
            <h2 className="card-title">Overall: {result.confidence?.overall || 'unknown'}</h2>
            {(result.confidence?.notes || []).map((n) => (
              <p key={n} className="kit-caption">
                {n}
              </p>
            ))}
            {(result.confidence?.sensorAvailability || []).length > 0 && (
              <p className="kit-caption">Sensors: {(result.confidence?.sensorAvailability || []).join(', ')}</p>
            )}
            {(result.confidence?.staleAttribution || []).length > 0 && (
              <p className="warning">Stale attribution: {(result.confidence?.staleAttribution || []).join('; ')}</p>
            )}
            <ExplainFinding
              page="investigate"
              kind="investigate-connection"
              subject={[form.namespace, form.pod, form.peer].filter(Boolean).join('/')}
              message={`Investigate confidence ${result.confidence?.overall || 'unknown'} with ${(result.events || []).length} events and ${(result.gaps || []).length} gaps.`}
              severity={result.confidence?.overall === 'low' ? 'warning' : 'info'}
            />
          </section>

          <section className="card span3">
            <p className="eyebrow">TIMELINE</p>
            <h2 className="card-title">{(result.events || []).length} evidence event{(result.events || []).length === 1 ? '' : 's'}</h2>
            {(result.events || []).length === 0 && <p className="empty-state">No matching evidence in this window.</p>}
            <div className="list">
              {(result.events || []).map((ev, i) => (
                <div className="agent wide" key={`${ev.ts}-${i}`}>
                  <b>{ev.stage || ev.source || 'event'}</b>
                  <span className={`severity-badge ${ev.confidence === 'high' || ev.confidence === 'exact' ? 'ok' : 'warning'}`}>
                    {ev.confidence || 'unknown'}
                  </span>
                  <span className="truncate" title={ev.summary}>
                    {ev.summary}
                  </span>
                  <small>
                    {ev.ts ? new Date(ev.ts).toLocaleString() : ''}
                    {ev.source ? ` · ${ev.source}` : ''}
                    {ev.link ? (
                      <>
                        {' · '}
                        <a href={ev.link.startsWith('#') || ev.link.startsWith('/') ? ev.link : undefined} onClick={(e) => {
                          if (ev.link?.startsWith('#page=')) {
                            e.preventDefault();
                            window.location.hash = ev.link.slice(1);
                          }
                        }}>
                          open
                        </a>
                      </>
                    ) : null}
                  </small>
                </div>
              ))}
            </div>
          </section>

          <section className="card span3">
            <p className="eyebrow">GAPS</p>
            <h2 className="card-title">Visibility boundary</h2>
            {(result.gaps || []).length === 0 && <p className="empty-state">No declared gaps for this scope.</p>}
            <ul>
              {(result.gaps || []).map((g, i) => (
                <li key={`${g.stage}-${i}`}>
                  <b>{g.stage || 'gap'}</b> — {g.reason}
                  {g.link ? (
                    <>
                      {' '}
                      <a
                        href={g.link.startsWith('#') || g.link.startsWith('/') ? g.link : undefined}
                        onClick={(e) => {
                          if (g.link?.startsWith('#page=')) {
                            e.preventDefault();
                            window.location.hash = g.link.slice(1);
                          }
                        }}
                      >
                        open
                      </a>
                    </>
                  ) : null}
                </li>
              ))}
            </ul>
            {(result.limitations || []).map((l) => (
              <p key={l} className="kit-caption">
                {l}
              </p>
            ))}
          </section>
        </>
      )}
    </div>
  );
}
