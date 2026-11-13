// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

import { FormEvent, useEffect, useState } from 'react';
import { api } from '../api';
import { useRoute } from '../hooks/useInvestigation';

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
  samplingLoss?: string[];
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

  useEffect(() => {
    setForm((f) => ({
      ...f,
      namespace: route.scope.namespace || f.namespace,
      pod: route.scope.pod || f.pod,
      node: route.scope.node || f.node,
      peer: route.scope.query || f.peer,
    }));
  }, [route.scope.namespace, route.scope.pod, route.scope.node, route.scope.query]);

  const run = (e?: FormEvent) => {
    e?.preventDefault();
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
        </form>
        {err && <p className="warning">{err}</p>}
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
                  <small>{ev.ts ? new Date(ev.ts).toLocaleString() : ''}{ev.source ? ` · ${ev.source}` : ''}</small>
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
