// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

import { useEffect, useState } from 'react';
import { api } from '../api';

type Kind = 'blocks' | 'audit' | 'events' | 'flows';
type Row = { at?: string; severity?: string; action?: string; target?: string; subject?: string; message?: string; kind?: string; node?: string };
type Export = { count?: number; items?: Row[]; note?: string };
type Status = { pull?: string[]; encodings?: string[]; syslogConfigured?: boolean; note?: string };

const KINDS: { id: Kind; label: string; path: string }[] = [
  { id: 'blocks', label: 'Blocks', path: '/api/v1/export/blocks?format=json&limit=25' },
  { id: 'audit', label: 'Audit', path: '/api/v1/export/audit?format=json&limit=25' },
  { id: 'events', label: 'Events', path: '/api/v1/export/events?format=json&limit=25' },
  { id: 'flows', label: 'Flows', path: '/api/v1/export/flows?format=json&limit=25' },
];

export default function SIEMExports() {
  const [kind, setKind] = useState<Kind>('blocks');
  const [data, setData] = useState<Export>();
  const [status, setStatus] = useState<Status>();
  const [err, setErr] = useState('');

  useEffect(() => {
    api<Status>('/api/v1/export/status')
      .then(setStatus)
      .catch(() => undefined);
  }, []);

  useEffect(() => {
    const spec = KINDS.find((k) => k.id === kind)!;
    const load = () =>
      api<Export>(spec.path)
        .then((d) => {
          setData(d);
          setErr('');
        })
        .catch((e) => setErr(String(e.message || e)));
    load();
    const t = setInterval(load, 20000);
    return () => clearInterval(t);
  }, [kind]);

  return (
    <section className="card span3">
      <p className="eyebrow">SIEM PULL EXPORTS</p>
      <h2 className="card-title">{data?.count ?? 0} recent · {kind}</h2>
      <p>
        Observe-only pull exports (JSON preview). Also CEF / syslog / OTLP via{' '}
        <code>netractl export {kind} --format …</code>.{' '}
        {status?.syslogConfigured ? 'Syslog push configured.' : 'Syslog push not configured.'}
      </p>
      <div className="chips">
        {KINDS.map((k) => (
          <button key={k.id} type="button" className={kind === k.id ? 'primary' : ''} onClick={() => setKind(k.id)}>
            {k.label}
          </button>
        ))}
      </div>
      {err && <p className="warning">{err}</p>}
      <div className="list">
        {(data?.items || []).length === 0 && !err && <p className="empty-state">No rows for this export yet.</p>}
        {(data?.items || []).map((r, i) => (
          <div className="agent wide" key={i}>
            <b>{r.action || r.kind || kind}</b>
            {r.severity && <span className={`severity-badge ${r.severity}`}>{r.severity}</span>}
            <small>
              {[r.subject || r.target, r.node, r.message, r.at ? new Date(r.at).toLocaleString() : ''].filter(Boolean).join(' · ')}
            </small>
          </div>
        ))}
      </div>
    </section>
  );
}
