// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

import { useEffect, useState } from 'react';
import { api } from '../api';
import PagePulse from '../components/kit/PagePulse';
import { navigate } from '../hooks/useInvestigation';

type Pack = {
  generatedAt?: string;
  report?: { headline?: string; mode?: string; healthScore?: number; summary?: string };
  fleet?: { agentCount?: number; staleAgents?: number; workloads?: number };
  coverage?: { detachedPrograms?: number; missingMapEntries?: number; quiet?: boolean };
  audit?: { total?: number };
  reasons?: { total?: number; blocked?: number };
  playbook?: { steps?: Array<{ title?: string; detail?: string }> };
};

function downloadText(name: string, body: string, mime: string) {
  const blob = new Blob([body], { type: mime });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = name;
  a.click();
  URL.revokeObjectURL(url);
}

async function fetchMarkdown(): Promise<string> {
  const r = await fetch('/api/v1/handoff?format=markdown', { credentials: 'same-origin' });
  if (!r.ok) throw new Error(`${r.status}`);
  return r.text();
}

export default function Handoff() {
  const [md, setMd] = useState('');
  const [json, setJson] = useState<Pack>();
  const [err, setErr] = useState('');
  const [tick, setTick] = useState(0);
  const [copied, setCopied] = useState(false);

  const load = () => {
    Promise.all([fetchMarkdown(), api<Pack>('/api/v1/handoff?format=json')])
      .then(([text, pack]) => {
        setMd(text);
        setJson(pack);
        setErr('');
        setTick(Date.now());
      })
      .catch((e) => setErr(String(e.message || e)));
  };

  useEffect(() => {
    load();
    const t = setInterval(load, 60000);
    return () => clearInterval(t);
  }, []);

  const rep = json?.report;
  const fl = json?.fleet;
  const cov = json?.coverage;

  return (
    <div className="grid">
      <PagePulse
        tick={tick || undefined}
        error={err || undefined}
        tone={err ? 'warn' : tick ? 'ok' : undefined}
        headline={rep?.headline || (tick ? 'On-call handoff pack ready.' : undefined)}
        figures={[
          { label: 'health', value: rep?.healthScore },
          { label: 'agents', value: fl?.agentCount },
          { label: 'stale', value: fl?.staleAgents, tone: fl?.staleAgents ? ('warn' as const) : undefined },
          { label: 'mode', value: rep?.mode },
        ]}
      />
      <section className="card span3">
        <p className="eyebrow">SHIFT HANDOFF</p>
        <h2 className="card-title">Report + coverage + fleet + audit + drop reasons</h2>
        <p>Observe-only pack for the next on-call. Never applies mode, rules, or policy.</p>
        <div className="chips" style={{ marginTop: '0.75rem' }}>
          <button type="button" onClick={load}>
            Refresh
          </button>
          <button
            type="button"
            className="btn-secondary"
            onClick={() => {
              void navigator.clipboard.writeText(md).then(() => {
                setCopied(true);
                setTimeout(() => setCopied(false), 1500);
              });
            }}
            disabled={!md}
          >
            {copied ? 'Copied' : 'Copy markdown'}
          </button>
          <button type="button" className="btn-secondary" disabled={!md} onClick={() => downloadText('netra-handoff.md', md, 'text/markdown')}>
            Download .md
          </button>
          <button
            type="button"
            className="btn-secondary"
            disabled={!json}
            onClick={() => downloadText('netra-handoff.json', JSON.stringify(json || {}, null, 2), 'application/json')}
          >
            Download JSON
          </button>
          <button type="button" className="btn-secondary" onClick={() => navigate('ai')}>
            Ask Netra
          </button>
          <button type="button" className="btn-secondary" onClick={() => navigate('report')}>
            Report
          </button>
        </div>
        {cov && (
          <p className="kit-caption" style={{ marginTop: '0.75rem' }}>
            Coverage: detached {cov.detachedPrograms ?? 0}, missing maps {cov.missingMapEntries ?? 0}
            {cov.quiet ? ', quiet' : ''} · Audit {json?.audit?.total ?? 0} · Drop events {json?.reasons?.total ?? 0} (
            {json?.reasons?.blocked ?? 0} blocked)
          </p>
        )}
      </section>
      <section className="card span3">
        <p className="eyebrow">MARKDOWN</p>
        <pre className="kit-pre" style={{ whiteSpace: 'pre-wrap', maxHeight: '70vh', overflow: 'auto' }}>
          {md || (err ? '' : 'Loading…')}
        </pre>
      </section>
    </div>
  );
}
