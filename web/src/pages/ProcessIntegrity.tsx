// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

import { useEffect, useState } from 'react';
import { api } from '../api';
import PagePulse from '../components/kit/PagePulse';
import { navigate } from '../hooks/useInvestigation';

type Finding = {
  severity?: string;
  comm?: string;
  pid?: number;
  node?: string;
  namespace?: string;
  pod?: string;
  change?: string;
  kind?: string;
  note?: string;
  message?: string;
};

function FindingsList({ title, empty, data }: { title: string; empty: string; data: any }) {
  const rows: Finding[] = data?.findings || data?.items || data?.changes || [];
  const gap = data?.coverageGap || data?.coverageGaps;
  return (
    <section className="card span3">
      <p className="eyebrow">{title}</p>
      <h2 className="card-title">
        {rows.length} finding{rows.length === 1 ? '' : 's'}
        {data?.enabled === false ? ' · sensor off' : ''}
      </h2>
      {gap && <p className="warning">Coverage gap after agent restart — in-memory diffs reset.</p>}
      <div className="list">
        {rows.length === 0 && <p className="empty-state">{empty}</p>}
        {rows.slice(0, 80).map((f, i) => (
          <div className="agent wide" key={i}>
            <b>
              {f.comm || f.kind || 'process'}
              {f.pid != null ? ` · pid ${f.pid}` : ''}
            </b>
            {f.severity && (
              <span className={`severity-badge ${f.severity === 'high' || f.severity === 'critical' ? 'warning' : 'info'}`}>
                {f.severity}
              </span>
            )}
            <small>
              {[f.node, f.namespace && f.pod ? `${f.namespace}/${f.pod}` : '', f.change, f.message || f.note]
                .filter(Boolean)
                .join(' · ')}
            </small>
          </div>
        ))}
      </div>
    </section>
  );
}

export default function ProcessIntegrity() {
  const [cap, setCap] = useState<any>();
  const [ns, setNs] = useState<any>();
  const [exe, setExe] = useState<any>();
  const [err, setErr] = useState('');
  const [tick, setTick] = useState(0);

  useEffect(() => {
    const load = () =>
      Promise.all([
        api<any>('/api/v1/ebpf/capdrift'),
        api<any>('/api/v1/ebpf/nsdrift'),
        api<any>('/api/v1/ebpf/exehash'),
      ])
        .then(([c, n, e]) => {
          setCap(c);
          setNs(n);
          setExe(e);
          setErr('');
          setTick(Date.now());
        })
        .catch((e) => setErr(String(e.message || e)));
    load();
    const t = setInterval(load, 20000);
    return () => clearInterval(t);
  }, []);

  const capN = (cap?.findings || cap?.items || []).length;
  const nsN = (ns?.findings || ns?.items || []).length;
  const exeN = (exe?.findings || exe?.items || []).length;

  return (
    <div className="grid">
      <PagePulse
        tick={tick || undefined}
        error={err || undefined}
        tone={capN + nsN + exeN ? 'warn' : tick ? 'ok' : undefined}
        headline={tick ? `Cap ${capN} · netns ${nsN} · exe-hash ${exeN}` : undefined}
        figures={[
          { label: 'cap drift', value: capN, tone: capN ? ('warn' as const) : undefined },
          { label: 'ns drift', value: nsN, tone: nsN ? ('warn' as const) : undefined },
          { label: 'exe-hash', value: exeN, tone: exeN ? ('warn' as const) : undefined },
        ]}
      />
      <section className="card span3">
        <p className="eyebrow">PROCESS INTEGRITY</p>
        <h2 className="card-title">Cap / netns / exe-hash observe</h2>
        <p>
          Agent-sourced from periodic <code>/proc</code> (needs <code>NETRA_PROCMETA_ENABLED</code>). Comm and pid only —
          never argv, environ or Secret contents. Exe-hash deny stays a separate leased step.
        </p>
        <div className="chips">
          <button type="button" className="btn-secondary" onClick={() => navigate('health')}>
            Health
          </button>
          <button type="button" className="btn-secondary" onClick={() => navigate('security-review')}>
            Security Review
          </button>
          <button type="button" className="btn-secondary" onClick={() => navigate('ebpf')}>
            Firewall
          </button>
          <button
            type="button"
            className="btn-secondary"
            disabled={!tick}
            onClick={() => {
              const blob = new Blob([JSON.stringify({ capdrift: cap, nsdrift: ns, exehash: exe }, null, 2)], {
                type: 'application/json',
              });
              const url = URL.createObjectURL(blob);
              const a = document.createElement('a');
              a.href = url;
              a.download = 'netra-process-integrity.json';
              a.click();
              URL.revokeObjectURL(url);
            }}
          >
            Export JSON
          </button>
        </div>
        {err && <p className="warning">{err}</p>}
      </section>

      <FindingsList title="CAPABILITY DRIFT" empty="No capability-change findings." data={cap} />
      <FindingsList title="NETNS DRIFT" empty="No namespace-change findings." data={ns} />
      <FindingsList title="EXE-HASH DRIFT" empty="No exe-hash-change findings." data={exe} />
    </div>
  );
}
