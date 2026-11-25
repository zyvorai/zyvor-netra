// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

import { useEffect, useState } from 'react';
import { api } from '../api';
import PagePulse from '../components/kit/PagePulse';
import { humanBytes } from '../lib/flowDrift';
import { coverageHeadline, coverageQuery, directionLabel, type CoverageReport } from '../lib/netpolCoverage';

export default function PolicyCoverage() {
  const [report, setReport] = useState<CoverageReport>();
  const [namespace, setNamespace] = useState('');
  const [all, setAll] = useState(false);
  const [err, setErr] = useState('');
  const [tick, setTick] = useState(0);

  useEffect(() => {
    let live = true;
    const load = () => {
      api<CoverageReport>(`/api/v1/insights/netpol-coverage${coverageQuery(namespace, '24h', all)}`)
        .then((r) => {
          if (!live) return;
          setReport(r);
          setErr('');
        })
        .catch((e) => {
          if (!live) return;
          // A failed read must not leave an older answer looking current.
          setReport(undefined);
          setErr(String(e?.message || e));
        })
        .finally(() => live && setTick(Date.now()));
    };
    load();
    const t = setInterval(load, 60000);
    return () => {
      live = false;
      clearInterval(t);
    };
  }, [namespace, all]);

  const s = report?.summary;
  const rows = report?.workloads || [];
  const bare = report?.namespacesWithoutPolicy || [];

  return (
    <div className="grid">
      <PagePulse
        tick={tick || undefined}
        error={err || undefined}
        tone={s ? (s.uncovered || s.partial || s.workloads === 0 ? 'warn' : 'ok') : undefined}
        headline={report ? coverageHeadline(report) : undefined}
        figures={[
          { label: 'uncovered', value: s?.uncovered || 0, tone: s?.uncovered ? 'warn' : undefined },
          { label: 'partly covered', value: s?.partial || 0, tone: s?.partial ? 'warn' : undefined },
          { label: 'covered', value: s?.covered || 0 },
          { label: 'open with public traffic', value: s?.attention || 0, tone: s?.attention ? 'warn' : undefined },
        ]}
      />

      <section className="card span3">
        <p className="eyebrow">NETWORKPOLICY COVERAGE</p>
        <h2 className="card-title">Workloads no NetworkPolicy restricts</h2>
        <p>
          Kubernetes accepts all traffic for a pod until a policy selects it for that direction. Only <code>networking.k8s.io</code> NetworkPolicy is read: Cilium, Calico
          and admin policies are not counted, and enforcement by the CNI is not checked. Read-only. Also available as <code>netractl insights netpol-coverage</code> and the{' '}
          <code>netra_insights_netpol_coverage</code> MCP tool.
        </p>
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.75rem', alignItems: 'center' }}>
          <label>
            Namespace <input value={namespace} onChange={(e) => setNamespace(e.target.value)} placeholder="all" style={{ width: '10rem' }} />
          </label>
          <label>
            <input type="checkbox" checked={all} onChange={(e) => setAll(e.target.checked)} /> include covered
          </label>
        </div>
        {err && <p className="empty-state">Needs the Kubernetes API and permission to list NetworkPolicies.</p>}
        {report?.listTruncated && <p className="warning">The list was cut to its bound ({report.total} rows in total).</p>}
        {report && rows.length === 0 && <p className="empty-state">Nothing to list.</p>}
        <div className="list">
          {rows.map((w) => (
            <div className="agent wide" key={`${w.namespace}/${w.kind}/${w.name}`}>
              <b>
                {w.namespace}/{w.name}
                {w.kind ? ` (${w.kind}, ${w.pods} pod${w.pods === 1 ? '' : 's'})` : ''}
              </b>
              <span className={`severity-badge ${w.attention ? 'warning' : 'info'}`}>{w.status}</span>
              <small>
                ingress: {directionLabel(w.ingress)} · egress: {directionLabel(w.egress)}
              </small>
              <small>
                public destinations {w.publicEgress.peers} ({humanBytes(w.publicEgress.bytes)}) · public sources {w.publicIngress.peers}
                {w.policies?.length ? ` · policies: ${w.policies.join(', ')}` : ''}
              </small>
            </div>
          ))}
        </div>
      </section>

      {bare.length > 0 && (
        <section className="card span3">
          <p className="eyebrow">NAMESPACES</p>
          <h2 className="card-title">Namespaces with pods and no NetworkPolicy</h2>
          <p>{bare.join(', ')}</p>
        </section>
      )}

      {(report?.limitations?.length || 0) > 0 && (
        <section className="card span3">
          <p className="eyebrow">LIMITS</p>
          <h2 className="card-title">What this does not say</h2>
          <ul>
            {[...(report?.gaps || []), ...(report?.limitations || [])].map((g) => (
              <li key={g}>{g}</li>
            ))}
          </ul>
        </section>
      )}
    </div>
  );
}
