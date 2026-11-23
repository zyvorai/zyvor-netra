// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

import { useEffect, useState } from 'react';
import { api } from '../api';
import PagePulse from '../components/kit/PagePulse';
import {
  floodHeadline,
  humanEta,
  severityTone,
  versionShare,
  worstCapacity,
  type CapacityResult,
  type FloodResult,
  type TlsPostureResult,
} from '../lib/netrisk';

export default function NetworkRisk() {
  const [floods, setFloods] = useState<FloodResult>();
  const [capacity, setCapacity] = useState<CapacityResult>();
  const [tls, setTls] = useState<TlsPostureResult>();
  const [err, setErr] = useState('');
  const [tick, setTick] = useState(0);

  useEffect(() => {
    const load = () => {
      Promise.allSettled([
        api<FloodResult>('/api/v1/security/floods'),
        api<CapacityResult>('/api/v1/capacity/forecast'),
        api<TlsPostureResult>('/api/v1/insights/tls-posture'),
      ]).then(([f, c, t]) => {
        if (f.status === 'fulfilled') setFloods(f.value);
        if (c.status === 'fulfilled') setCapacity(c.value);
        if (t.status === 'fulfilled') setTls(t.value);
        const failed = [f, c, t].filter((x) => x.status === 'rejected') as PromiseRejectedResult[];
        setErr(failed.map((x) => String(x.reason?.message || x.reason)).join('; '));
        setTick(Date.now());
      });
    };
    load();
    const t = setInterval(load, 15000);
    return () => clearInterval(t);
  }, []);

  const worst = worstCapacity(capacity);
  const nodeF = floods?.nodeFindings || [];
  const srcF = floods?.sourceFindings || [];
  const gaps = [...(floods?.gaps || []), ...(capacity?.gaps || [])];

  return (
    <div className="grid">
      <PagePulse
        tick={tick || undefined}
        error={err || undefined}
        tone={nodeF.length || srcF.length || worst ? 'warn' : floods ? 'ok' : undefined}
        headline={floods ? floodHeadline(floods) : undefined}
        figures={[
          { label: 'node floods', value: nodeF.length, tone: nodeF.length ? 'warn' : undefined },
          { label: 'flooding sources', value: srcF.length, tone: srcF.length ? 'warn' : undefined },
          { label: 'capacity at risk', value: worst ? 1 : 0, tone: worst ? 'warn' : undefined },
          { label: 'legacy TLS hellos', value: tls?.summary?.legacyMaxHellos || 0, tone: tls?.summary?.legacyMaxHellos ? 'warn' : undefined },
        ]}
      />

      <section className="card span3">
        <p className="eyebrow">FLOODS</p>
        <h2 className="card-title">Inbound volumetric floods</h2>
        <p>
          SYN, UDP, ICMP and fragment rates per node against their own baseline, and the sources driving them. A suggested deny is text and a
          preview request only: review it with Deny Preview, which runs the self-lockout check. Nothing here applies a rule. Source addresses of a
          flood are often spoofed.
        </p>
        {nodeF.length === 0 && srcF.length === 0 && <p className="empty-state">No flood findings in this window.</p>}
        <div className="list">
          {nodeF.map((f, i) => (
            <div className="agent wide" key={`n${i}`}>
              <b>{f.message}</b>
              <span className={`severity-badge ${severityTone(f.severity)}`}>{f.vector}</span>
              <small>
                {f.node} · {f.currentPerSecond}/s now, baseline {f.baselinePerSecond}/s
              </small>
            </div>
          ))}
          {srcF.map((f, i) => (
            <div className="agent wide" key={`s${i}`}>
              <b>{f.message}</b>
              <span className={`severity-badge ${severityTone(f.severity)}`}>{f.class}</span>
              <small>{f.node}</small>
              {f.suggestion ? (
                <details>
                  <summary>
                    Suggested deny: {f.suggestion.value} ({f.suggestion.direction}) — lockout {f.lockout?.risk || 'unchecked'}
                  </summary>
                  <pre>{JSON.stringify(f.suggestion.previewRequest, null, 2)}</pre>
                  <ol>
                    {f.suggestion.steps.map((s, j) => (
                      <li key={j}>{s}</li>
                    ))}
                  </ol>
                </details>
              ) : (
                <small>{f.noSuggestion}</small>
              )}
            </div>
          ))}
        </div>
      </section>

      <section className="card span3">
        <p className="eyebrow">CAPACITY</p>
        <h2 className="card-title">Conntrack and ephemeral-port exhaustion</h2>
        {(capacity?.forecasts || []).length === 0 && <p className="empty-state">No utilization series yet (needs the metrics platform).</p>}
        <div className="list">
          {(capacity?.forecasts || []).map((f, i) => (
            <div className="agent wide" key={i}>
              <b>
                {f.node} · {f.resource}: {f.current.toFixed(1)}% of {f.limit}%
              </b>
              <span className={`severity-badge ${severityTone(f.severity)}`}>{f.severity}</span>
              <small>
                {f.secondsToExhaustion !== undefined ? `exhausted in about ${humanEta(f.secondsToExhaustion)} (${f.confidence || 'low'} confidence)` : f.note || 'no forecast'}
              </small>
            </div>
          ))}
        </div>
        {capacity?.caveats?.map((c, i) => (
          <p className="empty-state" key={i}>
            {c}
          </p>
        ))}
      </section>

      <section className="card span3">
        <p className="eyebrow">TLS POSTURE</p>
        <h2 className="card-title">TLS versions clients offer</h2>
        <p>
          From JA4 ClientHello metadata: the highest TLS version a client offers, not what was negotiated. No decryption, no certificates.
        </p>
        {tls?.summary && (
          <p>
            {tls.summary.hellos} sampled hellos from {tls.summary.workloadsSeen} workloads: {versionShare(tls.summary.versions)}; {tls.summary.tls13Percent}% offer TLS 1.3;{' '}
            {tls.summary.ech} with ECH.
          </p>
        )}
        {(tls?.findings || []).length === 0 && <p className="empty-state">No legacy-maximum or unparsed clients sampled.</p>}
        <div className="list">
          {(tls?.findings || []).map((f, i) => (
            <div className="agent wide" key={i}>
              <b>{f.message}</b>
              <span className={`severity-badge ${severityTone(f.severity)}`}>{f.kind}</span>
              <small>{[f.namespace, f.workload, f.sni].filter(Boolean).join(' · ')}</small>
            </div>
          ))}
        </div>
      </section>

      {gaps.length > 0 && (
        <section className="card span3">
          <p className="eyebrow">GAPS</p>
          <h2 className="card-title">What this page cannot see</h2>
          <ul>
            {gaps.map((g, i) => (
              <li key={i}>{g}</li>
            ))}
          </ul>
        </section>
      )}
    </div>
  );
}
