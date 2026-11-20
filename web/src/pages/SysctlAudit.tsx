import { useEffect, useState } from 'react';
import { api } from '../api';
import PagePulse from '../components/kit/PagePulse';
import { countTone } from '../components/kit/tone';

const CATEGORY_LABELS: Record<string, string> = {
  security: 'Security',
  ipv6: 'IPv6 Posture',
  tcp: 'TCP Tuning',
  conntrack: 'Conntrack Timeouts',
  'arp-bridge': 'ARP/Neighbor + Bridge',
};
const CATEGORY_ORDER = ['security', 'ipv6', 'tcp', 'conntrack', 'arp-bridge'];
const PER_INTERFACE_CATEGORIES = new Set(['security', 'ipv6', 'arp-bridge']);

export default function SysctlAudit() {
  const [data, setData] = useState<any>();
  const [err, setErr] = useState('');
  useEffect(() => {
    const load = () =>
      api<any>('/api/v1/ebpf/sysctl-audit?limit=100')
        .then((d) => {
          setData(d);
          setErr('');
        })
        .catch((e) => setErr(String(e)));
    load();
    const t = setInterval(load, 15000);
    return () => clearInterval(t);
  }, []);

  const s = data?.summary || {};
  const outliers = data?.outliers || [];
  const nodes = data?.nodes || [];

  return (
    <div className="grid">
      {err && (
        <section className="card span3">
          <p className="warning">{err}</p>
        </section>
      )}
      <PagePulse
        headline={data ? ((s.critical || 0) ? `${s.critical} critical hardening finding${s.critical === 1 ? '' : 's'}.` : (s.warnings || 0) ? `${s.warnings} sysctl warning${s.warnings === 1 ? '' : 's'}, nothing critical.` : 'Hardening baseline holds on every node.') : undefined}
        tone={data ? ((s.critical || 0) ? 'bad' : (s.warnings || 0) ? 'warn' : 'ok') : undefined}
        tick={data}
        error={err || undefined}
        figures={[
          { label: 'fresh nodes', value: data ? (s.nodes || 0) : undefined },
          { label: 'critical', value: data ? (s.critical || 0) : undefined, tone: data ? ((s.critical || 0) ? 'bad' : 'ok') : undefined },
          { label: 'warnings', value: data ? (s.warnings || 0) : undefined, tone: data ? countTone(s.warnings || 0) : undefined },
          { label: 'informational', value: data ? (s.informational || 0) : undefined },
          { label: 'outliers', value: data ? (s.outliers || 0) : undefined, tone: data ? countTone(s.outliers || 0) : undefined },
          { label: 'findings', value: data ? (s.findings || 0) : undefined },
        ]}
      />
      <p className="kit-caption span3">
        A flat, baseline-checked inventory of network hardening and tuning sysctls — separate from Congestion Map's evidence-correlated
        findings. Most sysctls outside core hardening/TCP-lifecycle have no universal "correct" value and are reported informationally,
        never forced into a false pass/fail. Netra never writes sysctls.
      </p>

      <section className="card span3">
        <p className="eyebrow">OUTLIERS</p>
        <h2 className="card-title">Where nodes disagree</h2>
        <div className="list">
          {!outliers.length && <p className="empty-state">No nodes disagree with the cluster baseline right now.</p>}
          {outliers.map((o: any, i: number) => (
            <div className="agent wide" key={`${o.name}-${o.interface || ''}-${i}`}>
              <b>
                {o.name}
                {o.interface ? ` (${o.interface})` : ''}
              </b>
              <span>{CATEGORY_LABELS[o.category] || o.category}</span>
              <small>majority value: {o.majorityValue}</small>
              <small>diverges on: {(o.outlierNodes || []).join(', ')}</small>
            </div>
          ))}
        </div>
      </section>

      {nodes.map((n: any) => {
        const entriesByCategory: Record<string, any[]> = {};
        for (const e of n.snapshot?.entries || []) {
          (entriesByCategory[e.category] ||= []).push(e);
        }
        return (
          <section className="card span3" key={n.node}>
            <p className="eyebrow">SYSCTL AUDIT · {n.node}</p>
            <div className="list">
              {!(n.findings || []).filter((f: any) => !f.informational).length && (
                <p className="empty-state">No hardening findings on this node.</p>
              )}
              {(n.findings || [])
                .filter((f: any) => !f.informational)
                .map((f: any, i: number) => (
                  <div className="agent wide" key={`${f.name}-${f.interface || ''}-${i}`}>
                    <b>
                      {f.name}
                      {f.interface ? ` (${f.interface})` : ''}
                    </b>
                    <span className={`severity-badge ${f.severity === 'info' ? 'info' : f.severity}`}>{f.severity}</span>
                    <span>{CATEGORY_LABELS[f.category] || f.category}</span>
                    <small>
                      current: {f.currentValue}
                      {f.expectedValue ? ` · expected: ${f.expectedValue}` : ''}
                    </small>
                    <small>{f.rationale}</small>
                  </div>
                ))}
            </div>
            {CATEGORY_ORDER.filter((c) => entriesByCategory[c]?.length).map((category) => {
              const entries = entriesByCategory[category];
              if (PER_INTERFACE_CATEGORIES.has(category)) {
                const byInterface: Record<string, any[]> = {};
                for (const e of entries) (byInterface[e.interface || ''] ||= []).push(e);
                return (
                  <details key={category}>
                    <summary>
                      {CATEGORY_LABELS[category]} ({entries.length})
                    </summary>
                    {Object.keys(byInterface)
                      .sort()
                      .map((iface) => (
                        <details key={iface}>
                          <summary>{iface || '(global)'}</summary>
                          <div className="list">
                            {byInterface[iface].map((t: any) => (
                              <div className="agent wide" key={t.name}>
                                <b>{t.name}</b>
                                <code>{t.value}</code>
                                <small>{t.source}</small>
                              </div>
                            ))}
                          </div>
                        </details>
                      ))}
                  </details>
                );
              }
              return (
                <details key={category}>
                  <summary>
                    {CATEGORY_LABELS[category]} ({entries.length})
                  </summary>
                  <div className="list">
                    {entries.map((t: any) => (
                      <div className="agent wide" key={t.name}>
                        <b>{t.name}</b>
                        <code>{t.value}</code>
                        <small>{t.source}</small>
                      </div>
                    ))}
                  </div>
                </details>
              );
            })}
            {!CATEGORY_ORDER.some((c) => entriesByCategory[c]?.length) && (
              <p className="empty-state">No entries collected for this node.</p>
            )}
          </section>
        );
      })}
    </div>
  );
}
