// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
import { useEffect, useMemo, useState } from 'react';
import { api } from '../api';
import PagePulse from '../components/kit/PagePulse';
import { countTone } from '../components/kit/tone';

type Finding = {
  kind?: string;
  severity?: string;
  message?: string;
  domain?: string;
  namespace?: string;
  pod?: string;
  node?: string;
  workload?: string;
  observedAt?: string;
  firstSeen?: string;
  lastSeen?: string;
};

type Snapshot = {
  queriesSeen?: number;
  domainsTracked?: number;
  activeFindings?: number;
  attemptsSeen?: number;
  workloadsTracked?: number;
  findingsTotal?: Record<string, number>;
};

export default function Detect() {
  const [dns, setDns] = useState<{ findings?: Finding[]; snapshot?: Snapshot } | null>(null);
  const [scan, setScan] = useState<{ findings?: Finding[]; snapshot?: Snapshot } | null>(null);
  const [err, setErr] = useState('');
  const [tick, setTick] = useState(0);
  const [tab, setTab] = useState<'dns' | 'scan'>('dns');

  const load = () => {
    Promise.all([
      api<{ findings?: Finding[]; snapshot?: Snapshot }>('/api/v1/ebpf/dns-findings').catch((e) => {
        throw Object.assign(e, { where: 'dns' });
      }),
      api<{ findings?: Finding[]; snapshot?: Snapshot }>('/api/v1/ebpf/scan-findings').catch((e) => {
        throw Object.assign(e, { where: 'scan' });
      }),
    ])
      .then(([d, s]) => {
        setDns(d);
        setScan(s);
        setErr('');
        setTick((t) => t + 1);
      })
      .catch((e) => setErr(String(e)));
  };

  useEffect(() => {
    load();
    const t = setInterval(load, 10000);
    return () => clearInterval(t);
  }, []);

  const dnsFindings = dns?.findings || [];
  const scanFindings = scan?.findings || [];
  const active = (dns?.snapshot?.activeFindings || dnsFindings.length) + (scan?.snapshot?.activeFindings || scanFindings.length);
  const rows = tab === 'dns' ? dnsFindings : scanFindings;

  const kindCounts = useMemo(() => {
    const m: Record<string, number> = {};
    for (const f of [...dnsFindings, ...scanFindings]) {
      const k = f.kind || 'unknown';
      m[k] = (m[k] || 0) + 1;
    }
    return m;
  }, [dnsFindings, scanFindings]);

  return (
    <div className="grid">
      <PagePulse
        headline={
          active
            ? `${active} active DNS/scan finding${active === 1 ? '' : 's'} — observe only; open Security Review to correlate.`
            : 'DNS anomaly and scan/fan-out detectors are quiet. Findings never auto-enforce.'
        }
        tone={active ? 'warn' : undefined}
        tick={tick}
        error={err || undefined}
        figures={[
          { label: 'DNS findings', value: dnsFindings.length, tone: dnsFindings.length ? countTone(dnsFindings.length) : undefined },
          { label: 'scan findings', value: scanFindings.length, tone: scanFindings.length ? countTone(scanFindings.length) : undefined },
          { label: 'DNS queries seen', value: dns?.snapshot?.queriesSeen },
          { label: 'scan attempts', value: scan?.snapshot?.attemptsSeen },
          { label: 'domains tracked', value: dns?.snapshot?.domainsTracked },
          { label: 'workloads tracked', value: scan?.snapshot?.workloadsTracked },
        ]}
      />

      <section className="card span3">
        <p className="eyebrow">GA DETECTORS</p>
        <h2 className="card-title">DNS anomaly and scan detect</h2>
        <p>
          Review-only timelines from the controller detectors. Absence of a finding is not proof of innocence.
          Correlate on Security Review; leased auto-mitigate stays inert without an enforce lease.
        </p>
        <div className="filters" style={{ display: 'flex', gap: '0.75rem', marginTop: '0.75rem' }}>
          <button type="button" className={tab === 'dns' ? 'active' : ''} onClick={() => setTab('dns')}>
            DNS ({dnsFindings.length})
          </button>
          <button type="button" className={tab === 'scan' ? 'active' : ''} onClick={() => setTab('scan')}>
            Scan ({scanFindings.length})
          </button>
          <button type="button" onClick={load}>
            Refresh
          </button>
          <a className="overview-link" href="#page=security-review">
            Open Security Review
          </a>
          <a className="overview-link" href="#page=ebpf">
            Auto-mitigate status
          </a>
        </div>
        {Object.keys(kindCounts).length > 0 && (
          <div className="metrics" style={{ marginTop: '1rem' }}>
            {Object.entries(kindCounts).map(([k, n]) => (
              <div key={k}>
                <b>{n}</b>
                <span>{k}</span>
              </div>
            ))}
          </div>
        )}
      </section>

      {err && (
        <section className="card span3">
          <p className="warning">{err}</p>
        </section>
      )}

      <section className="card span3">
        <p className="eyebrow">{tab === 'dns' ? 'DNS FINDINGS' : 'SCAN FINDINGS'}</p>
        <h2 className="card-title">{tab === 'dns' ? 'Domain and query anomalies' : 'Fan-out, lateral, and SYN patterns'}</h2>
        {rows.length === 0 && <p className="empty-state">No active findings in this detector.</p>}
        <div className="list">
          {rows.slice(0, 80).map((f, i) => {
            const who = [f.namespace, f.pod || f.workload || f.domain].filter(Boolean).join('/') || f.node || '—';
            return (
              <div className="agent wide" key={i}>
                <b>{f.kind || 'finding'}</b>
                <span className={`severity-badge ${f.severity || 'warning'}`}>{f.severity || 'warning'}</span>
                <span className="truncate" title={who}>
                  {who}
                </span>
                <small>{f.message || ''}</small>
              </div>
            );
          })}
        </div>
      </section>
    </div>
  );
}
