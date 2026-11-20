// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

import { useEffect, useState } from 'react';
import { api } from '../api';
import { formatTime, formatValue } from '../lib/metrics';

export type EvidenceTarget = { context: string; node?: string; labels?: Record<string, string>; after: number; before: number };

type Peer = { namespace?: string; workload?: string; peer: string; port: number; protocol?: string; bytes: number; blocked?: number; retransmissions?: number };
type Link = { kind: string; title: string; href: string; why: string };
type Evidence = {
  kinds: string[];
  flowRecords: number;
  topPeers: Peer[];
  kernelDrops?: { name: string; count: number }[] | null;
  captures?: { node: string; startedAt: string; reason: string; artifactId?: string }[] | null;
  anomalous?: { node: string; chart: string; dimension: string; anomalyRate: number }[] | null;
  links: Link[];
  limitations: string[];
};

export function evidencePath(t: EvidenceTarget): string {
  const p = new URLSearchParams({ context: t.context, after: String(t.after), before: String(t.before) });
  if (t.node) p.set('node', t.node);
  const lbl = Object.entries(t.labels || {})
    .filter(([k]) => k === 'namespace' || k === 'workload' || k === 'pod')
    .map(([k, v]) => `${k}:${v}`)
    .join(',');
  if (lbl) p.set('labels', lbl);
  return `/api/v1/metrics/evidence?${p.toString()}`;
}

/** Read-only evidence for a metric window: flows, drops, captures, co-anomalies. */
export default function MetricEvidence({ target, onClose }: { target: EvidenceTarget; onClose: () => void }) {
  const [ev, setEv] = useState<Evidence | null>(null);
  const [err, setErr] = useState('');
  const path = evidencePath(target);
  useEffect(() => {
    let live = true;
    setEv(null);
    setErr('');
    api<Evidence>(path)
      .then((d) => live && setEv(d))
      .catch((e) => live && setErr(String(e.message || e)));
    return () => {
      live = false;
    };
  }, [path]);

  return (
    <div className="metric-evidence">
      <div className="metric-evidence__head">
        <strong>Evidence</strong>
        <span>
          {formatTime(target.after, target.before - target.after)} – {formatTime(target.before, target.before - target.after)}
          {target.node ? ` · ${target.node}` : ''}
        </span>
        <button type="button" onClick={onClose} aria-label="Close evidence">
          ×
        </button>
      </div>
      {err && <p className="warning">{err}</p>}
      {!ev && !err && <p className="muted">Loading…</p>}
      {ev && (
        <>
          <p className="muted">
            {ev.flowRecords} flow records · looking at {ev.kinds.join(', ')}
          </p>
          {ev.topPeers.length > 0 && (
            <table>
              <thead>
                <tr>
                  <th>Workload</th>
                  <th>Peer</th>
                  <th>Bytes</th>
                  <th>Blocked</th>
                  <th>Retrans</th>
                </tr>
              </thead>
              <tbody>
                {ev.topPeers.map((p) => (
                  <tr key={`${p.namespace}/${p.workload}/${p.peer}:${p.port}/${p.protocol}`}>
                    <td>{p.workload ? `${p.namespace}/${p.workload}` : '—'}</td>
                    <td>
                      {p.peer}:{p.port}/{p.protocol}
                    </td>
                    <td>{formatValue(p.bytes)}</td>
                    <td>{p.blocked || 0}</td>
                    <td>{p.retransmissions || 0}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
          {ev.kernelDrops && ev.kernelDrops.length > 0 && (
            <p>
              <b>Kernel drop reasons:</b> {ev.kernelDrops.map((d) => `${d.name} (${d.count})`).join(', ')}
            </p>
          )}
          {ev.captures && ev.captures.length > 0 && (
            <p>
              <b>Captures overlapping:</b> {ev.captures.map((c) => `${c.node} ${c.reason}${c.artifactId ? ` · ${c.artifactId}` : ''}`).join('; ')}
            </p>
          )}
          {ev.anomalous && ev.anomalous.length > 0 && (
            <p>
              <b>Anomalous at the same time:</b> {ev.anomalous.map((a) => `${a.chart}/${a.dimension} ${formatValue(a.anomalyRate)}%`).join(', ')}
            </p>
          )}
          <ul className="metric-evidence__links">
            {ev.links.map((l) => (
              <li key={l.href}>
                <code>{l.href}</code> — {l.title}: {l.why}
              </li>
            ))}
          </ul>
        </>
      )}
    </div>
  );
}
