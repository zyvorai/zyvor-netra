// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
import { useEffect, useMemo, useState } from 'react';
import { api } from '../api';
import PagePulse from '../components/kit/PagePulse';
import { countTone } from '../components/kit/tone';

type Attachment = {
  name?: string;
  type?: string;
  attachType?: string;
  interface?: string;
  owner?: string;
  expected?: boolean;
  present?: boolean;
  foreign?: boolean;
  cilium?: boolean;
};

type NodeView = {
  node?: string;
  attachments?: Attachment[];
  findings?: { severity?: string; message?: string; kind?: string; signal?: string }[];
  expectedMissing?: number;
  foreignCount?: number;
  netraCount?: number;
};

export default function BpfAttachments() {
  const [node, setNode] = useState('');
  const [data, setData] = useState<{ nodes?: NodeView[]; summary?: any } | NodeView[] | null>(null);
  const [err, setErr] = useState('');
  const [tick, setTick] = useState(0);

  const load = () => {
    const q = node.trim() ? `?node=${encodeURIComponent(node.trim())}` : '';
    api<any>(`/api/v1/ebpf/attachments${q}`)
      .then((x) => {
        setData(x);
        setErr('');
        setTick((t) => t + 1);
      })
      .catch((e) => setErr(String(e)));
  };

  useEffect(() => {
    load();
    const t = setInterval(load, 15000);
    return () => clearInterval(t);
  }, [node]);

  const nodes: NodeView[] = useMemo(() => {
    if (!data) return [];
    if (Array.isArray(data)) return data;
    return data.nodes || [];
  }, [data]);

  const allFindings = nodes.flatMap((n) => (n.findings || []).map((f) => ({ ...f, node: n.node })));
  const missing = nodes.reduce((a, n) => a + (n.expectedMissing || 0), 0);
  const foreign = nodes.reduce((a, n) => a + (n.foreignCount || 0), 0);
  const netra = nodes.reduce((a, n) => a + (n.netraCount || (n.attachments || []).filter((x) => (x.owner || '').includes('netra') || x.name?.startsWith('netra')).length), 0);

  const rows = nodes.flatMap((n) =>
    (n.attachments || []).map((a) => ({
      ...a,
      node: n.node,
    })),
  );

  return (
    <div className="grid">
      <PagePulse
        headline={
          missing
            ? `${missing} expected Netra hook${missing === 1 ? '' : 's'} missing — restart the agent on that node; this board never reattaches.`
            : allFindings.length
              ? `${allFindings.length} attachment finding${allFindings.length === 1 ? '' : 's'} — inventory only.`
              : 'Read-only BPF attachment inventory. Cilium-owned programs are listed and never touched.'
        }
        tone={missing ? 'bad' : allFindings.length ? 'warn' : undefined}
        tick={tick}
        error={err || undefined}
        figures={[
          { label: 'nodes', value: nodes.length },
          { label: 'netra programs', value: netra },
          { label: 'expected missing', value: missing, tone: missing ? 'bad' : undefined },
          { label: 'foreign', value: foreign, tone: foreign ? countTone(foreign) : undefined },
          { label: 'findings', value: allFindings.length },
        ]}
      />

      <section className="card span3">
        <p className="eyebrow">INVENTORY</p>
        <h2 className="card-title">What the kernel reports</h2>
        <p>
          This page never attaches, detaches, or replaces a program. Missing Netra hooks: restart the node agent.
          Cilium programs stay Cilium&apos;s.
        </p>
        <div className="filters" style={{ display: 'flex', gap: '0.75rem', marginTop: '0.75rem' }}>
          <label>
            Node <input value={node} onChange={(e) => setNode(e.target.value)} placeholder="optional" />
          </label>
          <button type="button" onClick={load}>
            Refresh
          </button>
        </div>
      </section>

      {err && (
        <section className="card span3">
          <p className="warning">{err}</p>
        </section>
      )}

      <section className="card span3">
        <p className="eyebrow">FINDINGS</p>
        <h2 className="card-title">Hook drift</h2>
        {allFindings.length === 0 && <p className="empty-state">No attachment findings.</p>}
        <div className="list">
          {allFindings.slice(0, 40).map((f, i) => (
            <div className="agent wide" key={i}>
              <b>{f.signal || f.kind || 'drift'}</b>
              <span className={`severity-badge ${f.severity || 'info'}`}>{f.severity || 'info'}</span>
              <span>{f.node || '—'}</span>
              <small>{f.message || ''}</small>
            </div>
          ))}
        </div>
      </section>

      <section className="card span3">
        <p className="eyebrow">ATTACHMENTS</p>
        <h2 className="card-title">Programs by interface / hook</h2>
        {rows.length === 0 && <p className="empty-state">No attachment rows yet — agents may still be reporting.</p>}
        {rows.length > 0 && (
          <div className="datatable-scroll">
            <div className="datahead obs">
              <span>NODE</span>
              <span>NAME</span>
              <span>TYPE</span>
              <span>IFACE</span>
              <span>OWNER</span>
              <span>STATUS</span>
            </div>
            {rows.slice(0, 200).map((a, i) => (
              <div className="datarow obs" key={i}>
                <span>{a.node || '—'}</span>
                <span className="truncate" title={a.name}>
                  {a.name || '—'}
                </span>
                <span>{a.attachType || a.type || '—'}</span>
                <span>{a.interface || '—'}</span>
                <span>{a.cilium ? 'cilium' : a.foreign ? 'foreign' : a.owner || 'netra'}</span>
                <span>
                  {a.present === false ? (a.expected ? 'missing' : 'absent') : 'present'}
                  {a.expected ? ' · expected' : ''}
                </span>
              </div>
            ))}
          </div>
        )}
      </section>
    </div>
  );
}
