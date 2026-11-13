// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

import { useEffect, useMemo, useState } from 'react';
import { api } from '../api';
import PagePulse from '../components/kit/PagePulse';
import { navigate } from '../hooks/useInvestigation';

type MapView = {
  id?: string;
  title?: string;
  group?: string;
  bpfMap?: string;
  count?: number;
  limit?: number;
  entries?: string[];
};

type Report = {
  generatedAt?: string;
  mode?: string;
  revision?: number;
  pinRoot?: string;
  note?: string;
  filledMaps?: number;
  emptyMaps?: number;
  totalEntries?: number;
  maps?: MapView[];
};

export default function EbpfMaps() {
  const [data, setData] = useState<Report>();
  const [group, setGroup] = useState('');
  const [err, setErr] = useState('');
  const [tick, setTick] = useState(0);
  const [open, setOpen] = useState<string | null>(null);

  useEffect(() => {
    const load = () => {
      api<Report>('/api/v1/ebpf/maps')
        .then((d) => {
          setData(d);
          setErr('');
          setTick(Date.now());
        })
        .catch((e) => setErr(String(e.message || e)));
    };
    load();
    const t = setInterval(load, 20000);
    return () => clearInterval(t);
  }, []);

  const groups = useMemo(() => [...new Set((data?.maps || []).map((m) => m.group || 'other'))].sort(), [data]);
  const rows = useMemo(
    () => (data?.maps || []).filter((m) => !group || m.group === group),
    [data, group]
  );

  return (
    <div className="grid">
      <PagePulse
        tick={tick || undefined}
        error={err || undefined}
        tone={err ? 'warn' : tick ? 'ok' : undefined}
        headline={tick ? `${data?.filledMaps || 0} filled · ${data?.emptyMaps || 0} empty · ${data?.totalEntries || 0} entries` : undefined}
        figures={[
          { label: 'filled', value: data?.filledMaps },
          { label: 'empty', value: data?.emptyMaps },
          { label: 'entries', value: data?.totalEntries },
          { label: 'mode', value: data?.mode },
        ]}
      />
      <section className="card span3">
        <p className="eyebrow">MAP INVENTORY</p>
        <h2 className="card-title">Controller-desired pins under {data?.pinRoot || '/sys/fs/bpf/netra'}</h2>
        <p>{data?.note || 'Read-only inventory of Netra-owned maps. Never touches Cilium-owned maps.'}</p>
        <div className="filters" style={{ display: 'flex', gap: '0.75rem', flexWrap: 'wrap', marginTop: '0.75rem' }}>
          <label>
            Group{' '}
            <select value={group} onChange={(e) => setGroup(e.target.value)}>
              <option value="">all</option>
              {groups.map((g) => (
                <option key={g} value={g}>
                  {g}
                </option>
              ))}
            </select>
          </label>
          <span className="kit-caption">revision {data?.revision ?? '—'}</span>
          <button
            type="button"
            className="btn-secondary"
            disabled={!data}
            onClick={() => {
              const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
              const url = URL.createObjectURL(blob);
              const a = document.createElement('a');
              a.href = url;
              a.download = 'netra-ebpf-maps.json';
              a.click();
              URL.revokeObjectURL(url);
            }}
          >
            Export JSON
          </button>
          <button type="button" className="btn-secondary" onClick={() => navigate('ai', { query: 'Which eBPF maps are filled vs empty?' })}>
            Ask about maps
          </button>
        </div>
      </section>
      <section className="card span3">
        <table className="metric-table">
          <thead>
            <tr>
              <th>Group</th>
              <th>Title</th>
              <th>BPF map</th>
              <th className="num">Count</th>
              <th className="num">Limit</th>
              <th />
            </tr>
          </thead>
          <tbody>
            {rows.map((m) => (
              <tr key={m.id || m.bpfMap}>
                <td>{m.group}</td>
                <td>{m.title || m.id}</td>
                <td>
                  <code>{m.bpfMap}</code>
                </td>
                <td className="num">{m.count ?? 0}</td>
                <td className="num">{m.limit ?? '—'}</td>
                <td>
                  {(m.entries || []).length > 0 && (
                    <button type="button" className="btn-secondary" onClick={() => setOpen(open === m.id ? null : m.id || m.bpfMap || null)}>
                      {open === (m.id || m.bpfMap) ? 'Hide' : 'Entries'}
                    </button>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        {rows.length === 0 && <p className="empty-state">No maps in this group.</p>}
        {open && (
          <pre style={{ marginTop: '1rem', maxHeight: '16rem', overflow: 'auto' }}>
            {((data?.maps || []).find((m) => (m.id || m.bpfMap) === open)?.entries || []).join('\n') || '(empty)'}
          </pre>
        )}
      </section>
    </div>
  );
}
