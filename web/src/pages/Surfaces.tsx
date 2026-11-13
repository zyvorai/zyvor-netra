// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
import { useEffect, useMemo, useState } from 'react';
import { api } from '../api';
import { navigate, useRoute } from '../hooks/useInvestigation';
import { surfaceRowHandoff } from '../lib/surfaceHandoff';
import PagePulse from '../components/kit/PagePulse';

type Board = {
  id: string;
  label: string;
  group: string;
  path: string;
  note?: string;
  empty?: string;
  listKeys: string[];
};

const BOARDS: Board[] = [
  { id: 'tls', label: 'TLS fingerprints', group: 'Encrypted', path: '/api/v1/ebpf/tls-fingerprints?limit=100', listKeys: ['fingerprints'], empty: 'No TLS fingerprints observed yet.' },
  { id: 'tls-risk', label: 'JA3 risk', group: 'Encrypted', path: '/api/v1/ebpf/tls-fingerprints/risk?limit=100', listKeys: ['items'], empty: 'No rare JA3 / ECH risk rows.' },
  { id: 'encdns', label: 'Encrypted DNS', group: 'Encrypted', path: '/api/v1/ebpf/encrypted-dns?limit=100', listKeys: ['result.hits', 'hits'], empty: 'No DoT/DoH hits.' },
  { id: 'ech', label: 'ECH / missing SNI', group: 'Encrypted', path: '/api/v1/insights/ech-blind?limit=100', listKeys: ['findings', 'items'], empty: 'No ECH-blind findings.' },
  { id: 'shadow', label: 'Shadow SaaS', group: 'Fit', path: '/api/v1/insights/shadow-saas?limit=100', listKeys: ['findings', 'items'], empty: 'No shadow SaaS findings.' },
  { id: 'experience', label: 'Experience', group: 'Fit', path: '/api/v1/insights/experience?limit=100', listKeys: ['workloads', 'rows', 'items'], empty: 'No experience scores yet.' },
  { id: 'destrisk', label: 'Destination risk', group: 'Fit', path: '/api/v1/insights/destination-risk?limit=100', listKeys: ['destinations', 'items'], empty: 'No destination-risk rows.' },
  { id: 'zt', label: 'Zero Trust drafts', group: 'Fit', path: '/api/v1/insights/zero-trust?limit=50', listKeys: ['drafts', 'items'], empty: 'No zero-trust drafts.' },
  { id: 'microseg', label: 'Microseg', group: 'Fit', path: '/api/v1/insights/microseg?limit=50', listKeys: ['leaseDrafts', 'suggestions', 'drafts', 'items'], empty: 'No microseg lease drafts.' },
  { id: 'packs', label: 'Policy packs', group: 'Fit', path: '/api/v1/insights/policy-packs?limit=50', listKeys: ['packs', 'items'], empty: 'No policy packs.' },
  { id: 'identity', label: 'Identity drafts', group: 'Fit', path: '/api/v1/insights/identity-drafts?limit=50', listKeys: ['drafts', 'items'], empty: 'No identity drafts.' },
  { id: 'exfil', label: 'Exfil heuristics', group: 'Threat', path: '/api/v1/insights/exfil?limit=100', listKeys: ['findings', 'items'], empty: 'No exfil heuristics.' },
  { id: 'lateral', label: 'Lateral playbooks', group: 'Threat', path: '/api/v1/insights/lateral?limit=50', listKeys: ['playbooks', 'items'], empty: 'No lateral playbooks.' },
  { id: 'catdeny', label: 'Category deny', group: 'Threat', path: '/api/v1/insights/category-deny?limit=50', listKeys: ['drafts', 'items'], empty: 'No category-deny drafts.' },
  { id: 'dnsintel', label: 'DNS intel hits', group: 'Threat', path: '/api/v1/intel/dns-hits?limit=100', listKeys: ['hits', 'items'], empty: 'No DNS intel hits.' },
  { id: 'intel', label: 'Threat intel feed', group: 'Threat', path: '/api/v1/intel/feed', listKeys: ['entries', 'items'], empty: 'Threat feed empty.' },
  { id: 'appcat', label: 'App categories', group: 'Ops', path: '/api/v1/ebpf/app-categories?limit=100', listKeys: ['hits', 'items'], empty: 'No app-category hits.' },
  { id: 'compliance', label: 'Compliance', group: 'Ops', path: '/api/v1/compliance?limit=100', listKeys: ['packs', 'checks', 'items', 'findings'], empty: 'No compliance packs.' },
  { id: 'ainet', label: 'AI destinations', group: 'Ops', path: '/api/v1/ebpf/ai-destinations?limit=100', listKeys: ['hits', 'items', 'destinations'], empty: 'No GenAI destinations matched.' },
  { id: 'automitigate', label: 'Auto-mitigate', group: 'Ops', path: '/api/v1/ebpf/auto-mitigate', listKeys: ['recent', 'actions', 'items'], empty: 'No recent auto-mitigate actions.' },
  { id: 'automitigate-preview', label: 'Auto-mitigate preview', group: 'Ops', path: '/api/v1/ebpf/auto-mitigate/preview', listKeys: ['candidates', 'preview', 'items', 'actions'], empty: 'No shadow auto-mitigate candidates.' },
  { id: 'reasons', label: 'Drop reasons', group: 'Ops', path: '/api/v1/ebpf/reasons', listKeys: ['items', 'reasons', 'buckets'], empty: 'No reason buckets.' },
  { id: 'prevention', label: 'Prevention report', group: 'Ops', path: '/api/v1/report/prevention', listKeys: ['gaps', 'coverage', 'sections', 'items'], empty: 'Prevention report has no list rows — see headline/coverageScore above.' },
  { id: 'clusters', label: 'Fleet clusters', group: 'Fleet', path: '/api/v1/fleet/clusters', listKeys: ['clusters', 'items'], empty: 'No fleet clusters configured.' },
  { id: 'tenants', label: 'Fleet tenants', group: 'Fleet', path: '/api/v1/fleet/tenants', listKeys: ['tenants', 'items'], empty: 'No fleet tenants.' },
];

const GROUPS = ['Encrypted', 'Fit', 'Threat', 'Ops', 'Fleet'];

function dig(obj: any, path: string): any {
  return path.split('.').reduce((acc, key) => (acc == null ? undefined : acc[key]), obj);
}

function pickList(data: any, keys: string[]): any[] {
  if (!data) return [];
  for (const k of keys) {
    const v = dig(data, k);
    if (Array.isArray(v)) return v;
  }
  if (Array.isArray(data)) return data;
  return [];
}

function rowLabel(row: any, boardId: string): string {
  if (boardId === 'experience') return [row.namespace, row.pod || row.workload].filter(Boolean).join('/') || row.node || '';
  if (boardId === 'destrisk') return row.destination || row.host || '';
  if (boardId === 'compliance' && row.controls) return row.name || row.id || 'pack';
  return (
    row.ja3 ||
    row.sni ||
    row.host ||
    row.hostname ||
    row.name ||
    row.title ||
    row.id ||
    row.source ||
    row.destination ||
    row.category ||
    row.node ||
    row.tenant ||
    row.cluster ||
    row.check ||
    row.domain ||
    row.label ||
    ''
  );
}

function rowMeta(row: any, boardId: string): string {
  const parts: string[] = [];
  if (row.severity) parts.push(String(row.severity));
  if (row.status && boardId === 'shadow') parts.push(String(row.status));
  if (row.ja4) parts.push(`ja4 ${String(row.ja4).slice(0, 18)}…`);
  if (row.ech) parts.push('ECH');
  if (row.count != null) parts.push(`n=${row.count}`);
  if (row.packets != null) parts.push(`pkts ${row.packets}`);
  if (row.score != null) parts.push(`score ${row.score}`);
  if (row.riskScore != null) parts.push(`risk ${row.riskScore}`);
  if (row.coverageScore != null) parts.push(`coverage ${row.coverageScore}`);
  if (row.category) parts.push(String(row.category));
  if (row.label && boardId !== 'ainet') parts.push(String(row.label));
  if (row.kind) parts.push(String(row.kind));
  if (row.mode) parts.push(String(row.mode));
  if (row.operation) parts.push(String(row.operation));
  if (row.cli) parts.push(String(row.cli));
  if (row.retransmits != null) parts.push(`retrans ${row.retransmits}`);
  if (row.dnsFailures != null) parts.push(`dnsFail ${row.dnsFailures}`);
  if (row.uniqueDestinations != null) parts.push(`uniqDst ${row.uniqueDestinations}`);
  if (row.externalDestinations != null) parts.push(`ext ${row.externalDestinations}`);
  if (row.intelHit) parts.push('intel');
  if (row.aiRelated) parts.push('ai');
  if (row.node && boardId !== 'clusters') parts.push(String(row.node));
  if (row.namespace && row.pod) parts.push(`${row.namespace}/${row.pod}`);
  if (Array.isArray(row.reasons) && row.reasons.length) parts.push(row.reasons.slice(0, 3).join(', '));
  if (Array.isArray(row.signals) && row.signals.length) parts.push(row.signals.slice(0, 2).join(', '));
  if (Array.isArray(row.steps) && row.steps.length) parts.push(String(row.steps[0]));
  if (row.message) parts.push(String(row.message));
  if (row.note && !row.message) parts.push(String(row.note));
  if (row.rationale && Array.isArray(row.rationale)) parts.push(row.rationale.slice(0, 2).join('; '));
  if (row.findingType) parts.push(String(row.findingType));
  if (row.at || row.observedAt || row.time) parts.push(String(row.at || row.observedAt || row.time));
  return parts.filter(Boolean).join(' · ');
}

export default function Surfaces() {
  const route = useRoute();
  const [group, setGroup] = useState(GROUPS[0]);
  const [boardId, setBoardId] = useState(BOARDS[0].id);
  const [filter, setFilter] = useState('');
  const [data, setData] = useState<any>();
  const [err, setErr] = useState('');
  const [loading, setLoading] = useState(false);

  const boards = BOARDS.filter((b) => b.group === group);
  const active = BOARDS.find((b) => b.id === boardId) || boards[0] || BOARDS[0];

  useEffect(() => {
    const q = (route.scope.query || '').trim();
    if (!q) return;
    const hit = BOARDS.find((b) => b.id === q || b.id === q.replace(/^board=/, ''));
    if (hit) {
      setGroup(hit.group);
      setBoardId(hit.id);
    }
  }, [route.scope.query]);

  useEffect(() => {
    if (!active?.id) return;
    if (route.scope.query === active.id) return;
    navigate('surfaces', { query: active.id });
  }, [active?.id]); // eslint-disable-line react-hooks/exhaustive-deps

  useEffect(() => {
    if (!boards.some((b) => b.id === boardId)) setBoardId(boards[0]?.id || BOARDS[0].id);
  }, [group]); // eslint-disable-line react-hooks/exhaustive-deps

  const load = () => {
    if (!active) return;
    setLoading(true);
    api<any>(active.path)
      .then((d) => {
        setData(d);
        setErr('');
      })
      .catch((e) => setErr(String(e)))
      .finally(() => setLoading(false));
  };

  useEffect(() => {
    load();
    const t = setInterval(load, 20000);
    return () => clearInterval(t);
  }, [active?.path]); // eslint-disable-line react-hooks/exhaustive-deps

  const list = useMemo(() => {
    const raw = pickList(data, active?.listKeys || []);
    // Compliance packs → flatten controls when present.
    if (active?.id === 'compliance' && raw.some((p) => Array.isArray(p?.controls))) {
      const flat: any[] = [];
      for (const p of raw) {
        for (const c of p.controls || []) flat.push({ ...c, pack: p.name || p.id });
      }
      if (flat.length) return flat;
    }
    const q = filter.trim().toLowerCase();
    if (!q) return raw;
    return raw.filter((row) => {
      const hay = `${rowLabel(row, active?.id || '')} ${rowMeta(row, active?.id || '')}`.toLowerCase();
      return hay.includes(q);
    });
  }, [data, active, filter]);

  const note = data?.note || active?.note || '';
  const statsBits: string[] = [];
  if (data?.stats) {
    if (data.stats.uniqueJa3 != null) statsBits.push(`${data.stats.uniqueJa3} unique JA3`);
    if (data.stats.enabled === false) statsBits.push('detector off');
  }
  if (data?.count != null) statsBits.push(`${data.count} items`);
  if (data?.uniqueJa3 != null) statsBits.push(`${data.uniqueJa3} unique JA3`);
  if (data?.echSightings != null) statsBits.push(`${data.echSightings} ECH`);
  if (data?.rare != null) statsBits.push(`${data.rare} rare`);
  if (data?.headline) statsBits.push(String(data.headline));
  if (data?.coverageScore != null) statsBits.push(`coverage ${data.coverageScore}`);
  if (data?.capped) statsBits.push('capped');
  if (data?.recommendation) statsBits.push(String(data.recommendation));

  return (
    <div className="grid">
      <PagePulse
        headline={active ? `${active.label}: ${list.length} row${list.length === 1 ? '' : 's'}.` : undefined}
        tick={data}
        error={err || undefined}
        figures={[
          { label: 'boards', value: BOARDS.length },
          { label: 'rows on this board', value: data ? list.length : undefined },
          ...(data?.uniqueJa3 != null ? [{ label: 'unique JA3', value: data.uniqueJa3 as number }] : []),
          ...(data?.rare != null ? [{ label: 'rare', value: data.rare as number, tone: data.rare ? ('warn' as const) : undefined }] : []),
          ...(data?.echSightings != null ? [{ label: 'ECH sightings', value: data.echSightings as number }] : []),
          ...(data?.capped ? [{ label: 'capped', value: 1, tone: 'warn' as const }] : []),
        ]}
      />
      <section className="card span3">
        <p className="eyebrow">OBSERVE-ONLY SURFACES</p>
        <h2 className="card-title">P1–P5 metadata boards</h2>
        <p>Encrypted traffic, fit maps, threat heuristics, and fleet rollups — review-only, no decrypt, no payload export.</p>
        <div className="chips" role="tablist" aria-label="Surface groups">
          {GROUPS.map((g) => (
            <button key={g} type="button" className={group === g ? 'primary' : ''} aria-pressed={group === g} onClick={() => setGroup(g)}>
              {g}
            </button>
          ))}
        </div>
        <div className="chips" role="tablist" aria-label="Boards" style={{ marginTop: '0.75rem' }}>
          {boards.map((b) => (
            <button key={b.id} type="button" className={active?.id === b.id ? 'primary' : ''} aria-pressed={active?.id === b.id} onClick={() => setBoardId(b.id)}>
              {b.label}
            </button>
          ))}
        </div>
        <div className="filters" style={{ marginTop: '0.75rem' }}>
          <input value={filter} onChange={(e) => setFilter(e.target.value)} placeholder="Filter host / JA3 / severity…" aria-label="Filter board rows" />
          <button
            type="button"
            className="btn-secondary"
            disabled={!data}
            onClick={() => {
              const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
              const url = URL.createObjectURL(blob);
              const a = document.createElement('a');
              a.href = url;
              a.download = `netra-surfaces-${active?.id || 'board'}.json`;
              a.click();
              URL.revokeObjectURL(url);
            }}
          >
            Export JSON
          </button>
          {active?.id === 'tls' || active?.id === 'tls-risk' ? (
            <button type="button" className="btn-secondary" onClick={() => navigate('tls-fingerprints')}>
              TLS / JA3 page
            </button>
          ) : null}
          {active?.id === 'ainet' || active?.id === 'appcat' || active?.id === 'shadow' ? (
            <button type="button" className="btn-secondary" onClick={() => navigate('security-review')}>
              Security Review
            </button>
          ) : null}
          {active?.id === 'automitigate' || active?.id === 'automitigate-preview' ? (
            <button type="button" className="btn-secondary" onClick={() => navigate('detect')}>
              Detect
            </button>
          ) : null}
          {active?.id === 'reasons' ? (
            <button type="button" className="btn-secondary" onClick={() => navigate('drop-reasons')}>
              Drop reasons page
            </button>
          ) : null}
        </div>
      </section>

      <section className="card span3">
        <p className="eyebrow">{active?.group?.toUpperCase()}</p>
        <h2 className="card-title">
          {active?.label}
          {statsBits.length > 0 && <small> · {statsBits.join(' · ')}</small>}
          {data?.capped && <span className="severity-badge warning"> capped</span>}
        </h2>
        {note && <p>{note}</p>}
        {loading && <p className="empty-state">Loading…</p>}
        {err && <p className="warning">{err}</p>}
        {!loading && !err && list.length === 0 && <p className="empty-state">{active?.empty || 'No rows yet — observe traffic or wait for agent sync.'}</p>}
        <div className="list">
          {list.slice(0, 200).map((row, i) => {
            const label = rowLabel(row, active?.id || '') || `row ${i + 1}`;
            const meta = rowMeta(row, active?.id || '');
            const sev = String(row.severity || '').toLowerCase();
            const handoff = active ? surfaceRowHandoff(active.id, row) : null;
            return (
              <div className={`agent wide${sev ? ` insightrow ${sev}` : ''}`} key={`${label}-${i}`}>
                <b className="truncate" title={label}>
                  {label}
                </b>
                {sev && <span className={`severity-badge ${sev === 'high' || sev === 'critical' ? 'warning' : 'info'}`}>{sev}</span>}
                {meta && <small>{meta}</small>}
                {handoff && (
                  <button
                    type="button"
                    className="btn-secondary"
                    onClick={() => navigate(handoff.page, handoff.scope)}
                  >
                    {handoff.label} →
                  </button>
                )}
              </div>
            );
          })}
        </div>
        {list.length > 0 && (
          <p>
            <small>
              Showing {Math.min(list.length, 200)} of {list.length} · <code>{active?.path.split('?')[0]}</code>
            </small>
          </p>
        )}
      </section>
    </div>
  );
}
