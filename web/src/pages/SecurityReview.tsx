// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
import { useEffect, useMemo, useState } from 'react';
import { api } from '../api';
import { useRoute } from '../hooks/useInvestigation';
import PagePulse from '../components/kit/PagePulse';

type Feed = { count: number; revision: number; expired: boolean; persistent: boolean; journalUnavailable: boolean; source?: string; expiresAt?: string; refreshError?: string; lastRefresh?: string };
type Revision = { revision: number; updatedAt: string; source: string; note?: string; expiresAt?: string; entries: unknown[] };
type Rule = { id: string; type: string; value: string; direction: string; protocol: string; synOnly: boolean; matchingEvents: number };
type Suggestion = { kind: string; rule: string; relatedRule: string; message: string };
type Optimization = { rules: Rule[]; suggestions: Suggestion[]; truncated: boolean; note: string };
type Incident = { id: string; node: string; namespace: string; pod: string; lastSeen: string; evidence: { id: string; kind: string; message: string; at: string }[] };
type Correlation = { result: { items: Incident[]; truncated: boolean; note: string }; dnsEnabled: boolean; scanEnabled: boolean };
type History = { feed: Feed; revisions: Revision[] };
type IntelHit = { type?: string; value?: string; kind?: string; node?: string; namespace?: string; pod?: string; subject?: string; packets?: number; blocked?: number };
type HitsBoard = { match?: { hits?: IntelHit[]; count?: number; capped?: boolean }; note?: string };

export default function SecurityReview() {
  const route = useRoute();
  const [history, setHistory] = useState<History>();
  const [review, setReview] = useState<Optimization>();
  const [correlation, setCorrelation] = useState<Correlation>();
  const [hits, setHits] = useState<HitsBoard>();
  const [previewText, setPreviewText] = useState('');
  const [previewOut, setPreviewOut] = useState('');
  const [rollbackRev, setRollbackRev] = useState('');
  const [note, setNote] = useState('');
  const [error, setError] = useState('');
  const [tick, setTick] = useState<number>();
  useEffect(() => {
    let active = true;
    const load = async () => {
      try {
        const [h, r, c, hi] = await Promise.all([
          api<History>('/api/v1/intel/history'),
          api<Optimization>('/api/v1/security/optimizer'),
          api<Correlation>('/api/v1/security/incidents'),
          api<HitsBoard>('/api/v1/intel/hits?limit=100').catch(() => ({})),
        ]);
        if (active) { setHistory(h); setReview(r); setCorrelation(c); setHits(hi); setError(''); setTick(Date.now()); }
      } catch (e) { if (active) setError(String(e)); }
    };
    void load(); const timer = setInterval(() => { void load(); }, 20000);
    return () => { active = false; clearInterval(timer); };
  }, []);
  const feed = history?.feed;
  const scopedIncidents = useMemo(() => {
    const items = correlation?.result.items || [];
    const { namespace, pod, node, query } = route.scope;
    const q = query.toLowerCase();
    return items.filter((c) =>
      (!namespace || c.namespace === namespace) &&
      (!pod || c.pod === pod) &&
      (!node || c.node === node) &&
      (!q || c.namespace.toLowerCase().includes(q) || c.pod.toLowerCase().includes(q) || c.evidence.some((e) => e.kind.toLowerCase().includes(q) || e.message.toLowerCase().includes(q)))
    );
  }, [correlation, route.scope]);
  const scopeActive = !!(route.scope.namespace || route.scope.pod || route.scope.node || route.scope.query);
  return <div className="grid">
    <PagePulse tick={tick} error={error || undefined} headline={tick ? (scopeActive ? 'Security evidence filtered from Detect handoff.' : 'Security evidence ready for review.') : undefined} tone={tick ? (error || feed?.journalUnavailable ? 'warn' : 'ok') : undefined}
      figures={[
        { label: 'feed entries', value: feed?.count },
        { label: 'review suggestions', value: review?.suggestions.length },
        { label: 'correlated incidents', value: scopeActive ? scopedIncidents.length : correlation?.result.items.length },
      ]} />
    <section className="card span3">
      <p className="eyebrow">THREAT INTELLIGENCE</p><h2 className="card-title">Feed lifecycle</h2>
      {!feed && !error && <p>Loading feed status…</p>}
      {feed && <>
        <p>Revision {feed.revision} · {feed.count} active entries · {feed.expired ? 'Expired' : 'Current'} · {feed.persistent ? 'Journal enabled' : 'Memory only'}</p>
        {feed.source && <p>Source: {feed.source}</p>}
        {feed.expiresAt && <p>Expires: {new Date(feed.expiresAt).toLocaleString()}</p>}
        {feed.journalUnavailable && <p className="warning">Journal unavailable. Repair the configured state file before updating the feed.</p>}
        {feed.refreshError && <p className="warning">{feed.refreshError}</p>}
        {feed.lastRefresh && <p>Last refresh attempt: {new Date(feed.lastRefresh).toLocaleString()}</p>}
        <p>Expiry stops new matches and feed applications. Already imported denies keep their normal enforcement lease. Refresh and rollback never apply rules.</p>
        <div className="table-wrap"><table><thead><tr><th>Revision</th><th>Updated</th><th>Entries</th><th>Source / note</th></tr></thead><tbody>
          {[...(history?.revisions || [])].reverse().map(r => <tr key={r.revision}><td>{r.revision}</td><td>{new Date(r.updatedAt).toLocaleString()}</td><td>{r.entries?.length || 0}</td><td>{r.source} {r.note}</td></tr>)}
        </tbody></table></div>
        <div className="filters" style={{ display: 'flex', gap: '0.75rem', flexWrap: 'wrap', marginTop: '0.75rem', alignItems: 'center' }}>
          <input value={rollbackRev} onChange={(e) => setRollbackRev(e.target.value)} placeholder="Revision #" aria-label="Rollback revision" style={{ width: '6rem' }} />
          <button
            type="button"
            className="btn-secondary"
            onClick={() => {
              const rev = rollbackRev.trim();
              if (!rev) { setError('Enter a revision to roll back to.'); return; }
              api(`/api/v1/intel/rollback/${encodeURIComponent(rev)}`, { method: 'POST' })
                .then(() => { setNote(`Rolled feed back to revision ${rev} (never auto-applies denies).`); setError(''); })
                .catch((e) => setError(String(e.message || e)));
            }}
          >
            Rollback revision
          </button>
          <span className="kit-caption">Restores a prior feed revision only — never applies deny entries.</span>
        </div>
        {note && <p className="kit-caption">{note}</p>}
      </>}
    </section>
    <section className="card span3">
      <p className="eyebrow">INTEL HITS</p>
      <h2 className="card-title">Live feed matches against agent metadata</h2>
      <p>{hits?.note || 'Observe-only match of the active feed. Never auto-enforces.'}</p>
      <div className="table-wrap"><table><thead><tr><th>Kind</th><th>Value</th><th>Workload</th><th>Node</th><th className="num">Packets</th><th className="num">Blocked</th></tr></thead><tbody>
        {(hits?.match?.hits || []).map((h, i) => (
          <tr key={`${h.value}-${h.pod}-${i}`}>
            <td>{h.kind || h.type || '—'}</td>
            <td>{h.value || h.subject || '—'}</td>
            <td>{[h.namespace, h.pod].filter(Boolean).join('/') || '—'}</td>
            <td>{h.node || '—'}</td>
            <td className="num">{h.packets || 0}</td>
            <td className="num">{h.blocked || 0}</td>
          </tr>
        ))}
      </tbody></table></div>
      {!(hits?.match?.hits || []).length && <p className="empty-state">No live intel hits right now.</p>}
    </section>
    <section className="card span3">
      <p className="eyebrow">FEED PREVIEW</p>
      <h2 className="card-title">Parse a candidate feed without applying</h2>
      <textarea
        value={previewText}
        onChange={(e) => setPreviewText(e.target.value)}
        rows={5}
        placeholder="Paste feed body (JSON/CSV/lines) to preview…"
        style={{ width: '100%', fontFamily: 'inherit' }}
      />
      <button
        type="button"
        className="btn-secondary"
        style={{ marginTop: '0.5rem' }}
        onClick={() => {
          api<{ preview?: unknown; applyHint?: string }>('/api/v1/intel/preview', {
            method: 'POST',
            headers: { 'Content-Type': 'text/plain' },
            body: previewText,
          })
            .then((d) => {
              setPreviewOut(JSON.stringify(d.preview ?? d, null, 2));
              setNote(d.applyHint || 'Preview only — nothing applied.');
              setError('');
            })
            .catch((e) => setError(String(e.message || e)));
        }}
      >
        Preview feed
      </button>
      {previewOut && <pre style={{ marginTop: '0.75rem', maxHeight: '16rem', overflow: 'auto' }}>{previewOut}</pre>}
    </section>
    <section className="card span3">
      <p className="eyebrow">DENY RULE REVIEW</p><h2 className="card-title">Equivalent and covered predicates</h2>
      <p>{review?.note || 'Inspect flat IP, CIDR and port deny predicates. No changes are applied.'}</p>
      {review?.truncated && <p className="warning">Review capped. Inspect remaining configuration separately.</p>}
      {review && <>
        {!review.suggestions.length && <p className="empty-state">No predicate suggestions in this review.</p>}
        <div className="table-wrap"><table><thead><tr><th>Kind</th><th>Rule</th><th>Related rule</th></tr></thead><tbody>
          {review.suggestions.map((s,i) => <tr key={`${s.rule}:${s.relatedRule}:${i}`} title={s.message}><td>{s.kind}</td><td>{s.rule}</td><td>{s.relatedRule}</td></tr>)}
        </tbody></table></div>
        <div className="table-wrap"><table><thead><tr><th>Rule ID</th><th>Predicate</th><th>Direction</th><th>Protocol</th><th>Matching sampled events</th></tr></thead><tbody>
          {review.rules.map(r => <tr key={r.id}><td>{r.id}</td><td>{r.type}: {r.value}{r.synOnly ? ' (TCP SYN restriction)' : ''}</td><td>{r.direction}</td><td>{r.protocol}</td><td>{r.matchingEvents}</td></tr>)}
        </tbody></table></div>
      </>}
    </section>
    <section className="card span3">
      <p className="eyebrow">SECURITY CORRELATION</p><h2 className="card-title">Evidence on the same workload</h2>
      <p>{correlation?.result.note || 'Recent DNS, scan and IP/CIDR intel evidence, joined by exact node, namespace and pod.'}</p>
      {correlation && <p>DNS detector: {correlation.dnsEnabled ? 'enabled' : 'disabled'} · Scan detector: {correlation.scanEnabled ? 'enabled' : 'disabled'}</p>}
      {scopeActive && <p className="kit-caption">Filter: {[route.scope.namespace && `ns=${route.scope.namespace}`, route.scope.pod && `pod=${route.scope.pod}`, route.scope.node && `node=${route.scope.node}`, route.scope.query && `q=${route.scope.query}`].filter(Boolean).join(' · ')}</p>}
      {correlation?.result.truncated && <p className="warning">Evidence capped. Consult detector findings and agent events for the full context.</p>}
      {correlation && !scopedIncidents.length && <p className="empty-state">{scopeActive ? 'No correlated incidents match this Detect handoff filter.' : 'No workload has two recent evidence kinds.'}</p>}
      {scopedIncidents.map(c => <article key={c.id}>
        <h3>{c.namespace}/{c.pod} · {c.node}</h3>
        <ul>{c.evidence.map(e => <li key={e.id}><b>{e.kind}</b> · {e.message} · {new Date(e.at).toLocaleString()}</li>)}</ul>
      </article>)}
    </section>
  </div>;
}
