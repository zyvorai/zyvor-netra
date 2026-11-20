import { useState } from 'react';
import { api } from '../api';

type Hit = { type: string; value: string; kind: string; node: string; namespace?: string; pod?: string; subject: string; packets: number; blocked: number };
type Issue = { line: number; message: string };
type Response = {
  preview?: { entries?: { type: string; value: string }[]; skipped?: Issue[]; count?: number; dropped?: number };
  match?: { hits?: Hit[]; count?: number; capped?: boolean; checked?: number };
};

export default function WatchlistMatch() {
  const [text, setText] = useState('');
  const [resp, setResp] = useState<Response>();
  const [err, setErr] = useState('');
  const [busy, setBusy] = useState(false);

  const submit = () => {
    if (!text.trim()) return;
    setBusy(true);
    api<Response>('/api/v1/watchlist/match', { method: 'POST', body: text })
      .then((r) => { setResp(r); setErr(''); })
      .catch((e) => setErr(String(e)))
      .finally(() => setBusy(false));
  };

  return (
    <section className="card span3">
      <p className="eyebrow">WATCHLIST MATCH</p>
      <h2 className="card-title">Check a list against current traffic</h2>
      <p>Paste IPs, CIDRs, DNS names, or SNI hosts (JSON, CSV, or one per line) and check them against current agent state. Observe-only — this applies nothing.</p>
      <textarea
        aria-label="Watchlist entries"
        value={text}
        onChange={(e) => setText(e.target.value)}
        placeholder={'1.2.3.4\n10.0.0.0/8\nexample.com'}
        rows={4}
        style={{ width: '100%', fontFamily: 'monospace' }}
      />
      <p>
        <button type="button" onClick={submit} disabled={busy || !text.trim()}>
          {busy ? 'Checking…' : 'Check'}
        </button>
      </p>
      {err && <p className="warning">{err}</p>}
      {resp && (
        <div className="list">
          <div className="agent wide">
            <b>Parsed</b><span>{resp.preview?.count ?? 0} entries</span>
            <small>{resp.preview?.dropped ?? 0} dropped · {resp.match?.checked ?? 0} checked · {resp.match?.count ?? 0} matches{resp.match?.capped ? ' (capped)' : ''}</small>
          </div>
          {(resp.preview?.skipped || []).map((s, i) => (
            <div className="agent wide" key={`skip-${i}`}><b>Line {s.line}</b><span className="severity-badge warning">skipped</span><small>{s.message}</small></div>
          ))}
          {(resp.match?.hits || []).length === 0 && (resp.preview?.count ?? 0) > 0 && (
            <p className="empty-state">No matches against current agent state.</p>
          )}
          {(resp.match?.hits || []).map((h, i) => (
            <div className="agent wide" key={i}>
              <b>{h.value}</b><span>{h.kind}</span><small>{h.subject} on {h.node} — {h.packets} pkts, {h.blocked} blocked</small>
            </div>
          ))}
        </div>
      )}
    </section>
  );
}
