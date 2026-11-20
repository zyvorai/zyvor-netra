import { useState } from 'react';
import { api } from '../api';

export function draftQuestionFromFinding(kind: string, subject: string, message: string): string | null {
  const blob = `${kind} ${subject} ${message}`;
  const cidr = blob.match(/\b(?:\d{1,3}\.){3}\d{1,3}\/\d{1,2}\b/);
  if (cidr) return `deny ${cidr[0]}`;
  const ip = blob.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/);
  if (ip) return `deny ${ip[0]}`;
  const named = blob.match(/\b(?:dns|sni|domain|name)[:\s]+([a-z0-9._-]+\.[a-z]{2,})\b/i);
  if (named) return `deny dns ${named[1]}`;
  if (/\b(dns|sni)\b/i.test(blob)) {
    const host = blob.match(/\b([a-z0-9._-]+\.[a-z]{2,})\b/i);
    if (host) return `deny dns ${host[1]}`;
  }
  return null;
}

type Brief = {
  headline: string;
  severity: string;
  summary: string;
  findings?: { severity?: string; message: string }[];
  nextSteps?: string[];
  fingerprint?: string;
  engine?: string;
};

export default function ExplainFinding(props: {
  page: string;
  kind: string;
  subject?: string;
  message?: string;
  severity?: string;
}) {
  const [open, setOpen] = useState(false);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState('');
  const [brief, setBrief] = useState<Brief | null>(null);
  const [draft, setDraft] = useState<{ understood?: boolean; summary?: string; cli?: string; note?: string } | null>(null);
  const draftQ = draftQuestionFromFinding(props.kind, props.subject || '', props.message || '');

  async function run() {
    if (busy) return;
    setOpen(true);
    setBusy(true);
    setErr('');
    try {
      const b = await api<Brief>('/api/v1/ai/explain', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          page: props.page,
          kind: props.kind,
          subject: props.subject || '',
          message: props.message || '',
          severity: props.severity || '',
        }),
      });
      setBrief(b);
      setDraft(null);
    } catch (e) {
      setErr(String(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <span className="explain-finding">
      <button type="button" className="ask-chip" onClick={() => void run()} disabled={busy} aria-label={`Explain ${props.kind}`}>
        {busy ? 'Explaining…' : 'Explain'}
      </button>
      {open && (
        <div className="explain-pop">
          {err && <p className="warning">{err}</p>}
          {brief && (
            <>
              <p>
                <span className={`severity-badge ${brief.severity || 'info'}`}>{brief.severity || 'info'}</span>{' '}
                <b>{brief.headline}</b>
              </p>
              <p>{brief.summary}</p>
              {(brief.nextSteps || []).slice(0, 3).map((s) => (
                <p key={s} className="ask-netra-meta">{s}</p>
              ))}
              {draftQ && (
                <button
                  type="button"
                  className="btn-secondary"
                  disabled={busy}
                  onClick={() => {
                    void api<{ understood?: boolean; summary?: string; cli?: string; note?: string }>('/api/v1/ai/draft', {
                      method: 'POST',
                      headers: { 'Content-Type': 'application/json' },
                      body: JSON.stringify({ question: draftQ }),
                    }).then(setDraft).catch((e) => setErr(String(e)));
                  }}
                >
                  Draft rule from this
                </button>
              )}
              {draft && (
                <p className="ask-netra-meta">
                  {draft.understood ? draft.summary : 'No safe exact match'}{draft.cli ? ` · ${draft.cli}` : ''}
                  {' — preview only, not applied.'}
                </p>
              )}
            </>
          )}
          <button type="button" className="btn-secondary" onClick={() => setOpen(false)}>Close</button>
        </div>
      )}
    </span>
  );
}
