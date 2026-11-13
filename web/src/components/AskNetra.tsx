import { FormEvent, useEffect, useRef, useState } from 'react';
import { api } from '../api';

type Finding = { severity?: string; kind?: string; subject?: string; message: string };
type Brief = {
  headline: string;
  severity: string;
  summary: string;
  findings: Finding[];
  nextSteps: string[];
  engine: string;
  model?: string;
  question?: string;
  fingerprint?: string;
  generatedAt: string;
  conversationId?: string;
};
type RuleDraft = {
  understood: boolean;
  confidence?: string;
  kind?: string;
  summary: string;
  cli?: string;
  warnings?: string[];
  note?: string;
  body?: Record<string, unknown>;
};
type AgentStep = { node: string; detail?: string };
type AgentResult = {
  brief: Brief;
  intent?: string;
  draft?: RuleDraft | null;
  steps?: AgentStep[];
  engine?: string;
  conversationId?: string;
};
type Exchange = { question: string; brief: Brief; steps?: AgentStep[]; intent?: string };
// Rendered scrollback is capped so a long-running tab doesn't grow an
// unbounded DOM list — the server-side memory itself independently caps at
// a few turns (internal/ai/conversation.go), this is purely a display cap.
const MAX_SHOWN_EXCHANGES = 8;
type AIStatus = {
  enabled: boolean;
  provider?: string;
  model?: string;
  heuristicOnly: boolean;
  mutations: string;
};

/**
 * One readable line for the AI status strip. The server's `mutations` text is a
 * whole clause ("never — AI endpoints are read-only"), so it gets a label instead
 * of being glued on after a bare "·". Missing fields are omitted rather than
 * printed as "undefined".
 */
export function aiStatusLine(status: AIStatus): string {
  const engine = status.heuristicOnly
    ? 'Heuristic engine only'
    : ['Optional rewrite on', status.model || status.provider].filter(Boolean).join(' · ');
  const mutations = status.mutations?.trim();
  return mutations ? `${engine} · Mutations: ${mutations}` : engine;
}

export const ASK_SUGGESTIONS = [
  'What looks unhealthy?',
  'Why are packets being dropped?',
  'Any new external exposure?',
  'Are we in enforce mode?',
  'What policy drafts need review?',
  'Any rare JA3 or ECH blindness?',
  'Any encrypted DNS (DoT/DoH)?',
  'Which GenAI destinations are we talking to?',
  'Any shadow SaaS outside the sanctioned list?',
  'Where is netlink/route churn?',
];

export function canAsk(question: string, busy: boolean): boolean {
  return !busy && question.trim().length > 0;
}

export function looksLikeDraft(question: string): boolean {
  return /\b(deny|block|drop|rate[- ]?limit|throttle|ban|forbid|allow|except|whitelist|exception|quarantine|isolate|syn-drop)\b/i.test(question);
}

export function formatGraphSteps(steps: AgentStep[] | undefined): string {
  if (!steps || steps.length === 0) return '';
  return steps
    .map((s) => (s.detail ? `${s.node}:${s.detail}` : s.node))
    .join(' → ');
}

type Digest = {
  fingerprint: string;
  changed: boolean;
  card: string;
  suggestions?: string[];
  whyChanged?: string[];
  whyChangedProse?: string;
};

export default function AskNetra() {
  const [status, setStatus] = useState<AIStatus | null>(null);
  const [question, setQuestion] = useState('');
  const [thread, setThread] = useState<Exchange[]>([]);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState('');
  const [chips, setChips] = useState<string[]>(ASK_SUGGESTIONS);
  const [draft, setDraft] = useState<RuleDraft | null>(null);
  const [digest, setDigest] = useState<Digest | null>(null);
  const [copied, setCopied] = useState(false);
  // Held in a ref, not state: identifies "this conversation" to the
  // controller's short-lived multi-turn memory (internal/ai/conversation.go)
  // so a follow-up question ("what about that?") can be resolved. Minted
  // once, on the first ask() in this tab; "New conversation" drops it so
  // the next ask() starts a fresh, unrelated one.
  const conversationId = useRef<string | null>(null);

  useEffect(() => {
    api<AIStatus>('/api/v1/ai/status')
      .then((s) => {
        setStatus(s);
        setErr('');
      })
      .catch((e) => setErr(String(e)));
    api<Brief>('/api/v1/ai/brief')
      .then((b) => {
        setThread([{ question: '', brief: b }]);
        setErr('');
      })
      .catch((e) => setErr(String(e)));
    api<{ items?: string[] }>('/api/v1/ai/suggestions')
      .then((s) => {
        if (s.items && s.items.length) setChips(s.items);
      })
      .catch(() => undefined);
    api<Digest>('/api/v1/ai/digest')
      .then(setDigest)
      .catch(() => undefined);
  }, []);

  async function ask(q: string) {
    const text = q.trim();
    if (!text || busy) return;
    setBusy(true);
    setErr('');
    try {
      if (!conversationId.current) conversationId.current = crypto.randomUUID();
      const res = await api<AgentResult>('/api/v1/ai/agent', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ question: text, conversationId: conversationId.current }),
      });
      const b = res.brief;
      setThread((prev) => [...prev, { question: text, brief: b, steps: res.steps, intent: res.intent }]);
      setQuestion('');
      if (res.draft && res.draft.understood) {
        setDraft(res.draft);
      } else if (looksLikeDraft(text)) {
        // Agent ran draft and did not understand — still surface that.
        setDraft(res.draft || null);
      } else {
        setDraft(null);
      }
    } catch (e) {
      setErr(String(e));
    } finally {
      setBusy(false);
    }
  }

  function newConversation() {
    conversationId.current = null;
    setThread([]);
    setDraft(null);
  }

  function onSubmit(e: FormEvent) {
    e.preventDefault();
    void ask(question);
  }

  const shown = thread.slice(-MAX_SHOWN_EXCHANGES);

  return (
    <section className="card span3 ask-netra">
      <p className="eyebrow">ASK NETRA</p>
      <h2 className="card-title">Read-only brief from live aggregates.</h2>
      <p>
        Answers come from agent, health, and insights counters Netra already computed.
        The question runs a read-only graph (classify → optional draft preview → synthesize).
        Nothing here flips enforce mode or applies policy.
      </p>
      <form className="toolbar ask-netra-form" onSubmit={onSubmit}>
        <label className="ask-netra-field">
          Question
          <input
            value={question}
            onChange={(e) => setQuestion(e.target.value)}
            placeholder="Why is DNS failing in kube-system?"
            aria-label="Ask Netra question"
            maxLength={500}
            disabled={busy}
          />
        </label>
        <button type="submit" className="primary" disabled={!canAsk(question, busy)}>
          {busy ? 'Asking…' : 'Ask'}
        </button>
        <button
          type="button"
          className="btn-secondary"
          disabled={busy}
          onClick={() => void ask('What looks unhealthy?')}
        >
          Refresh brief
        </button>
        <button
          type="button"
          className="btn-secondary"
          disabled={busy || thread.length === 0}
          onClick={newConversation}
        >
          New conversation
        </button>
      </form>
      <div className="ask-netra-chips">
        {chips.map((s) => (
          <button
            key={s}
            type="button"
            className="ask-chip"
            disabled={busy}
            onClick={() => void ask(s)}
          >
            {s}
          </button>
        ))}
      </div>
      {status && (
        <p className="ask-netra-meta">{aiStatusLine(status)}</p>
      )}
      {err && <p className="warning">{err}</p>}
      {shown.map((ex, i) => {
        const b = ex.brief;
        const engine = b.engine === 'llm' ? `LLM${b.model ? ` · ${b.model}` : ''}` : 'Heuristic brief';
        return (
          <div className="ask-netra-answer" key={(b.conversationId || '') + i + b.generatedAt}>
            {ex.question && <p className="ask-netra-meta ask-netra-question">You asked: {ex.question}</p>}
            {formatGraphSteps(ex.steps) && (
              <p className="ask-netra-meta">Graph {ex.intent ? `(${ex.intent}) ` : ''}{formatGraphSteps(ex.steps)}</p>
            )}
            <p>
              <span className={`severity-badge ${b.severity || 'info'}`}>{b.severity || 'info'}</span>
              {' '}
              <b>{b.headline}</b>
              <span className="ask-netra-engine">{engine}{b.fingerprint ? ` · ${b.fingerprint}` : ''}</span>
            </p>
            <p>{b.summary}</p>
            {(b.findings || []).length > 0 && (
              <ul className="ask-netra-list">
                {b.findings.slice(0, 6).map((f, j) => (
                  <li key={(f.kind || '') + (f.subject || '') + j}>
                    {f.severity && <span className={`severity-badge ${f.severity}`}>{f.severity}</span>}
                    {' '}
                    {f.message}
                  </li>
                ))}
              </ul>
            )}
            {(b.nextSteps || []).length > 0 && (
              <>
                <p className="eyebrow">NEXT</p>
                <ul className="ask-netra-list">
                  {b.nextSteps.slice(0, 5).map((step) => (
                    <li key={step}>{step}</li>
                  ))}
                </ul>
              </>
            )}
          </div>
        );
      })}
      {draft && (
        <div className="ask-netra-draft">
          <p className="eyebrow">RULE PREVIEW</p>
          <p>
            <b>{draft.understood ? draft.summary : 'Not a safe exact match'}</b>
            {draft.confidence && <span className="ask-netra-engine">{draft.confidence}</span>}
          </p>
          {draft.cli && <p><code>{draft.cli}</code></p>}
          <p className="ask-netra-meta">{draft.note}</p>
          {(draft.warnings || []).map((w) => (
            <p key={w} className="ask-netra-meta">{w}</p>
          ))}
        </div>
      )}
      {digest && (
        <div className="toolbar" style={{ marginTop: 12 }}>
          <button
            type="button"
            className="btn-secondary"
            onClick={() => {
              void navigator.clipboard?.writeText(digest.card);
              setCopied(true);
              setTimeout(() => setCopied(false), 1500);
            }}
          >
            {copied ? 'Copied digest' : 'Copy on-call card'}
          </button>
          {digest.fingerprint && (
            <span className="ask-netra-meta">
              Fingerprint {digest.fingerprint}{digest.changed ? ' · changed since last look' : ''}
            </span>
          )}
        </div>
      )}
      {digest?.changed && (digest.whyChangedProse || (digest.whyChanged || []).length > 0) && (
        <p className="ask-netra-meta">
          Why: {digest.whyChangedProse || (digest.whyChanged || []).join('; ')}
        </p>
      )}
      {thread.length === 0 && !err && <p className="empty-state">Loading cluster brief…</p>}
    </section>
  );
}
