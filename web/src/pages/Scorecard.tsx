import { useEffect, useState } from 'react';
import { api } from '../api';
import PagePulse from '../components/kit/PagePulse';
import { countTone, scoreTone } from '../components/kit/tone';

type Card = {
  score?: number;
  band?: string;
  headline?: string;
  healthScore?: number;
  staleAgents?: number;
  detachedPrograms?: number;
  missingMaps?: number;
  blockedEvents?: number;
  notes?: string[];
};

export default function Scorecard() {
  const [card, setCard] = useState<Card>();
  const [err, setErr] = useState('');
  const load = () => {
    api<Card>('/api/v1/scorecard').then((c) => { setCard(c); setErr(''); }).catch((e) => setErr(String(e)));
  };
  useEffect(() => { load(); const t = setInterval(load, 20000); return () => clearInterval(t); }, []);
  return (
    <div className="grid">
      <PagePulse
        headline={card ? card.headline || `${card.score ?? '—'} · ${card.band || 'unknown'}` : undefined}
        tone={card?.score != null ? scoreTone(card.score) : undefined}
        tick={card}
        error={err || undefined}
        figures={[
          { label: 'score /100', value: card?.score, tone: card?.score != null ? scoreTone(card.score) : undefined },
          { label: 'health /100', value: card?.healthScore, tone: card?.healthScore != null ? scoreTone(card.healthScore) : undefined },
          { label: 'stale agents', value: card?.staleAgents, tone: card ? countTone(card.staleAgents || 0) : undefined },
          { label: 'detached programs', value: card?.detachedPrograms, tone: card ? countTone(card.detachedPrograms || 0) : undefined },
          { label: 'missing maps', value: card?.missingMaps, tone: card ? countTone(card.missingMaps || 0) : undefined },
          { label: 'blocked events', value: card?.blockedEvents },
        ]}
      />
      <section className="card span3">
        <p className="eyebrow">SCORECARD</p>
        <h2 className="card-title">What moved the score · {card?.band || 'unknown'} band</h2>
        <p>Observe-only rollup of health, coverage, and blocked events.</p>
        {err && <p className="warning">{err}</p>}
        {card && (
          <div className="list">
            {!(card.notes || []).length && <p className="empty-state">No notes — every input is within its normal range.</p>}
            {(card.notes || []).map((n) => <div className="agent wide" key={n}><b>Note</b><span>{n}</span></div>)}
          </div>
        )}
      </section>
    </div>
  );
}
