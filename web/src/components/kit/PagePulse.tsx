// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

import { useEffect, useState } from 'react';
import Sparkline from '../Sparkline';
import { useCountUp } from '../../hooks/useCountUp';
import { compact } from './format';
import type { Tone } from './tone';

export type PulseFigureSpec = {
  label: string;
  value?: number | string;
  format?: (n: number) => string;
  tone?: Tone;
  series?: number[];
};

export function PulseFigure({ label, value, format = compact, tone, series }: PulseFigureSpec) {
  const numeric = typeof value === 'number' && Number.isFinite(value);
  const animated = useCountUp(numeric ? (value as number) : 0);
  return (
    <div className={`kit-pulse__cell${tone ? ' tone-' + tone : ''}`}>
      <span>{label}</span>
      <b>{numeric ? format(animated) : value === undefined || value === '' ? '—' : value}</b>
      {series && (
        <div className="kit-pulse__spark">
          {series.length > 1 ? <Sparkline values={series} width={200} height={32} fill /> : <i>warming up…</i>}
        </div>
      )}
    </div>
  );
}

function ago(ms: number): string {
  const s = Math.max(0, Math.round(ms / 1000));
  if (s < 60) return `${s}s ago`;
  if (s < 3600) return `${Math.round(s / 60)}m ago`;
  return `${Math.round(s / 3600)}h ago`;
}

/** Live pill: records when `tick` last changed and shows it ticking. */
export function LivePill({ tick, error, paused }: { tick?: unknown; error?: string; paused?: boolean }) {
  const [at, setAt] = useState<number | undefined>(undefined);
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    if (tick !== undefined) setAt(Date.now());
  }, [tick]);
  useEffect(() => {
    const t = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(t);
  }, []);
  const state = paused ? 'paused' : error ? 'stale' : at ? 'live' : 'idle';
  const text =
    state === 'paused' ? 'Paused' : state === 'stale' ? `Stale${at ? ' · last ' + ago(now - at) : ''}` : state === 'live' ? `Live · updated ${ago(now - at!)}` : 'Loading…';
  return (
    <span className={`kit-live kit-live--${state}`} title={error || undefined}>
      <i aria-hidden="true" /> {text}
    </span>
  );
}

type PagePulseProps = {
  figures: PulseFigureSpec[];
  tick?: unknown;
  error?: string;
  paused?: boolean;
  /** One plain-language sentence summarizing the page state. */
  headline?: string;
  tone?: Tone;
  /** Hide the live pill on on-demand (non-polling) results. */
  live?: boolean;
};

export default function PagePulse({ figures, tick, error, paused, headline, tone, live = true }: PagePulseProps) {
  return (
    <section className="kit-pulse span3" aria-label="Live summary">
      <div className="kit-pulse__head">
        {headline && <h2 className={`kit-pulse__headline${tone ? ' tone-' + tone : ''}`}>{headline}</h2>}
        {live && <LivePill tick={tick} error={error} paused={paused} />}
      </div>
      <div className="kit-pulse__grid">
        {figures.map((f) => (
          <PulseFigure key={f.label} {...f} />
        ))}
      </div>
    </section>
  );
}
