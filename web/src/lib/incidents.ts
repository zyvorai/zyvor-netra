// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

/** How many signals a cluster shows before "Show N more". */
export const INCIDENT_SIGNAL_LIMIT = 4;

const RANK: Record<string, number> = { critical: 4, high: 3, medium: 2, warning: 2, low: 1, info: 0 };

type Ranked = { severity: string; at: string };

/**
 * Most severe first, then newest first. A stable order matters because the list
 * is truncated: without ranking, "top N" would hide the worst signal arbitrarily.
 * Unknown severities sort last. Does not mutate its input.
 */
export function rankSignals<T extends Ranked>(signals: readonly T[]): T[] {
  return signals
    .map((s, i) => ({ s, i }))
    .sort((a, b) => {
      const d = (RANK[b.s.severity] ?? -1) - (RANK[a.s.severity] ?? -1);
      if (d !== 0) return d;
      const t = (Date.parse(b.s.at) || 0) - (Date.parse(a.s.at) || 0);
      return t !== 0 ? t : a.i - b.i;
    })
    .map((x) => x.s);
}

/** The ranked signals to show, and how many are hidden behind the toggle. */
export function visibleSignals<T extends Ranked>(signals: readonly T[], expanded: boolean, limit = INCIDENT_SIGNAL_LIMIT) {
  const ranked = rankSignals(signals);
  if (expanded || ranked.length <= limit) return { shown: ranked, hidden: 0 };
  return { shown: ranked.slice(0, limit), hidden: ranked.length - limit };
}
