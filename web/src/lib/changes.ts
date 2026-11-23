// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

// Types and helpers for GET /api/v1/incidents/changes (internal/changeline).
export type ChangeEntry = {
  at?: string;
  atKnown?: boolean;
  class?: string;
  source?: string;
  node?: string;
  severity?: string;
  summary?: string;
};

export type ChangeSuspect = { break: ChangeEntry; changes: ChangeEntry[]; sameNode?: boolean };

export type ChangesResult = {
  generatedAt?: string;
  lead?: string;
  entries?: ChangeEntry[];
  suspects?: ChangeSuspect[];
  gaps?: string[];
  counts?: Record<string, number>;
  truncated?: boolean;
  caveat?: string;
};

// splitEntries separates entries with an event time from level-triggered state
// (drop and attachment findings), which the API sorts last and never pairs.
export function splitEntries(entries: ChangeEntry[] | undefined): { timed: ChangeEntry[]; state: ChangeEntry[] } {
  const timed: ChangeEntry[] = [];
  const state: ChangeEntry[] = [];
  for (const e of entries || []) (e.atKnown ? timed : state).push(e);
  return { timed, state };
}

// classTone maps an entry to a severity-badge class.
export function classTone(e: ChangeEntry): string {
  if (e.class === 'change') return 'info';
  if (e.class === 'break') return e.severity === 'critical' ? 'critical' : 'warning';
  return 'info';
}

export function headline(r: ChangesResult | undefined): string {
  if (!r) return '';
  const c = r.counts || {};
  const n = r.suspects?.length || 0;
  return `${c.change || 0} change${c.change === 1 ? '' : 's'}, ${c.break || 0} break${c.break === 1 ? '' : 's'}, ${n} suspected pairing${n === 1 ? '' : 's'}`;
}
