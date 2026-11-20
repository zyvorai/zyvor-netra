// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
import { describe, expect, it } from 'vitest';
import { rankSignals, visibleSignals } from './incidents';

const s = (severity: string, at: string, id = '') => ({ severity, at, id });

describe('rankSignals', () => {
  it('puts the most severe first and the newest first within a severity', () => {
    const out = rankSignals([
      s('warning', '2026-09-27T10:00:00Z', 'w-old'),
      s('critical', '2026-09-27T09:00:00Z', 'c-old'),
      s('warning', '2026-09-27T11:00:00Z', 'w-new'),
      s('critical', '2026-09-27T12:00:00Z', 'c-new'),
    ]);
    expect(out.map((x) => x.id)).toEqual(['c-new', 'c-old', 'w-new', 'w-old']);
  });
  it('treats medium and warning as equal and sorts unknown severities last', () => {
    const out = rankSignals([s('weird', '2026-09-27T10:00:00Z', 'x'), s('medium', '2026-09-27T10:00:00Z', 'm'), s('info', '2026-09-27T10:00:00Z', 'i')]);
    expect(out.map((x) => x.id)).toEqual(['m', 'i', 'x']);
  });
  it('is stable for equal severity and time, and does not mutate the input', () => {
    const input = [s('high', 'bad-date', 'a'), s('high', 'bad-date', 'b')];
    const copy = [...input];
    expect(rankSignals(input).map((x) => x.id)).toEqual(['a', 'b']);
    expect(input).toEqual(copy);
  });
});

describe('visibleSignals', () => {
  const many = Array.from({ length: 10 }, (_, i) => s(i === 7 ? 'critical' : 'warning', `2026-09-27T10:0${i}:00Z`, String(i)));
  it('shows the top N (worst first) and counts the rest', () => {
    const { shown, hidden } = visibleSignals(many, false, 4);
    expect(shown).toHaveLength(4);
    expect(shown[0].id).toBe('7');
    expect(hidden).toBe(6);
  });
  it('shows everything when expanded or when under the limit', () => {
    expect(visibleSignals(many, true, 4)).toMatchObject({ hidden: 0 });
    expect(visibleSignals(many, true, 4).shown).toHaveLength(10);
    expect(visibleSignals(many.slice(0, 3), false, 4)).toMatchObject({ hidden: 0 });
  });
});
