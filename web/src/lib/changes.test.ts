// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0
import { describe, expect, it } from 'vitest';
import { classTone, headline, splitEntries } from './changes';

describe('changes helpers', () => {
  it('splits timed entries from level-triggered state', () => {
    const { timed, state } = splitEntries([
      { atKnown: true, summary: 'a' },
      { atKnown: false, summary: 'b' },
      { summary: 'c' },
    ]);
    expect(timed.map((e) => e.summary)).toEqual(['a']);
    expect(state.map((e) => e.summary)).toEqual(['b', 'c']);
    expect(splitEntries(undefined)).toEqual({ timed: [], state: [] });
  });

  it('tones breaks by severity and leaves changes neutral', () => {
    expect(classTone({ class: 'change' })).toBe('info');
    expect(classTone({ class: 'break', severity: 'critical' })).toBe('critical');
    expect(classTone({ class: 'break', severity: 'info' })).toBe('warning');
    expect(classTone({})).toBe('info');
  });

  it('writes a headline that tolerates missing counts', () => {
    expect(headline(undefined)).toBe('');
    expect(headline({})).toBe('0 changes, 0 breaks, 0 suspected pairings');
    expect(headline({ counts: { change: 1, break: 1 }, suspects: [{ break: {}, changes: [] }] })).toBe('1 change, 1 break, 1 suspected pairing');
  });
});
