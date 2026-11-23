// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0
import { describe, expect, it } from 'vitest';
import { formatRemaining } from './DenyLeases';

describe('formatRemaining', () => {
  it('formats hours, minutes and seconds', () => {
    expect(formatRemaining(3 * 3600 + 5 * 60)).toBe('3h 5m');
    expect(formatRemaining(125)).toBe('2m 5s');
    expect(formatRemaining(42)).toBe('42s');
  });
  it('never shows a negative time', () => {
    expect(formatRemaining(0)).toBe('expiring');
    expect(formatRemaining(-30)).toBe('expiring');
  });
});
