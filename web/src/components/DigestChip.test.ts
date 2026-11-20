import { describe, expect, it } from 'vitest';
import { digestLabel, digestTooltip } from './DigestChip';

describe('digestLabel', () => {
  it('shows severity and a short fingerprint', () => {
    expect(digestLabel({ severity: 'warning', fingerprint: 'a1b2c3d4e5f6' })).toBe('warning · a1b2c3');
  });

  it('marks a changed incident cluster', () => {
    expect(digestLabel({ severity: 'critical', fingerprint: 'deadbeef0001', changed: true })).toBe(
      'critical · changed deadbe',
    );
  });
});

describe('digestTooltip', () => {
  it('falls back to the headline when nothing changed', () => {
    expect(digestTooltip({ headline: 'All quiet' })).toBe('All quiet');
  });

  it('appends the LLM prose when present and changed', () => {
    expect(
      digestTooltip({ headline: 'Drops rising', changed: true, whyChangedProse: 'mode flipped to enforce' }),
    ).toBe('Drops rising — mode flipped to enforce');
  });

  it('falls back to joined bullets when there is no prose', () => {
    expect(
      digestTooltip({ headline: 'Drops rising', changed: true, whyChanged: ['mode changed', 'health dropped'] }),
    ).toBe('Drops rising — mode changed; health dropped');
  });

  it('omits the why-suffix when changed but nothing to explain', () => {
    expect(digestTooltip({ headline: 'Drops rising', changed: true })).toBe('Drops rising');
  });
});
