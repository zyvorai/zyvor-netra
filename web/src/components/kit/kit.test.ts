import { describe, expect, it } from 'vitest';
import { bytes, compact, msFromUs, pct } from './format';
import { countTone, scoreTone } from './tone';

describe('tone', () => {
  it('treats any nonzero count as a deviation', () => {
    expect(countTone(undefined)).toBe('idle');
    expect(countTone(0)).toBe('ok');
    expect(countTone(3)).toBe('warn');
    expect(countTone(50, 10)).toBe('bad');
  });

  it('grades scores where higher is better', () => {
    expect(scoreTone(undefined)).toBe('idle');
    expect(scoreTone(95)).toBe('ok');
    expect(scoreTone(70)).toBe('warn');
    expect(scoreTone(20)).toBe('bad');
  });
});

describe('format', () => {
  it('keeps small integers whole', () => {
    expect(compact(3)).toBe('3');
    expect(compact(0)).toBe('0');
  });

  it('formats bytes, latency and ratios', () => {
    expect(bytes(47_935_853_040)).toBe('47.9 GB');
    expect(msFromUs(1234)).toBe('1.2 ms');
    expect(msFromUs(250_000)).toBe('250 ms');
    expect(pct(1, 4)).toBe('25.0%');
    expect(pct(1, 0)).toBe('0%');
  });
});
