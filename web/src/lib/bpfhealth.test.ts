import { describe, expect, it } from 'vitest';
import { bpfMapsMissingFinding, rateDropFinding } from './bpfhealth';

describe('bpfMapsMissingFinding', () => {
  it('returns null for no missing maps', () => {
    expect(bpfMapsMissingFinding(undefined)).toBeNull();
    expect(bpfMapsMissingFinding([])).toBeNull();
  });
  it('classifies missing maps', () => {
    const f = bpfMapsMissingFinding(['icmp_errors', 'allowed_uids']);
    expect(f?.kind).toBe('bpf-maps-missing');
    expect(f?.evidence).toContain('icmp_errors');
    expect(f?.evidence).toContain('allowed_uids');
    expect(f?.nextCheck).toContain('Rebuild');
  });
});

describe('rateDropFinding', () => {
  it('returns null for zero count', () => {
    expect(rateDropFinding({ name: '203.0.113.5', count: 0 })).toBeNull();
  });
  it('classifies a nonzero drop count', () => {
    const f = rateDropFinding({ name: '203.0.113.5', count: 42 });
    expect(f?.kind).toBe('rate-drop');
    expect(f?.evidence).toContain('203.0.113.5');
    expect(f?.evidence).toContain('42');
    expect(f?.nextCheck).toContain('PPS ceiling');
  });
});
