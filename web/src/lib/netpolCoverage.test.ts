// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0
import { describe, expect, it } from 'vitest';
import { coverageHeadline, coverageQuery, directionLabel, type CoverageReport } from './netpolCoverage';

const summary = (over: Partial<NonNullable<CoverageReport['summary']>>) => ({
  policies: 0,
  pods: 0,
  hostNetworkPods: 0,
  workloads: 0,
  uncovered: 0,
  partial: 0,
  covered: 0,
  attention: 0,
  ingressUnrestrictedPods: 0,
  egressUnrestrictedPods: 0,
  ...over,
});

describe('netpol coverage helpers', () => {
  it('writes headlines without claiming safety for an empty report', () => {
    expect(coverageHeadline(undefined)).toBe('');
    expect(coverageHeadline({})).toBe('');
    expect(coverageHeadline({ summary: summary({}) })).toBe('no pod-network workloads found');
    expect(coverageHeadline({ summary: summary({ workloads: 1, covered: 1 }) })).toBe('every one of 1 workload is restricted in both directions');
    expect(coverageHeadline({ summary: summary({ workloads: 5, uncovered: 2, partial: 1, attention: 1 }) })).toBe(
      '3 of 5 workloads unrestricted in some direction, 1 with public traffic',
    );
  });

  it('describes a direction', () => {
    expect(directionLabel(undefined)).toBe('unknown');
    expect(directionLabel({ open: 0, allowAll: 0, restricted: 0, restrictedButAnyAddress: 0 })).toBe('no pods');
    expect(directionLabel({ open: 1, allowAll: 2, restricted: 3, restrictedButAnyAddress: 1 })).toBe(
      '1 no policy, 2 allow-all, 3 restricted (1 still any address)',
    );
  });

  it('builds a query from validated input only', () => {
    expect(coverageQuery('', '', false)).toBe('');
    expect(coverageQuery(' shop ', '24h', true)).toBe('?namespace=shop&window=24h&all=true');
    expect(coverageQuery('a&all=true', '1d', false)).toBe('');
  });
});
