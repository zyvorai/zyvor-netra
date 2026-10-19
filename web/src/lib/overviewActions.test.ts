// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

import { describe, expect, it } from 'vitest';
import { ctaLabel, rankOverviewActions } from './overviewActions';

describe('rankOverviewActions', () => {
  it('returns empty when nothing is raised', () => {
    const { items, worst } = rankOverviewActions({});
    expect(items).toEqual([]);
    expect(worst).toBeUndefined();
  });

  it('ranks critical congestion above alerts and incidents', () => {
    const { items, worst } = rankOverviewActions({
      kernelFindings: [{ severity: 'critical', signal: 'softnet-drop', explanation: 'CPU cannot keep up', node: 'w1' }],
      alerts: [{ id: 'a1', rule: 'cpu_busy', status: 'critical', node: 'w1' }],
      incidents: [{ sourceKey: 'ns/pod', subject: 'prod/api', severity: 'warning', findings: [{ message: 'drift + drops' }] }],
    });
    expect(worst?.page).toBe('congestion');
    expect(worst?.severity).toBe('critical');
    expect(items.map((i) => i.page)).toEqual(['congestion', 'metric-alerts', 'incidents']);
  });

  it('ranks critical metric alert before incidents', () => {
    const { worst } = rankOverviewActions({
      alerts: [{ id: 'a1', rule: 'disk_full', status: 'critical', node: 'n1' }],
      incidents: [{ sourceKey: 'x', subject: 'ns/pod', severity: 'critical', findings: [{ message: 'multi' }] }],
    });
    expect(worst?.page).toBe('metric-alerts');
  });

  it('caps at limit and dedupes', () => {
    const { items } = rankOverviewActions({
      limit: 2,
      healthAnoms: [
        { kind: 'rtt-high', severity: 'warning', subject: 'a', message: 'one' },
        { kind: 'rtt-high', severity: 'warning', subject: 'a', message: 'one' },
        { kind: 'dns-fail', severity: 'warning', subject: 'b', message: 'two' },
        { kind: 'reset', severity: 'warning', subject: 'c', message: 'three' },
      ],
    });
    expect(items).toHaveLength(2);
  });

  it('maps detect findings to Detect', () => {
    const { items } = rankOverviewActions({
      dnsFindings: [{ kind: 'dga', message: 'many subdomains', namespace: 'prod', pod: 'api' }],
    });
    expect(items[0]?.page).toBe('detect');
    expect(items[0]?.severity).toBe('warning');
  });
});

describe('ctaLabel', () => {
  it('names the worst page', () => {
    expect(ctaLabel('congestion')).toBe('Open Congestion Map');
    expect(ctaLabel(undefined)).toBe('Investigate connections');
  });
});
