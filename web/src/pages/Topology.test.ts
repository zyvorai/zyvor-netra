// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
import { describe, expect, it } from 'vitest';
import { findingsBySource, label, mergeByID } from './Topology';

describe('label', () => {
  it('uses namespace/name for cluster-local nodes', () => {
    expect(label({ id: 'workload:prod:deployment:api', kind: 'workload', namespace: 'prod', name: 'api' })).toBe('prod/api');
  });
  it('uses IP for external nodes', () => {
    expect(label({ id: 'external:203.0.113.10', kind: 'external', name: '203.0.113.10', ip: '203.0.113.10' })).toBe('203.0.113.10');
  });
});

describe('findingsBySource', () => {
  it('keeps the highest-ranked severity across all three sources', () => {
    const by = findingsBySource(
      [{ severity: 'info', kind: 'destination', source: 'workload:prod:deployment:api', value: 'x', message: 'new destination' }],
      [{ severity: 'critical', source: 'workload:prod:deployment:api', metric: 'pps', message: 'rate spike' }],
      [{ source: 'workload:prod:deployment:api', score: 40, severity: 'medium', reasons: ['3 external deps'] }],
    );
    const f = by.get('workload:prod:deployment:api');
    expect(f?.severity).toBe('critical');
    expect(f?.count).toBe(3);
  });

  it('caps stored reasons at 5 even when there are more findings', () => {
    const drift = Array.from({ length: 8 }, (_, i) => ({ severity: 'info', kind: 'destination', source: 'a', value: String(i), message: `finding ${i}` }));
    const by = findingsBySource(drift, [], []);
    expect(by.get('a')?.count).toBe(8);
    expect(by.get('a')?.reasons.length).toBe(5);
  });

  it('ignores findings with no source', () => {
    const by = findingsBySource([{ severity: 'warning', kind: 'destination', source: '', value: 'x', message: 'm' }], [], []);
    expect(by.size).toBe(0);
  });
});

describe('mergeByID', () => {
  type Item = { id: string; v: number };
  const equal = (a: Item, b: Item) => a.v === b.v;

  it('reuses the previous object reference when nothing changed', () => {
    const prev = new Map<string, Item>([['a', { id: 'a', v: 1 }]]);
    const next = mergeByID(prev, [{ id: 'a', v: 1 }], equal);
    expect(next.get('a')).toBe(prev.get('a'));
  });

  it('replaces the object when the derived value changed', () => {
    const prevItem = { id: 'a', v: 1 };
    const prev = new Map<string, Item>([['a', prevItem]]);
    const next = mergeByID(prev, [{ id: 'a', v: 2 }], equal);
    expect(next.get('a')).not.toBe(prevItem);
    expect(next.get('a')?.v).toBe(2);
  });

  it('drops entries no longer present and adds new ones', () => {
    const prev = new Map<string, Item>([['a', { id: 'a', v: 1 }], ['b', { id: 'b', v: 2 }]]);
    const next = mergeByID(prev, [{ id: 'a', v: 1 }, { id: 'c', v: 3 }], equal);
    expect(Array.from(next.keys()).sort()).toEqual(['a', 'c']);
  });
});
