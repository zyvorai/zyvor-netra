// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0
import { describe, expect, it } from 'vitest';
import { driftHeadline, driftQuery, edgeLabel, humanBytes, humanSpan, shiftHeadline, shiftQuery } from './flowDrift';

describe('flow drift helpers', () => {
  it('formats bytes and spans and tolerates hostile numbers', () => {
    expect(humanBytes(undefined)).toBe('unknown');
    expect(humanBytes(NaN)).toBe('unknown');
    expect(humanBytes(-1)).toBe('unknown');
    expect(humanBytes(512)).toBe('512 B');
    expect(humanBytes(10 * 1024 * 1024)).toBe('10.0 MiB');
    expect(humanSpan(undefined)).toBe('unknown');
    expect(humanSpan(1800)).toBe('30m');
    expect(humanSpan(7200)).toBe('2h');
    expect(humanSpan(5 * 86400)).toBe('5d');
  });

  it('writes honest headlines, including not ready', () => {
    expect(driftHeadline(undefined)).toBe('');
    expect(driftHeadline({ ready: false, notReadyReason: 'only 5m of history' })).toBe('not ready: only 5m of history');
    expect(driftHeadline({ ready: true, baselineSpanSeconds: 7200 })).toBe('no new or vanished dependencies (baseline 2h)');
    expect(driftHeadline({ ready: true, newTotal: 1, newPublicEgress: 1, vanishedTotal: 2, baselineSpanSeconds: 86400 * 3 })).toBe(
      '1 new dependency (1 public egress), 2 gone quiet, baseline 3d',
    );
    expect(shiftHeadline({ ready: false })).toBe('not ready: not enough history');
    expect(shiftHeadline({ ready: true, factor: 3, shifts: [] })).toBe('no workload moved by 3x or more');
    expect(
      shiftHeadline({ ready: true, factor: 2, shifts: [{ kind: 'surge' }, { kind: 'drop' }, { kind: 'drop' }] as never }),
    ).toBe('1 surge, 2 drops at 2x or more');
  });

  it('labels an edge with direction and name', () => {
    const e = { namespace: 'shop', workload: 'cart', direction: 'egress', peer: '203.0.113.9', peerClass: 'public', port: 443, protocol: 'TCP', name: 'api.example', bytes: 1, observations: 1, firstSeen: '', lastSeen: '' };
    expect(edgeLabel(e)).toBe('shop/cart -> api.example (203.0.113.9):443/tcp');
    expect(edgeLabel({ ...e, direction: 'ingress', name: undefined, namespace: undefined })).toBe('cart <- 203.0.113.9:443/tcp');
  });

  it('names the same-time baseline and unusual-time rows', () => {
    expect(shiftHeadline({ ready: true, factor: 3, baselineMode: 'same-time', baselineDays: 5, shifts: [] })).toBe(
      'no workload moved by 3x or more against the same time on 5 earlier days',
    );
    expect(shiftHeadline({ ready: true, factor: 3, shifts: [{ kind: 'unusual-time' }] as never })).toBe('0 surges, 0 drops at 3x or more, 1 at an unusual time');
    expect(shiftQuery('', '', 'average')).toBe('');
    expect(shiftQuery('', '', 'same-time')).toBe('?baseline_mode=same-time');
    expect(shiftQuery('30m', '72h', 'same-time')).toBe('?recent=30m&baseline=72h&baseline_mode=same-time');
  });

  it('builds a query from validated windows only', () => {
    expect(driftQuery('', '', false)).toBe('');
    expect(driftQuery('30m', '72h', true)).toBe('?recent=30m&baseline=72h&public_only=true');
    expect(driftQuery('1h; drop', 'x', false)).toBe('');
  });
});
