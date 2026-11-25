// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0
import { describe, expect, it } from 'vitest';
import { floodHeadline, humanEta, severityTone, versionShare, worstCapacity, beaconHeadline, beaconLabel, humanPeriod } from './netrisk';

describe('network risk helpers', () => {
  it('formats time to exhaustion and tolerates hostile numbers', () => {
    expect(humanEta(undefined)).toBe('unknown');
    expect(humanEta(NaN)).toBe('unknown');
    expect(humanEta(Infinity)).toBe('unknown');
    expect(humanEta(-5)).toBe('unknown');
    expect(humanEta(0)).toBe('now');
    expect(humanEta(30)).toBe('<1m');
    expect(humanEta(42 * 60)).toBe('42m');
    expect(humanEta(3 * 3600 + 10 * 60)).toBe('3h 10m');
    expect(humanEta(50 * 3600)).toBe('2d 2h');
  });

  it('maps severity to a badge tone', () => {
    expect(severityTone('critical')).toBe('critical');
    expect(severityTone('high')).toBe('critical');
    expect(severityTone('warning')).toBe('warning');
    expect(severityTone(undefined)).toBe('info');
  });

  it('writes a flood headline that counts suggestions as review only', () => {
    expect(floodHeadline(undefined)).toBe('');
    expect(floodHeadline({})).toBe('no flood findings');
    expect(floodHeadline({ sourcesWarming: true })).toBe('no flood findings (source rates warming)');
    const r = {
      nodeFindings: [{ node: 'n', vector: 'syn', signal: 's', currentPerSecond: 1, baselinePerSecond: 0, severity: 'high', message: '' }],
      sourceFindings: [
        { node: 'n', class: 'syn', address: '8.8.8.8', perSecond: 1, shareOfClass: 1, severity: 'high', message: '', suggestion: { kind: 'ip', value: '8.8.8.8', direction: 'ingress', previewRequest: {}, steps: [] } },
        { node: 'n', class: 'syn', address: '10.0.0.1', perSecond: 1, shareOfClass: 0, severity: 'high', message: '', noSuggestion: 'private' },
      ],
    };
    expect(floodHeadline(r)).toBe('1 node vector, 2 sources, 1 suggested deny (review only)');
  });

  it('picks the most urgent capacity forecast and ignores ok ones', () => {
    const f = (node: string, severity: string) => ({ node, resource: 'conntrack', current: 1, limit: 100, slopePerHour: 0, severity });
    expect(worstCapacity(undefined)).toBeUndefined();
    expect(worstCapacity({ forecasts: [f('a', 'ok')] })).toBeUndefined();
    expect(worstCapacity({ forecasts: [f('a', 'info'), f('b', 'critical'), f('c', 'warning')] })?.node).toBe('b');
  });

  it('summarises a version histogram', () => {
    expect(versionShare(undefined)).toBe('none sampled');
    expect(versionShare({})).toBe('none sampled');
    expect(versionShare({ '1.3': 9, '1.2': 1, '1.0': 0 })).toBe('1.3 90%, 1.2 10%');
    expect(versionShare({ '1.2': 1, '1.3': 1 })).toBe('1.2 50%, 1.3 50%');
  });
});

describe('beacon helpers', () => {
  it('formats periods with seconds', () => {
    expect(humanPeriod(undefined)).toBe('unknown');
    expect(humanPeriod(-1)).toBe('unknown');
    expect(humanPeriod(45)).toBe('45s');
    expect(humanPeriod(90)).toBe('1m 30s');
    expect(humanPeriod(300)).toBe('5m');
    expect(humanPeriod(3600)).toBe('1h');
    expect(humanPeriod(5400)).toBe('1h 30m');
  });

  it('says not ready, none, or how many', () => {
    expect(beaconHeadline(undefined)).toBe('');
    expect(beaconHeadline({ ready: false, notReadyReason: 'history spans 2m' })).toBe('not ready: history spans 2m');
    expect(beaconHeadline({ ready: true })).toBe('no periodic egress found in the window');
    expect(beaconHeadline({ ready: true, total: 1 })).toBe('1 periodic destination to identify');
    expect(beaconHeadline({ ready: true, total: 3 })).toBe('3 periodic destinations to identify');
  });

  it('labels a candidate by pod, name and peer', () => {
    const c = { namespace: 'shop', workload: 'api', pod: 'api-1', peer: '203.0.113.7', peerClass: 'public', port: 443, protocol: 'TCP', name: 'c.example', events: 30, periodSeconds: 60, jitterSeconds: 0, score: 1, medianBytes: 600 };
    expect(beaconLabel(c)).toBe('shop/api-1 -> c.example (203.0.113.7):443/tcp');
    expect(beaconLabel({ ...c, namespace: undefined, pod: undefined, name: undefined, protocol: undefined })).toBe('api -> 203.0.113.7:443');
  });
});
