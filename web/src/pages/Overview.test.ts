import { describe, expect, it } from 'vitest';
import { bytesRate, compact } from './Overview';
import { ratesBetween } from '../hooks/useOverviewPulse';
import { flowDuration, workloadLabel } from '../components/DatapathHero';
import { ctaLabel, rankOverviewActions } from '../lib/overviewActions';

describe('overview action CTA', () => {
  it('uses Investigate connections when the board is clear', () => {
    const { worst } = rankOverviewActions({});
    expect(ctaLabel(worst?.page)).toBe('Investigate connections');
  });

  it('names Congestion Map for a critical kernel finding', () => {
    const { worst } = rankOverviewActions({
      kernelFindings: [{ severity: 'critical', signal: 'softnet-drop', explanation: 'busy CPU', node: 'n1' }],
    });
    expect(ctaLabel(worst?.page)).toBe('Open Congestion Map');
  });
});

describe('ratesBetween', () => {
  it('divides counter deltas by elapsed seconds', () => {
    const r = ratesBetween({ at: 0, packets: 100, bytes: 1000, dns: 0, blocked: 0 }, { at: 5000, packets: 600, bytes: 6000, dns: 10, blocked: 5 });
    expect(r).toEqual({ packets: 100, bytes: 1000, dns: 2, blocked: 1 });
  });

  it('treats a counter reset as zero, not negative traffic', () => {
    const r = ratesBetween({ at: 0, packets: 900, bytes: 9000, dns: 5, blocked: 0 }, { at: 1000, packets: 10, bytes: 100, dns: 1, blocked: 0 });
    expect(r).toEqual({ packets: 0, bytes: 0, dns: 0, blocked: 0 });
  });

  it('refuses a non-increasing clock', () => {
    const c = { at: 1000, packets: 1, bytes: 1, dns: 1, blocked: 1 };
    expect(ratesBetween(c, c)).toBeUndefined();
  });
});

describe('workloadLabel', () => {
  it('drops the namespace, owner and pod hash suffixes', () => {
    expect(workloadLabel('kube-system/hubble-relay-59cc868d4d-jmg7l (ReplicaSet/hubble-relay-59cc868d4d)')).toBe('hubble-relay');
    expect(workloadLabel('kube-system/cilium-rnzwl (DaemonSet/cilium)')).toBe('cilium');
  });

  it('truncates long names', () => {
    expect(workloadLabel('ns/a-very-long-workload-name-here', 10)).toBe('a-very-lo…');
  });
});

describe('flowDuration', () => {
  it('is slow when idle and faster, but bounded, when busy', () => {
    expect(flowDuration(0)).toBe(6);
    expect(flowDuration(1000)).toBeLessThan(flowDuration(10));
    expect(flowDuration(1e12)).toBe(1.2);
  });
});

describe('formatters', () => {
  it('compacts large counts', () => {
    expect(compact(466.2)).toBe('466');
    expect(compact(12_500)).toBe('12.5K');
    expect(compact(6_229_583)).toBe('6.2M');
    expect(compact(2.34)).toBe('2.3');
  });

  it('formats byte rates', () => {
    expect(bytesRate(512)).toBe('512 B/s');
    expect(bytesRate(5_750_300)).toBe('5.8 MB/s');
  });
});
