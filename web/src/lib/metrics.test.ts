// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
import { describe, expect, it } from 'vitest';
import { anomalyBand, formatValue, groupContexts, latest, niceCeil, streamSocketURL, valueRange, type ContextInfo, type MetricResult } from './metrics';

const ctx = (context: string, family?: string): ContextInfo => ({ context, family, charts: [], firstT: 0, lastT: 0 });

const result = (units: string, dims: (number | null)[][], anom: (number | null)[][] = []): MetricResult => ({
  context: 'x',
  units,
  tier: 0,
  interval: 1,
  after: 0,
  before: 2,
  timestamps: dims[0].map((_, i) => i),
  dimensions: dims.map((values, i) => ({ name: `d${i}`, values, anomalyRate: anom[i] || values.map(() => 0), series: 1 })),
  matched: dims.length,
});

describe('metrics helpers', () => {
  it('groups contexts into sections and ordered families', () => {
    const g = groupContexts([ctx('net.net', 'net'), ctx('system.cpu', 'cpu'), ctx('system.ram', 'ram'), ctx('ebpf.packets', 'datapath'), ctx('cgroup.cpu', 'cpu'), ctx('nginx.requests', 'nginx')]);
    expect(g.map((s) => s.section)).toEqual(['System', 'Network', 'Workloads', 'eBPF datapath', 'Applications']);
    expect(g[0].families.map((f) => f.family)).toEqual(['cpu', 'ram']);
  });

  it('computes stacked and line ranges', () => {
    const r = result('', [[1, 2, null], [3, 4, 5]]);
    expect(valueRange(r, false)).toEqual([0, 5]);
    expect(valueRange(r, true)).toEqual([0, 6]);
    expect(valueRange(result('%', [[10, 70]]), false)).toEqual([0, 100]);
    expect(valueRange(result('', [[null, null]]), false)).toEqual([0, 1]);
    expect(valueRange(result('', [[-5, 3]]), false)).toEqual([-5, 3]);
  });

  it('rounds axis maxima to friendly numbers', () => {
    expect(niceCeil(7)).toBe(8);
    expect(niceCeil(101)).toBe(120);
    expect(niceCeil(0.33)).toBeCloseTo(0.4);
  });

  it('formats values with SI prefixes and units', () => {
    expect(formatValue(1534, 'kilobits/s')).toBe('1.53k kilobits/s');
    expect(formatValue(42.123, '%')).toBe('42%');
    expect(formatValue(3.21, '%')).toBe('3.2%');
    expect(formatValue(null)).toBe('—');
    expect(formatValue(2_500_000)).toBe('2.50M');
  });

  it('takes the latest value and the anomaly band', () => {
    const r = result('', [[1, 2, null], [3, null, null]], [[0, 50, null], [100, null, null]]);
    expect(latest(r.dimensions![0])).toBe(2);
    expect(anomalyBand(r)).toEqual([100, 50, null]);
  });

  it('derives the WebSocket URL from the page origin', () => {
    expect(streamSocketURL({ protocol: 'https:', host: 'netra.example:30870' })).toBe('wss://netra.example:30870/api/v1/metrics/stream');
    expect(streamSocketURL({ protocol: 'http:', host: 'localhost:5173' })).toBe('ws://localhost:5173/api/v1/metrics/stream');
  });
});
