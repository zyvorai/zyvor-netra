// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
import { describe, expect, it } from 'vitest';
import { chartsFor } from './Metrics';
import { timelineResult } from './MetricAnomalies';
import { since } from './MetricAlerts';
import { dataURL } from '../hooks/useMetricStream';
import { evidencePath } from '../components/MetricEvidence';
import type { ContextInfo } from '../lib/metrics';

const ctx = (context: string, charts: [string, string][]): ContextInfo => ({
  context,
  title: context,
  charts: charts.map(([node, chart]) => ({ node, chart, dimensions: ['a'] })),
  firstT: 0,
  lastT: 0,
});

describe('Metrics page', () => {
  it('draws one chart per instance on a node, and collapses large or fleet-wide contexts', () => {
    const net = ctx('net.net', [['n1', 'net.eth0'], ['n1', 'net.eth1'], ['n2', 'net.eth0']]);
    const many = ctx('cgroup.cpu', Array.from({ length: 10 }, (_, i) => ['n1', `cgroup_${i}.cpu`] as [string, string]));
    const perNode = chartsFor([net, many], 'n1', 'dimension', 300);
    expect(perNode.map((c) => c.q.charts?.[0] ?? c.q.groupBy)).toEqual(['net.eth0', 'net.eth1', 'chart']);
    expect(perNode[0].q.nodes).toEqual(['n1']);
    expect(perNode[0].q.points).toBe(300);

    const fleet = chartsFor([net], '', 'node', 86400);
    expect(fleet).toHaveLength(1);
    expect(fleet[0].q.groupBy).toBe('node');
    expect(fleet[0].q.nodes).toBeUndefined();
    expect(fleet[0].q.points).toBe(360);
  });

  it('builds the polling URL from a stream query', () => {
    const u = dataURL({ id: 'x', context: 'system.cpu', nodes: ['n1'], window: 900, points: 300, groupBy: 'chart', labels: { pod: 'web-*' } });
    const p = new URL(u, 'http://x').searchParams;
    expect(p.get('context')).toBe('system.cpu');
    expect(p.get('after')).toBe('-900');
    expect(p.get('nodes')).toBe('n1');
    expect(p.get('group_by')).toBe('chart');
    expect(p.get('labels')).toBe('pod:web-*');
  });

  it('turns the anomaly timeline into a chart result', () => {
    const r = timelineResult({
      after: 0,
      before: 120,
      nodes: [
        { node: 'n1', anomalyRate: 1, dimensions: 10, anomalousDimensions: 1, timeline: [{ t: 0, rate: 0 }, { t: 60, rate: 5 }] },
        { node: 'n2', anomalyRate: 0, dimensions: 8, anomalousDimensions: 0, timeline: [{ t: 0, rate: null }, { t: 60, rate: 0 }] },
      ],
      ranked: [],
    });
    expect(r?.timestamps).toEqual([0, 60]);
    expect(r?.interval).toBe(60);
    expect(r?.dimensions?.map((d) => d.values)).toEqual([[0, 5], [null, 0]]);
    expect(timelineResult({ after: 0, before: 1, nodes: [], ranked: [] })).toBeUndefined();
  });

  it('formats alert ages', () => {
    const now = Date.parse('2026-10-04T12:00:00Z');
    expect(since('2026-10-04T11:59:30Z', now)).toBe('30s');
    expect(since('2026-10-04T11:30:00Z', now)).toBe('30m');
    expect(since('2026-10-04T06:00:00Z', now)).toBe('6.0h');
    expect(since('2026-10-01T12:00:00Z', now)).toBe('3.0d');
  });
});

describe('evidencePath', () => {
  it('passes the window, node and only workload-identifying labels', () => {
    const p = new URL(evidencePath({ context: 'workload.red_errors', node: 'n1', labels: { namespace: 'shop', workload: 'cart', workload_kind: 'Deployment' }, after: 100, before: 200 }), 'http://x');
    expect(p.pathname).toBe('/api/v1/metrics/evidence');
    expect(p.searchParams.get('context')).toBe('workload.red_errors');
    expect(p.searchParams.get('node')).toBe('n1');
    expect(p.searchParams.get('labels')).toBe('namespace:shop,workload:cart');
    expect(p.searchParams.get('after')).toBe('100');
  });
  it('omits node and labels when absent', () => {
    const p = new URL(evidencePath({ context: 'net.net', after: 1, before: 2 }), 'http://x');
    expect(p.searchParams.has('node')).toBe(false);
    expect(p.searchParams.has('labels')).toBe(false);
  });
});
