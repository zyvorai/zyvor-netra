import { describe, expect, it } from 'vitest';
import { BLANK_CELLS, SEVERITY_GLOSS, STAGES, STAGE_GLOSSARY, conntrackCeiling, formatStageRate, nodeStageSeverity, stageForLayer, stageLiveRate, stageRateForWindow, stageSummaries, worstSeverity } from './CongestionMap';

// The 12 layers below are grepped directly from internal/kerneldiag/analyze.go's
// `Layer: "..."` literals. If a 13th is ever added there without a matching
// STAGES entry in CongestionMap.tsx, this test starts failing — that's the point.
const REAL_LAYERS = [
  'softnet-backlog',
  'softnet-budget',
  'tcp-receive',
  'socket-receive',
  'socket-send',
  'tcp-listen',
  'tcp-memory',
  'qdisc',
  'conntrack',
  'nic-driver',
  'ip',
  'tcp-connection-quality',
];

describe('stageForLayer', () => {
  it('maps every real Layer literal to a stage', () => {
    for (const layer of REAL_LAYERS) {
      expect(stageForLayer(layer), `layer ${layer} should map to a stage`).toBeDefined();
    }
  });

  it('returns undefined for an unknown layer', () => {
    expect(stageForLayer('made-up-layer')).toBeUndefined();
  });

  it('covers every layer referenced by STAGES exactly once', () => {
    const allLayers = STAGES.flatMap((s) => s.layers);
    expect(new Set(allLayers).size).toBe(allLayers.length);
  });
});

describe('STAGES + BLANK_CELLS grid placement', () => {
  it('never places two cells (a stage or a blank placeholder) in the same column/row — a real bug this once shipped: ip and conntrack both at (shared, row 3) silently overlapped, so conntrack painted over and completely hid the IP layer card', () => {
    const cells = [...STAGES.map((s) => `${s.column}:${s.row}`), ...BLANK_CELLS.map((b) => `${b.column}:${b.row}`)];
    const seen = new Set<string>();
    for (const cell of cells) {
      expect(seen.has(cell), `duplicate grid position ${cell}`).toBe(false);
      seen.add(cell);
    }
  });
});

describe('STAGE_GLOSSARY', () => {
  it('has a non-empty what/why entry for every declared stage', () => {
    for (const stage of STAGES) {
      const g = STAGE_GLOSSARY[stage.key];
      expect(g, `missing glossary entry for ${stage.key}`).toBeDefined();
      expect(g.what.length, `${stage.key} glossary "what" is empty`).toBeGreaterThan(0);
      expect(g.why.length, `${stage.key} glossary "why" is empty`).toBeGreaterThan(0);
    }
  });
});

describe('SEVERITY_GLOSS', () => {
  it('has a friendly word for every StageSeverity value', () => {
    for (const sev of ['critical', 'warning', 'ok', 'warming'] as const) {
      expect(SEVERITY_GLOSS[sev], `missing gloss for ${sev}`).toBeTruthy();
    }
  });
});

describe('worstSeverity', () => {
  it('ranks critical above warning above ok above warming', () => {
    expect(worstSeverity(['ok', 'critical', 'warning'])).toBe('critical');
    expect(worstSeverity(['ok', 'warning'])).toBe('warning');
    expect(worstSeverity(['warming', 'ok'])).toBe('ok');
    expect(worstSeverity(['warming', 'warming'])).toBe('warming');
  });

  it('defaults to ok for an empty list', () => {
    expect(worstSeverity([])).toBe('ok');
  });
});

describe('nodeStageSeverity', () => {
  const stage = STAGES.find((s) => s.key === 'napi-softnet')!;

  it('returns the worst severity among matching findings', () => {
    const node = {
      node: 'n1',
      window: { warming: false },
      findings: [
        { severity: 'warning', layer: 'softnet-backlog', signal: 'a', explanation: '', recommendation: '', risk: '' },
        { severity: 'critical', layer: 'softnet-budget', signal: 'b', explanation: '', recommendation: '', risk: '' },
      ],
    };
    expect(nodeStageSeverity(node, stage)).toBe('critical');
  });

  it('returns warming when the node window is warming and has no matching findings', () => {
    const node = { node: 'n1', window: { warming: true }, findings: [] };
    expect(nodeStageSeverity(node, stage)).toBe('warming');
  });

  it('returns ok when not warming and no matching findings', () => {
    const node = { node: 'n1', window: { warming: false }, findings: [] };
    expect(nodeStageSeverity(node, stage)).toBe('ok');
  });

  it('ignores findings from unrelated layers', () => {
    const node = {
      node: 'n1',
      window: { warming: false },
      findings: [{ severity: 'critical', layer: 'qdisc', signal: 'x', explanation: '', recommendation: '', risk: '' }],
    };
    expect(nodeStageSeverity(node, stage)).toBe('ok');
  });
});

describe('stageSummaries', () => {
  it('aggregates worst-per-node severity across the whole cluster', () => {
    const nodes = [
      {
        node: 'n1',
        window: { warming: false },
        findings: [{ severity: 'critical', layer: 'qdisc', signal: 'x', explanation: '', recommendation: '', risk: '' }],
      },
      { node: 'n2', window: { warming: false }, findings: [] },
    ];
    const out = stageSummaries(nodes);
    expect(out.get('qdisc')?.severity).toBe('critical');
    expect(out.get('qdisc')?.perNode.map((p) => p.severity)).toEqual(['critical', 'ok']);
    expect(out.get('nic-driver')?.severity).toBe('ok');
  });

  it('shows warming, never a false-clean ok, when every node is still warming', () => {
    const nodes = [
      { node: 'n1', window: { warming: true }, findings: [] },
      { node: 'n2', window: { warming: true }, findings: [] },
    ];
    const out = stageSummaries(nodes);
    for (const stage of STAGES) {
      expect(out.get(stage.key)?.severity).toBe('warming');
    }
  });

  it('has one summary entry per declared stage', () => {
    const out = stageSummaries([]);
    expect(out.size).toBe(STAGES.length);
  });
});

describe('stageLiveRate', () => {
  it('aggregates the dedicated window fields for nic-driver', () => {
    const nodes = [
      { node: 'n1', window: { warming: false, rxMissedPerSecond: 1, rxDroppedPerSecond: 2, txDroppedPerSecond: 3, rxMissed: 10, rxDropped: 20, txDropped: 30 } },
    ];
    expect(stageLiveRate(nodes, 'nic-driver')).toEqual({ perSecond: 6, delta: 60 });
  });

  it('aggregates the dedicated window fields for napi-softnet and qdisc', () => {
    const nodes = [
      { node: 'n1', window: { warming: false, softnetDroppedPerSecond: 1, softnetTimeSqueezePerSecond: 2, softnetDropped: 5, softnetTimeSqueeze: 6, qdiscDropsPerSecond: 4, qdiscDrops: 40 } },
    ];
    expect(stageLiveRate(nodes, 'napi-softnet')).toEqual({ perSecond: 3, delta: 11 });
    expect(stageLiveRate(nodes, 'qdisc')).toEqual({ perSecond: 4, delta: 40 });
  });

  it('sums exactly the named counters analyze.go uses as evidence for a counter-driven stage', () => {
    const nodes = [
      {
        node: 'n1',
        window: {
          warming: false,
          counters: [
            { name: 'TcpExt.ListenDrops', delta: 3, perSecond: 0.1 },
            { name: 'TcpExt.ListenOverflows', delta: 2, perSecond: 0.05 },
            { name: 'Tcp.EstabResets', delta: 999, perSecond: 99 }, // not tcp-listen evidence — must be ignored
          ],
        },
      },
    ];
    expect(stageLiveRate(nodes, 'tcp-listen')).toEqual({ perSecond: 0.15000000000000002, delta: 5 });
  });

  it('excludes warming nodes from the aggregate', () => {
    const nodes = [
      { node: 'n1', window: { warming: true, qdiscDropsPerSecond: 100, qdiscDrops: 1000 } },
      { node: 'n2', window: { warming: false, qdiscDropsPerSecond: 1, qdiscDrops: 10 } },
    ];
    expect(stageLiveRate(nodes, 'qdisc')).toEqual({ perSecond: 1, delta: 10 });
  });

  it('returns null for conntrack (no window-based rate exists)', () => {
    expect(stageLiveRate([{ node: 'n1', window: { warming: false } }], 'conntrack')).toBeNull();
  });

  it('returns null when no node has a settled window', () => {
    expect(stageLiveRate([{ node: 'n1', window: { warming: true } }], 'qdisc')).toBeNull();
    expect(stageLiveRate([], 'qdisc')).toBeNull();
  });
});

describe('stageRateForWindow', () => {
  it('matches what stageLiveRate computes for a single-node array — regression guard for the extraction', () => {
    const window = { warming: false, qdiscDropsPerSecond: 4, qdiscDrops: 40 };
    expect(stageRateForWindow(window, 'qdisc')).toEqual(stageLiveRate([{ node: 'n1', window }], 'qdisc'));
  });
});

describe('formatStageRate', () => {
  it('formats a zero rate as an explicit measurement, not a blank', () => {
    expect(formatStageRate({ perSecond: 0, delta: 0 })).toBe('0 in this window · 0.00/s across cluster');
  });

  it('formats a null rate as null (caller decides whether to render anything)', () => {
    expect(formatStageRate(null)).toBeNull();
  });

  it('rounds a large per-second rate and keeps two decimals for a small one', () => {
    expect(formatStageRate({ perSecond: 12.7, delta: 500 })).toBe('500 in this window · 13/s across cluster');
    expect(formatStageRate({ perSecond: 3.5, delta: 1082 })).toBe('1,082 in this window · 3.50/s across cluster');
  });
});

describe('conntrackCeiling', () => {
  it('returns the nf_conntrack_max tunable value from the first node that has it', () => {
    const nodes = [
      { node: 'n1', snapshot: { tunables: [{ name: 'net.core.somaxconn', value: '4096' }] } },
      { node: 'n2', snapshot: { tunables: [{ name: 'net.netfilter.nf_conntrack_max', value: '393216' }] } },
    ];
    expect(conntrackCeiling(nodes)).toBe('393216');
  });

  it('returns null when no node has the tunable', () => {
    expect(conntrackCeiling([{ node: 'n1', snapshot: { tunables: [] } }])).toBeNull();
  });
});
