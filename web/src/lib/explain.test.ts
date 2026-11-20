import { describe, expect, it } from 'vitest';
import { buildExplainReport, emptyExplainScope, parseExplainScope, type ExplainAgentStatus, type ExplainScope } from './explain';

function scope(overrides: Partial<ExplainScope>): ExplainScope {
  return { ...emptyExplainScope, ...overrides };
}

describe('parseExplainScope validation', () => {
  const bad: Partial<ExplainScope>[] = [
    {},
    { pid: '1' },
    { node: 'n', pid: '0' },
    { pod: 'api' },
    { pod: 'ns/api', namespace: 'other' },
    { all: true, limit: 0 },
    { all: true, limit: 1001 },
    { all: true, maxAgeMinutes: 0 },
    { destination: 'example.com:443' },
    { destination: '1.2.3.4:0' },
    { dns: 'example.com', node: 'n', pid: '1' },
    { dns: '.' },
    { node: ' n' },
  ];
  for (const o of bad) {
    it(`rejects ${JSON.stringify(o)}`, () => {
      const r = parseExplainScope(scope(o));
      expect('error' in r).toBe(true);
    });
  }
});

describe('parseExplainScope selectors', () => {
  it('splits pod into namespace/pod and normalizes an IPv6 destination+port', () => {
    const r = parseExplainScope(scope({ pod: 'prod/api', destination: '[2001:db8::1]:443' }));
    if (!('scope' in r)) throw new Error('expected scope');
    expect(r.scope.namespace).toBe('prod');
    expect(r.scope.pod).toBe('api');
    expect(r.scope.ip).toBe('2001:db8::1');
    expect(r.scope.port).toBe(443);
  });

  it('unmaps an IPv4-mapped IPv6 destination', () => {
    const r = parseExplainScope(scope({ destination: '::ffff:192.0.2.1' }));
    if (!('scope' in r)) throw new Error('expected scope');
    expect(r.scope.ip).toBe('192.0.2.1');
  });

  it('lowercases and trims a trailing dot from --dns', () => {
    const r = parseExplainScope(scope({ dns: 'EXAMPLE.COM.' }));
    if (!('scope' in r)) throw new Error('expected scope');
    expect(r.scope.dns).toBe('example.com');
  });
});

function fixture(): { agents: ExplainAgentStatus[]; now: Date } {
  const now = new Date('2026-09-13T00:00:00Z');
  const nowIso = now.toISOString();
  return {
    now,
    agents: [
      {
        node: 'node-b',
        stale: false,
        observedAt: nowIso,
        events: [
          {
            namespace: 'prod',
            pod: 'api',
            pid: 42,
            action: 'blocked',
            reason: 'port-deny',
            observedAt: nowIso,
            destinationIp: '',
            destinationPort: 0,
          },
        ],
      },
      {
        node: 'node-a',
        stale: false,
        observedAt: nowIso,
        events: [
          {
            namespace: 'prod',
            pod: 'api',
            pid: 42,
            containerId: 'container-exact',
            action: 'blocked',
            reason: 'cidr-deny',
            hook: 'cgroup',
            destinationIp: '192.0.2.1',
            destinationPort: 443,
            observedAt: nowIso,
          },
          { namespace: 'dev', pod: 'api', action: 'observed', observedAt: nowIso, destinationIp: '', destinationPort: 0 },
        ],
        tcpHealth: [
          {
            namespace: 'prod',
            pod: 'api',
            pid: 42,
            remoteIp: '192.0.2.1',
            remotePort: 443,
            activeEstablished: 1,
            passiveEstablished: 0,
            retransmissions: 2,
            rtos: 1,
          },
        ],
        dnsHealth: [{ namespace: 'prod', pod: 'api', name: 'example.com', queries: 3, responses: 2, failures: 1 }],
      },
    ],
  };
}

describe('buildExplainReport', () => {
  it('scopes findings to a specific node+pid, excluding the other node and DNS (no pod identity)', () => {
    const { agents, now } = fixture();
    const r = parseExplainScope(scope({ node: 'node-a', pid: '42' }));
    if (!('scope' in r)) throw new Error('expected scope');
    const report = buildExplainReport(agents, r.scope, now);
    expect(report.agentsConsidered).toBe(1);
    expect(report.findingsTotal).toBe(3); // 1 blocked event + tcp-established + tcp-loss-signal
    expect(report.findings.every((f) => f.node === 'node-a')).toBe(true);
  });

  it('finds DNS counters when scoped to namespace/pod with no pid/container/destination', () => {
    const { agents, now } = fixture();
    const r = parseExplainScope(scope({ pod: 'prod/api' }));
    if (!('scope' in r)) throw new Error('expected scope');
    const report = buildExplainReport(agents, r.scope, now);
    expect(report.findings.some((f) => f.kind === 'dns-counters')).toBe(true);
  });

  it('excludes stale agents', () => {
    const { agents, now } = fixture();
    agents[1].stale = true;
    const r = parseExplainScope(scope({ all: true }));
    if (!('scope' in r)) throw new Error('expected scope');
    const report = buildExplainReport(agents, r.scope, now);
    expect(report.agentsExcluded).toBe(1);
  });

  it('truncates findings to the limit but still reports the true total', () => {
    const { agents, now } = fixture();
    const r = parseExplainScope(scope({ all: true, limit: 1 }));
    if (!('scope' in r)) throw new Error('expected scope');
    const report = buildExplainReport(agents, r.scope, now);
    expect(report.findings.length).toBe(1);
    expect(report.findingsTotal).toBeGreaterThan(1);
    expect(report.truncated).toBe(true);
  });
});


describe('node ICMP explanation', () => {
  const now = new Date('2026-09-13T00:00:00Z');
  const agents: ExplainAgentStatus[] = [{ node: 'n', stale: false, observedAt: now.toISOString(), icmpErrors: [
    { interfaceIndex: 2, family: 'IPv4', type: 3, code: 4, direction: 'ingress', hook: 'tc', packets: 3, advertisedMtu: 1400 },
  ] }];
  it('includes node observations without assigning a workload', () => {
    const parsed = parseExplainScope(scope({ node: 'n' }));
    if ('error' in parsed) throw new Error(parsed.error);
    const r = buildExplainReport(agents, parsed.scope, now);
    expect(r.findingsTotal).toBe(1);
    expect(r.findings[0].kind).toBe('icmp-pmtu');
    expect(r.findings[0].evidence).toContain('last-advertised-mtu=1400');
    expect(r.findings[0].pod).toBeUndefined();
  });
  it('excludes unrelated scope and stale reports', () => {
    for (const selector of [{ node: 'other' }, { namespace: 'ns' }, { pod: 'ns/p' }, { node: 'n', pid: '1' }, { container: 'id' }, { destination: '192.0.2.1' }, { dns: 'example.com' }]) {
      const parsed = parseExplainScope(scope(selector));
      if ('error' in parsed) throw new Error(parsed.error);
      expect(buildExplainReport(agents, parsed.scope, now).findingsTotal).toBe(0);
    }
    const parsed = parseExplainScope(scope({ all: true }));
    if ('error' in parsed) throw new Error(parsed.error);
    expect(buildExplainReport(agents, parsed.scope, new Date(now.getTime() + 121_000)).findingsTotal).toBe(0);
  });
});

describe('bpf-maps-missing explanation', () => {
  const now = new Date('2026-09-13T00:00:00Z');
  const agents: ExplainAgentStatus[] = [{ node: 'n', stale: false, observedAt: now.toISOString(), missingMaps: ['allowed_ports', 'rate_v6'] }];
  it('includes node observations without assigning a workload', () => {
    const parsed = parseExplainScope(scope({ node: 'n' }));
    if ('error' in parsed) throw new Error(parsed.error);
    const r = buildExplainReport(agents, parsed.scope, now);
    expect(r.findingsTotal).toBe(1);
    expect(r.findings[0].kind).toBe('bpf-maps-missing');
    expect(r.findings[0].evidence).toContain('allowed_ports');
    expect(r.findings[0].pod).toBeUndefined();
  });
  it('excludes unrelated scope and stale reports', () => {
    for (const selector of [{ node: 'other' }, { namespace: 'ns' }, { pod: 'ns/p' }, { node: 'n', pid: '1' }, { container: 'id' }, { destination: '192.0.2.1' }, { dns: 'example.com' }]) {
      const parsed = parseExplainScope(scope(selector));
      if ('error' in parsed) throw new Error(parsed.error);
      expect(buildExplainReport(agents, parsed.scope, now).findingsTotal).toBe(0);
    }
  });
});

describe('rate-drop explanation', () => {
  const now = new Date('2026-09-13T00:00:00Z');
  const agents: ExplainAgentStatus[] = [{ node: 'n', stale: false, observedAt: now.toISOString(), rateDrops: [{ name: '203.0.113.5', count: 42 }] }];
  it('matches node-wide and destination scope', () => {
    const parsed = parseExplainScope(scope({ node: 'n' }));
    if ('error' in parsed) throw new Error(parsed.error);
    const r = buildExplainReport(agents, parsed.scope, now);
    expect(r.findingsTotal).toBe(1);
    expect(r.findings[0].kind).toBe('rate-drop');
    expect(r.findings[0].evidence).toContain('203.0.113.5');

    const dst = parseExplainScope(scope({ destination: '203.0.113.5' }));
    if ('error' in dst) throw new Error(dst.error);
    expect(buildExplainReport(agents, dst.scope, now).findingsTotal).toBe(1);

    const other = parseExplainScope(scope({ destination: '198.51.100.9' }));
    if ('error' in other) throw new Error(other.error);
    expect(buildExplainReport(agents, other.scope, now).findingsTotal).toBe(0);
  });
  it('excludes identity scope', () => {
    for (const selector of [{ node: 'other' }, { namespace: 'ns' }, { pod: 'ns/p' }, { node: 'n', pid: '1' }, { container: 'id' }, { dns: 'example.com' }]) {
      const parsed = parseExplainScope(scope(selector));
      if ('error' in parsed) throw new Error(parsed.error);
      expect(buildExplainReport(agents, parsed.scope, now).findingsTotal).toBe(0);
    }
  });
});
