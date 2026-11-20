import { describe, expect, it } from 'vitest';
import { coverage, emptyScope, endpoint, eventRows, explainEvent, observedWorkloads, readRoute, routeHash, type Agent } from './investigation';
const agents: Agent[] = [
  { node: 'edge-1', stale: false, observedAt: '2026-09-12T10:00:00Z', programs: [{ name: 'cgroup', attached: true }], workloads: [{ namespace: 'prod', pod: 'api', workloadKind: 'ReplicaSet', workloadName: 'api-abc' }], events: [
    { namespace: 'prod', pod: 'api', destinationIp: '2001:db8::1', destinationPort: 443, protocol: 'TCP', action: 'blocked', reason: 'cidr-deny', hook: 'cgroup', direction: 'egress', observedAt: '2026-09-12T09:59:00Z' },
    { namespace: 'dev', pod: 'api', destinationIp: '10.0.0.1', protocol: 'UDP', action: 'observed', direction: 'ingress', observedAt: '2026-09-12T09:58:00Z' },
  ] },
  { node: 'edge-2', stale: true, events: [{ namespace: 'prod', pod: 'api', action: 'passed', comm: 'curl', observedAt: '2026-09-12T09:57:00Z' }] },
];
describe('investigation route and scope', () => {
  it('roundtrips special characters and never needs a credential', () => {
    const scope = { ...emptyScope, namespace: 'prod', query: 'a&b / # + IPv6::' };
    expect(readRoute(routeHash('connections', scope))).toEqual({ page: 'connections', scope });
    expect(routeHash('connections', scope)).not.toContain('token');
  });
  it('handles unknown pages and drops unknown parameters', () => {
    expect(readRoute('#page=evil&token=secret').page).toBe('overview');
    expect(routeHash('overview', readRoute('#token=secret').scope)).toBe('#page=overview');
  });
  it('joins namespace, pod, and node exactly', () => {
    const rows = eventRows(agents, { ...emptyScope, namespace: 'prod', pod: 'api', node: 'edge-1' });
    expect(rows).toHaveLength(1); expect(rows[0].reason).toBe('cidr-deny');
    expect(eventRows(agents, { ...emptyScope, namespace: 'pro' })).toHaveLength(0);
  });
  it('combines search, outcome, direction and protocol', () => {
    expect(eventRows(agents, { ...emptyScope, query: 'DB8', protocol: 'tcp', direction: 'EGRESS', action: 'blocked' })).toHaveLength(1);
    expect(eventRows(agents, { ...emptyScope, query: 'db8', action: 'passed' })).toHaveLength(0);
  });
  it('searches processes and keeps stale evidence explicit', () => {
    const rows = eventRows(agents, { ...emptyScope, query: 'CURL' });
    expect(rows).toHaveLength(1); expect(rows[0].stale).toBe(true);
  });
  it('sorts by event time and tolerates missing data', () => {
    expect(eventRows(agents, emptyScope).map(e => e.action)).toEqual(['blocked', 'observed', 'passed']);
    expect(eventRows([{ node: 'empty' }], emptyScope)).toEqual([]);
  });
});
describe('evidence boundaries', () => {
  it('explains a reported drop without claiming rule identity', () => {
    const e = explainEvent({ action: 'blocked', reason: 'netpol-rule', hook: 'cgroup' });
    expect(e.title).toBe('Blocked at this Netra hook'); expect(e.evidence).toContain('netpol-rule'); expect(e.limitation).toContain('does not identify a stable rule ID');
  });
  it.each(['passed', 'allowed', 'observed'])('does not equate %s with delivery', action => {
    expect(explainEvent({ action }).limitation).toContain('does not prove end-to-end delivery');
  });
  it('does not invent an outcome or reason', () => {
    expect(explainEvent({}).title).toBe('Outcome unavailable');
    expect(explainEvent({}).evidence).toContain('does not include a reason');
  });
  it('retains owner metadata and separates same-named workloads on different nodes', () => {
    const rows = observedWorkloads(agents, { ...emptyScope, namespace: 'prod' });
    expect(rows).toHaveLength(2); expect(rows[0].workloadName).toBe('api-abc');
    expect(observedWorkloads([{ node: 'x', events: [{ sourceIp: '1.2.3.4' }] }], emptyScope)).toEqual([]);
  });
  it('never treats missing reports as healthy coverage', () => {
    expect(coverage([])).toEqual({ reporting: 0, stale: 0, unknown: 0, partial: 0 });
    expect(coverage([{ node: 'x' }]).unknown).toBe(1);
    expect(coverage(agents).stale).toBe(1);
    expect(coverage([{ node: 'x', stale: false, programs: [{ name: 'optional', attached: false }] }]).partial).toBe(1);
  });
  it('formats IPv6 endpoints without ambiguous ports', () => {
    expect(endpoint('2001:db8::1', 443)).toBe('[2001:db8::1]:443');
    expect(endpoint('10.0.0.1', 53)).toBe('10.0.0.1:53'); expect(endpoint()).toBe('Unknown');
  });
});
