// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
import { describe, it, expect } from 'vitest';
import { dnsResponseFinding, type DNSResponseEvent } from './dns';
import { buildExplainReport, emptyExplainScope, parseExplainScope, type ExplainAgentStatus } from './explain';
const now = new Date('2026-09-13T00:00:00Z');
const event: DNSResponseEvent = { type: 'dns-response', action: 'observed', protocol: 'UDP', hook: 'cgroup', direction: 'ingress', sourcePort: 53, sourceIp: '192.0.2.53', dnsQuery: 'api.example.com', dnsRcode: 3, latencyUs: 1250, observedAt: now.toISOString(), namespace: 'prod', pod: 'api' };
describe('DNS response diagnosis', () => {
  it('classifies base-header codes without inventing specific causes', () => {
    for (const [code, name] of [[0, 'NOERROR'], [1, 'FORMERR'], [2, 'SERVFAIL'], [3, 'NXDOMAIN'], [4, 'NOTIMP'], [5, 'REFUSED'], [6, 'RCODE_6'], [15, 'RCODE_15']] as const) {
      const f = dnsResponseFinding({ ...event, dnsRcode: code });
      expect(f?.name).toBe(name);
      expect(f?.kind).toBe(code === 0 ? 'dns-response' : 'dns-response-error');
    }
    expect(dnsResponseFinding({ ...event, dnsRcode: undefined })?.name).toBe('NOERROR');
    expect(dnsResponseFinding({ ...event, dnsRcode: 0 })?.nextCheck).toContain('does not prove an answer');
  });
  it('rejects non-native events and malformed response codes', () => {
    for (const change of [{ type: 'dns' }, { action: 'blocked' }, { protocol: 'TCP' }, { hook: 'tc' }, { direction: 'egress' }, { sourcePort: 5353 }, { dnsQuery: '' }, { dnsRcode: -1 }, { dnsRcode: 16 }, { dnsRcode: 2.5 }, { dnsRcode: NaN }]) {
      expect(dnsResponseFinding({ ...event, ...change })).toBeNull();
    }
  });
  it('integrates with Explain exactly once and preserves scope and freshness', () => {
    const agents: ExplainAgentStatus[] = [{ node: 'n', stale: false, observedAt: now.toISOString(), events: [{ ...event, destinationIp: '192.0.2.10', destinationPort: 42000 }] }];
    for (const [overrides, count] of [[{ pod: 'prod/api', dns: 'API.EXAMPLE.COM.' }, 1], [{ node: 'other' }, 0], [{ namespace: 'other' }, 0], [{ dns: 'other.example.com' }, 0], [{ destination: '192.0.2.53' }, 0]] as const) {
      const parsed = parseExplainScope({ ...emptyExplainScope, ...overrides });
      if ('error' in parsed) throw Error(parsed.error);
      const r = buildExplainReport(agents, parsed.scope, now);
      expect(r.findingsTotal).toBe(count);
      if (count) expect(r.findings[0].kind).toBe('dns-response-error');
      expect(buildExplainReport([{ ...agents[0], stale: true }], parsed.scope, now).findingsTotal).toBe(0);
    }
  });
});
