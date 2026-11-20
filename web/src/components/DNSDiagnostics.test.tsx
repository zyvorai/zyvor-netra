// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
import { describe, it, expect } from 'vitest';
import { renderToStaticMarkup } from 'react-dom/server';
import DNSDiagnostics from './DNSDiagnostics';
const now = Date.parse('2026-09-13T00:00:00Z');
const event = { type: 'dns-response', action: 'observed', protocol: 'UDP', hook: 'cgroup', direction: 'ingress', sourcePort: 53, sourceIp: '192.0.2.53', dnsQuery: 'api.example.com', dnsRcode: 3, latencyUs: 1250, observedAt: new Date(now).toISOString(), namespace: 'prod', pod: 'api' };
const agent = { node: 'n', observedAt: event.observedAt, events: [event] };
describe('DNS diagnostics panel', () => {
  it('shows the error, resolver, workload, timing and next check', () => {
    const html = renderToStaticMarkup(<DNSDiagnostics agents={[agent]} now={now} />);
    for (const text of ['NXDOMAIN (3)', '192.0.2.53', 'prod/api', '1.25 ms', 'search domains', 'not a complete error count']) expect(html).toContain(text);
  });
  it('excludes stale reports and old, missing, future, or successful events', () => {
    const agents = [{ ...agent, stale: true }, { ...agent, observedAt: new Date(now - 121000).toISOString() }, { ...agent, events: [
      { ...event, observedAt: new Date(now - 121000).toISOString() }, { ...event, observedAt: '' }, { ...event, observedAt: new Date(now + 61000).toISOString() }, { ...event, dnsRcode: 0 }, { ...event, type: 'dns' },
    ] }];
    const html = renderToStaticMarkup(<DNSDiagnostics agents={agents} now={now} />);
    expect(html).toContain('No recent DNS error response evidence');
    expect(html).not.toContain('NXDOMAIN (3)');
  });
  it('escapes untrusted names and retains unknown workload state', () => {
    const html = renderToStaticMarkup(<DNSDiagnostics agents={[{ ...agent, events: [{ ...event, dnsQuery: '<script>alert(1)</script>', namespace: undefined, pod: undefined }] }]} now={now} />);
    expect(html).not.toContain('<script>');
    expect(html).toContain('&lt;script&gt;');
    expect(html).toContain('Workload not reported');
  });
  it('bounds rows and handles old agents without DNS events', () => {
    const html = renderToStaticMarkup(<DNSDiagnostics agents={[{ ...agent, events: Array.from({ length: 51 }, () => ({ ...event })) }]} now={now} />);
    expect(html).toContain('latest 50 of 51');
    expect(html.match(/NXDOMAIN \(3\)/g)).toHaveLength(50);
    expect(renderToStaticMarkup(<DNSDiagnostics agents={[{ node: 'old' }]} now={now} />)).toContain('No recent DNS error');
  });
});
