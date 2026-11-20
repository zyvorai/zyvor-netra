// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
import { describe, expect, it } from 'vitest';
import { renderToStaticMarkup } from 'react-dom/server';
import ICMPDiagnostics from './ICMPDiagnostics';

const now = Date.parse('2026-09-13T00:00:00Z');
const error = { interfaceIndex: 2, family: 'IPv6', type: 2, code: 0, direction: 'ingress', hook: 'tc', packets: 5, advertisedMtu: 1280 };
const agent = { node: 'node-a', observedAt: new Date(now).toISOString(), icmpErrors: [error] };
describe('ICMP diagnostics', () => {
  it('shows current interface names with their indices and escapes them', () => {
    const html = renderToStaticMarkup(<ICMPDiagnostics agents={[{ ...agent, icmpErrors: [{ ...error, interfaceName: '<eth0>' }] }]} now={now} />);
    expect(html).toContain('&lt;eth0&gt;');
    expect(html).toContain('index 2');
    expect(html).toContain('indices can be reused');
  });
  it('shows usable MTU evidence and its attribution limits', () => {
    const html = renderToStaticMarkup(<ICMPDiagnostics agents={[agent]} now={now} />);
    expect(html).toContain('1280 bytes');
    expect(html).toContain('index 2');
    expect(html).toContain('unverified peer claims');
    expect(html).toContain('do not identify a failing workload');
    expect(html).toContain('Check interface and tunnel MTUs');
  });
  it('excludes stale, old, undated, future, zero-count, and non-TC data', () => {
    const agents = [{ ...agent, stale: true }, { ...agent, observedAt: new Date(now - 121_000).toISOString() },
      { ...agent, observedAt: undefined }, { ...agent, observedAt: new Date(now + 61_000).toISOString() },
      { ...agent, icmpErrors: [{ ...error, packets: 0 }, { ...error, hook: 'cgroup' }] }];
    const html = renderToStaticMarkup(<ICMPDiagnostics agents={agents} now={now} />);
    expect(html).toContain('No ICMP error evidence');
    expect(html).not.toContain('1280 bytes');
  });
  it('supports old agent reports and escapes untrusted node labels', () => {
    expect(renderToStaticMarkup(<ICMPDiagnostics agents={[{ node: 'old' }]} now={now} />)).toContain('Check agent support');
    const html = renderToStaticMarkup(<ICMPDiagnostics agents={[{ ...agent, node: '<script>alert(1)</script>' }]} now={now} />);
    expect(html).not.toContain('<script>');
    expect(html).toContain('&lt;script&gt;');
  });
  it('bounds the visible rows and discloses truncation', () => {
    const agents = Array.from({ length: 51 }, (_, i) => ({ ...agent, node: `node-${i}` }));
    const html = renderToStaticMarkup(<ICMPDiagnostics agents={agents} now={now} />);
    expect(html).toContain('Showing 50 of 51');
    expect(html.match(/1280 bytes/g)).toHaveLength(50);
  });
});
