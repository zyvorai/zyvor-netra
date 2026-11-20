// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
import { dnsResponseFinding, type DNSResponseEvent } from '../lib/dns';
import { TableWrap } from './Toolbar';

type Agent = { node: string; stale?: boolean; observedAt?: string; events?: DNSResponseEvent[] };
export default function DNSDiagnostics({ agents, now = Date.now() }: { agents: Agent[]; now?: number }) {
  const fresh = (stamp?: string) => {
    const age = now - Date.parse(stamp || '');
    return Number.isFinite(age) && age >= -60_000 && age <= 120_000;
  };
  const rows = agents.filter(a => a.node && !a.stale && fresh(a.observedAt))
    .flatMap(a => (a.events || []).flatMap(e => {
      const finding = dnsResponseFinding(e);
      return finding?.kind === 'dns-response-error' && fresh(e.observedAt) ? [{ node: a.node, event: e, finding }] : [];
    })).sort((a, b) => Date.parse(b.event.observedAt) - Date.parse(a.event.observedAt) || a.node.localeCompare(b.node));
  return <section className="card span3" aria-labelledby="dns-errors-title">
    <p className="eyebrow">DNS RESPONSE DIAGNOSTICS</p>
    <h2 id="dns-errors-title" className="card-title">Why did DNS fail?</h2>
    <p>Reported matched UDP/53 responses from the last two minutes. These events are not a complete error count or failure rate. Only base-header response codes are available; EDNS extended errors, answer records, TCP DNS, DoH, and DoT are not inferred.</p>
    {rows.length === 0 ? <p className="empty-state">No recent DNS error response evidence. Missing events do not prove DNS is healthy or that unmatched queries timed out.</p> : <div className="datatable-scroll investigation-table">
      <TableWrap><table aria-label="DNS error responses">
        <thead><tr><th scope="col">Node / workload</th><th scope="col">Query / resolver</th><th scope="col">Response</th><th scope="col">Reported timing</th><th scope="col">Next check</th></tr></thead>
        <tbody>{rows.slice(0, 50).map(({ node, event: e, finding: f }, i) => <tr key={`${node}/${e.observedAt}/${i}`}>
          <td>{node}<br />{e.namespace && e.pod ? `${e.namespace}/${e.pod}` : 'Workload not reported'}</td>
          <td>{e.dnsQuery}<br />{e.sourceIp || 'Resolver not reported'}</td>
          <td>{f.name} ({f.code})</td>
          <td>{((e.latencyUs || 0) / 1000).toFixed(2)} ms<br /><time dateTime={e.observedAt}>{e.observedAt}</time></td>
          <td>{f.nextCheck}</td>
        </tr>)}</tbody>
      </table></TableWrap>
      {rows.length > 50 && <p>Showing the latest 50 of {rows.length} reported error events.</p>}
    </div>}
  </section>;
}
