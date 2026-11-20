// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

import { icmpFinding, type ICMPError } from '../lib/icmp';
import { TableWrap } from './Toolbar';
type Agent = { node: string; stale?: boolean; observedAt?: string; icmpErrors?: ICMPError[] };

export default function ICMPDiagnostics({ agents, now = Date.now() }: { agents: Agent[]; now?: number }) {
  const rows = agents.filter(a => {
    const age = now - Date.parse(a.observedAt || '');
    return a.node && !a.stale && Number.isFinite(age) && age >= -60_000 && age <= 120_000;
  }).flatMap(a => (a.icmpErrors || []).filter(e => icmpFinding(e))
    .map(e => ({ ...e, node: a.node })))
    .sort((a, b) => b.packets - a.packets || a.node.localeCompare(b.node) || a.interfaceIndex - b.interfaceIndex);
  return <section className="card span3" aria-labelledby="icmp-title">
    <p className="eyebrow">ICMP DIAGNOSTICS</p>
    <h2 id="icmp-title" className="card-title">MTU, unreachable destinations, and routing errors</h2>
    <p>Cumulative observations from current node reports. A packet can appear on multiple interfaces; these counters do not identify a failing workload or connection. Advertised MTUs are unverified peer claims. Interface names reflect the current lookup; indices can be reused.</p>
    {rows.length === 0 ? <p className="empty-state">No ICMP error evidence in fresh reports. Check agent support and TC attachment before concluding the path is healthy.</p> : <div className="datatable-scroll investigation-table">
      <TableWrap><table aria-label="ICMP error observations">
        <thead><tr><th scope="col">Node / interface</th><th scope="col">Signal</th><th scope="col">Observations</th><th scope="col">Last advertised MTU</th><th scope="col">Next check</th></tr></thead>
        <tbody>{rows.slice(0, 50).map((e, i) => {
          const { label, nextCheck } = icmpFinding(e)!;
          return <tr key={`${e.node}/${e.interfaceIndex}/${e.family}/${e.type}/${e.code}/${e.direction}/${i}`}>
            <td>{e.node} / {e.interfaceName && <>{e.interfaceName} · </>}index {e.interfaceIndex}<br />{e.direction} · TC</td>
            <td>{label}<br />{e.family} type {e.type}, code {e.code}</td>
            <td>{e.packets.toLocaleString()}</td><td>{e.advertisedMtu ? `${e.advertisedMtu} bytes` : 'Not advertised'}</td>
            <td>{nextCheck}</td>
          </tr>;
        })}</tbody>
      </table></TableWrap>
      {rows.length > 50 && <p>Showing 50 of {rows.length} observations. Use <code>netractl explain --node NODE --limit 1000</code> to inspect more.</p>}
    </div>}
  </section>;
}
