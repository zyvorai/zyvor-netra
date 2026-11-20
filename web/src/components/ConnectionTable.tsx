import { useEffect, useState } from 'react';
import { endpoint, type EventRow } from '../lib/investigation';
import ConnectionDrawer from './ConnectionDrawer';
import { TableWrap } from './Toolbar';
export default function ConnectionTable({ rows }: { rows: EventRow[] }) {
  const [selected, setSelected] = useState<EventRow>();
  const [page, setPage] = useState(0);
  useEffect(() => { setPage(0); }, [rows]);
  const size = 50;
  return <><div className="toolbar"><span>{rows.length} sampled events</span><button disabled={page === 0} onClick={() => setPage(p => p - 1)}>Previous</button><span>Page {page + 1} of {Math.max(1, Math.ceil(rows.length / size))}</span><button disabled={(page + 1) * size >= rows.length} onClick={() => setPage(p => p + 1)}>Next</button></div>
    <TableWrap className="investigation-table"><table><thead><tr><th>Outcome / time</th><th>Workload / node</th><th>Source → destination</th><th>Protocol / hook</th><th>Evidence</th></tr></thead><tbody>
      {rows.slice(page * size, (page + 1) * size).map(e => <tr key={e.id}><td><span className={e.action === 'blocked' ? 'outcome blocked' : 'outcome'}>{e.action || 'Unknown'}</span><small>{e.observedAt ? new Date(e.observedAt).toLocaleString() : 'Time unavailable'}{e.stale ? ' · stale report' : ''}</small></td><td>{e.pod ? `${e.namespace}/${e.pod}` : 'Unattributed'}<small>{e.node}</small></td><td>{endpoint(e.sourceIp, e.sourcePort)}<small>→ {endpoint(e.destinationIp, e.destinationPort)}</small></td><td>{e.protocol || 'Unknown'}<small>{e.hook || 'Unknown hook'} · {e.direction || 'Unknown direction'}</small></td><td><button onClick={() => setSelected(e)}>Explain connection</button></td></tr>)}
    </tbody></table></TableWrap>{rows.length === 0 && <p className="empty-state">No sampled events match this view. Check filters and agent coverage; absence of events does not prove absence of traffic.</p>}
    {selected && <ConnectionDrawer event={selected} close={() => setSelected(undefined)} />}
  </>;
}
