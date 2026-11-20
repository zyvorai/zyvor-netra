import { useEffect, useRef, useState } from 'react';
import { endpoint, explainEvent, type EventRow } from '../lib/investigation';
import { navigate } from '../hooks/useInvestigation';
export default function ConnectionDrawer({ event, close }: { event: EventRow; close: () => void }) {
  const dialog = useRef<HTMLDialogElement>(null);
  // Capture the trigger during the first render. Reading document.activeElement inside the effect
  // was too late: the Close button's autoFocus is applied at commit, before effects run, so
  // "previous" was the Close button itself and focus fell to <body> when the dialog closed.
  const [previous] = useState<HTMLElement | null>(() => document.activeElement as HTMLElement | null);
  useEffect(() => { dialog.current?.showModal(); return () => { dialog.current?.close(); previous?.focus(); }; }, [previous]);
  const explanation = explainEvent(event);
  return <dialog ref={dialog} className="connection-drawer" onCancel={e => { e.preventDefault(); close(); }} aria-labelledby="connection-title">
    <div className="toolbar"><p className="eyebrow">CONNECTION EVIDENCE</p><button autoFocus onClick={close} aria-label="Close connection details">Close</button></div>
    <h2 id="connection-title">{explanation.title}</h2>
    {event.stale && <p className="warning">This event comes from a stale agent report.</p>}
    <p className="connection-tuple">{endpoint(event.sourceIp, event.sourcePort)} → {endpoint(event.destinationIp, event.destinationPort)}</p>
    <dl className="evidence-grid">{Object.entries({ Node: event.node, Workload: event.pod ? `${event.namespace}/${event.pod}` : 'Unattributed', Process: event.comm ? `${event.comm}${event.pid ? ` · PID ${event.pid}` : ''}` : 'Not reported', Protocol: event.protocol, Direction: event.direction, Hook: event.hook, Outcome: event.action, 'Event time': event.observedAt, 'Agent report time': event.reportAt, 'DNS name': event.dnsQuery }).map(([k, v]) => <div key={k}><dt>{k}</dt><dd>{v || 'Not reported'}</dd></div>)}</dl>
    <h3>What the evidence says</h3><p>{explanation.evidence}</p><p>{explanation.limitation}</p>
    <p>Sampled events are not a complete connection history. A process name is not verified executable identity.</p>
    <div className="toolbar">{event.namespace && event.pod && <button className="primary" onClick={() => { navigate('workloads', { namespace: event.namespace, pod: event.pod, node: event.node, query: '' }); close(); }}>Open workload</button>}<button onClick={() => { navigate('ebpf'); close(); }}>Review current firewall</button></div>
    <details><summary>Raw event</summary><pre className="mini">{JSON.stringify(event, null, 2)}</pre></details>
  </dialog>;
}
