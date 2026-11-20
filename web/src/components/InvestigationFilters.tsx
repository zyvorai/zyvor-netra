import { useEffect, useState } from 'react';
import { navigate, useRoute } from '../hooks/useInvestigation';
import { emptyScope } from '../lib/investigation';
export default function InvestigationFilters({ traffic = true }: { traffic?: boolean }) {
  const { page, scope } = useRoute();
  const [copied, setCopied] = useState('');
  // Local echo for the four free-text filters: scope[key] only updates via
  // the async browser "hashchange" event fired after navigate() sets
  // window.location.hash. Binding the input's value directly to scope[key]
  // means any re-render that lands before that event fires resets the DOM
  // value to the still-stale scope, dropping whatever was just typed —
  // reproducible under fast typing, not just automated keystroke injection.
  const [draft, setDraft] = useState({ namespace: scope.namespace, pod: scope.pod, node: scope.node, query: scope.query });
  useEffect(() => { setDraft({ namespace: scope.namespace, pod: scope.pod, node: scope.node, query: scope.query }); }, [scope.namespace, scope.pod, scope.node, scope.query]);
  function change(key: 'namespace' | 'pod' | 'node' | 'query', value: string) {
    setDraft(d => ({ ...d, [key]: value }));
    navigate(page, { [key]: value });
  }
  return <section className="investigation-filters" aria-label="Investigation filters">
    {(['namespace', 'pod', 'node', 'query'] as const).map(key => <label key={key}>{key === 'query' ? 'Search' : key === 'pod' ? 'Pod (exact)' : `${key} (exact)`}<input value={draft[key]} placeholder={key === 'query' ? 'IP, process, DNS or workload' : 'All'} onChange={e => change(key, e.target.value)} /></label>)}
    {traffic && <>
      <label>Direction<select value={scope.direction} onChange={e => navigate(page, { direction: e.target.value })}><option value="">All</option><option value="ingress">Ingress</option><option value="egress">Egress</option></select></label>
      <label>Protocol<select value={scope.protocol} onChange={e => navigate(page, { protocol: e.target.value })}><option value="">All</option>{['TCP', 'UDP', 'ICMP', 'ICMPv6'].map(p => <option key={p}>{p}</option>)}</select></label>
      <label>Outcome<select value={scope.action} onChange={e => navigate(page, { action: e.target.value })}><option value="">All</option><option value="blocked">Blocked</option><option value="observed">Observed</option></select></label>
    </>}
    <div className="toolbar"><button onClick={() => navigate(page, emptyScope)}>Clear filters</button><button onClick={async () => { try { await navigator.clipboard.writeText(window.location.href); setCopied('Link copied'); } catch { setCopied('Copy the URL from your address bar'); } }}>Copy view link</button><span role="status">{copied}</span></div>
  </section>;
}
