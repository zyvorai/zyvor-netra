// Read-only views over AgentReport. Never infer a winning policy from current config.
export type Scope = { namespace: string; pod: string; node: string; query: string; direction: string; protocol: string; action: string };
export const emptyScope: Scope = { namespace: '', pod: '', node: '', query: '', direction: '', protocol: '', action: '' };
export const pages = ['overview', 'connections', 'workloads', 'explain', 'pods', 'vms', 'health', 'path', 'drops', 'congestion', 'sysctl-audit', 'node-resources', 'l7', 'surfaces', 'features', 'insights', 'topology', 'incidents', 'policies', 'flows', 'ebpf', 'audit', 'report', 'scorecard', 'talkers', 'fleet', 'traffic', 'capture', 'metrics', 'metric-anomalies', 'metric-alerts'] as const;
export type Route = { page: typeof pages[number]; scope: Scope };
export function readRoute(hash: string): Route {
  const params = new URLSearchParams(hash.replace(/^#/, ''));
  const page = params.get('page') as Route['page'];
  const scope = { ...emptyScope };
  for (const key of Object.keys(scope) as (keyof Scope)[]) scope[key] = params.get(key) || '';
  return { page: pages.includes(page) ? page : 'overview', scope };
}
export function routeHash(page: Route['page'], scope: Scope): string {
  const params = new URLSearchParams({ page });
  for (const [key, value] of Object.entries(scope)) if (value) params.set(key, value);
  return '#' + params.toString();
}
export type NetworkEvent = {
  observedAt?: string; type?: string; hook?: string; direction?: string; protocol?: string;
  sourceIp?: string; destinationIp?: string; sourcePort?: number; destinationPort?: number;
  action?: string; reason?: string; namespace?: string; pod?: string; comm?: string; pid?: number; dnsQuery?: string;
};
export type Workload = { namespace?: string; pod?: string; node?: string; workloadKind?: string; workloadName?: string; labels?: Record<string, string> };
export type Agent = {
  node: string; stale?: boolean; ageSeconds?: number; observedAt?: string; mode?: string;
  hooks?: string[]; programs?: { name: string; attached: boolean }[]; workloads?: Workload[];
  events?: NetworkEvent[]; stats?: (Workload & { packets?: number; blocked?: number; destinationIp?: string })[];
};
export type EventRow = NetworkEvent & { node: string; stale: boolean; reportAt?: string; id: string };
export function matchesIdentity(row: Workload, scope: Scope) {
  return (!scope.namespace || row.namespace === scope.namespace) && (!scope.pod || row.pod === scope.pod) && (!scope.node || row.node === scope.node);
}
export function eventRows(agents: Agent[], scope: Scope): EventRow[] {
  const q = scope.query.toLowerCase().trim();
  return agents.flatMap(a => (a.events || []).map((e, index) => ({ ...e, node: a.node, stale: a.stale === true, reportAt: a.observedAt, id: `${a.node}:${index}` })))
    .filter(e => matchesIdentity(e, scope) && (!scope.direction || e.direction?.toLowerCase() === scope.direction.toLowerCase()) &&
      (!scope.protocol || e.protocol?.toUpperCase() === scope.protocol.toUpperCase()) && (!scope.action || e.action === scope.action) &&
      (!q || [e.sourceIp, e.destinationIp, e.pod, e.namespace, e.comm, e.dnsQuery, e.reason, e.node].some(v => v?.toLowerCase().includes(q))))
    .sort((a, b) => (Date.parse(b.observedAt || '') || 0) - (Date.parse(a.observedAt || '') || 0));
}
export function observedWorkloads(agents: Agent[], scope: Scope): Workload[] {
  const rows = new Map<string, Workload>();
  for (const a of agents) for (const w of [...(a.workloads || []), ...(a.stats || []), ...(a.events || [])]) {
    if (!w.namespace || !w.pod) continue;
    const row = { ...w, node: a.node };
    const key = JSON.stringify([a.node, w.namespace, w.pod]);
    if (!rows.has(key)) rows.set(key, row);
  }
  return [...rows.values()].filter(w => matchesIdentity(w, scope) && (!scope.query || [w.pod, w.namespace, w.node, w.workloadName].some(v => v?.toLowerCase().includes(scope.query.toLowerCase()))))
    .sort((a, b) => `${a.namespace}/${a.pod}/${a.node}`.localeCompare(`${b.namespace}/${b.pod}/${b.node}`));
}
export function explainEvent(event: NetworkEvent): { title: string; evidence: string; limitation: string } {
  const blocked = event.action === 'blocked';
  const passed = event.action === 'passed' || event.action === 'allowed' || event.action === 'observed';
  return {
    title: blocked ? 'Blocked at this Netra hook' : passed ? 'Not blocked at this Netra hook' : 'Outcome unavailable',
    evidence: event.reason ? `The event reports reason “${event.reason}” at ${event.hook || 'an unspecified hook'}.` : 'This event does not include a reason code.',
    limitation: blocked ? 'The event does not identify a stable rule ID or policy generation. Current rules cannot prove which historical rule caused this drop.' : 'This does not prove end-to-end delivery or an explicit allow rule. Other hooks or network devices may still block traffic.',
  };
}
export function coverage(agents: Agent[]) {
  return { reporting: agents.length, stale: agents.filter(a => a.stale === true).length,
    unknown: agents.filter(a => a.stale !== true && (!a.programs?.length || typeof a.stale !== 'boolean')).length,
    partial: agents.filter(a => a.stale === false && a.programs?.some(p => !p.attached)).length };
}
export function endpoint(ip?: string, port?: number) { return ip ? `${ip.includes(':') ? `[${ip}]` : ip}${port ? `:${port}` : ''}` : 'Unknown'; }
