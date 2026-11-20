// ruleTypeClass groups a Firewall Rules table row's `type` field (EBPF.tsx)
// into the same deny/allow/throttle split already implicit in the naming
// convention used across EBPF.tsx's rule types: bare names (ip4/cidr/port/
// uid/dns/sni/process) and the policy engines (netpol/netpol-v2) are deny
// mechanisms, "allow-"-prefixed names are exceptions, and rate/shield are
// throttles rather than a hard allow/deny.
export function ruleTypeClass(type?: string): string {
  const t = (type || '').toLowerCase();
  if (t.startsWith('allow')) return 'rule-allow';
  if (t === 'rate' || t === 'shield') return 'rule-rate';
  return 'rule-deny';
}
