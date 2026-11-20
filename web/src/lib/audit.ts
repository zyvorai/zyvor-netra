// auditActionClass groups an audit log's `domain.verb` action string
// (e.g. "capture.start", "ebpf.deny.add", "policy.rollback") into a color
// class by its verb suffix — the action space is high-cardinality (~50
// distinct strings across internal/store) but every value follows this
// suffix convention, so no per-action enum is needed.
export function auditActionClass(action?: string): string {
  const a = (action || '').toLowerCase();
  if (a.endsWith('.delete') || a.includes('.deny')) return 'action-destructive';
  if (a.endsWith('.add') || a.endsWith('.apply') || a.endsWith('.mode')) return 'action-mutating';
  if (a.endsWith('.start') || a.endsWith('.stop') || a.endsWith('.rollback')) return 'action-lifecycle';
  return '';
}
