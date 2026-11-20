// Best-effort IP -> workload attribution for captured packets. Pod/VM IPs
// are directly routable on this cluster's CNI, so a captured frame's own
// src/dst IP is often literally a pod's IP — no correlation heuristics
// needed, just a lookup. This does NOT attribute to a process/PID: that
// would require the capture eBPF program itself (bpf/netra_capture.c) to
// record cgroup/PID context at capture time, which is a kernel-side change
// out of scope here.
export type LabeledWorkload = { namespace: string; name: string; podIP?: string };

export function buildIPIndex(pods: LabeledWorkload[], vms: LabeledWorkload[]): Map<string, string> {
  const idx = new Map<string, string>();
  for (const p of pods) if (p.podIP) idx.set(p.podIP, `pod ${p.namespace}/${p.name}`);
  for (const v of vms) if (v.podIP && !idx.has(v.podIP)) idx.set(v.podIP, `vm ${v.namespace}/${v.name}`);
  return idx;
}

export function labelForIP(index: Map<string, string>, ip?: string): string | undefined {
  return ip ? index.get(ip) : undefined;
}
