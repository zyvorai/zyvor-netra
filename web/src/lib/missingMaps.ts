// AgentReport.MissingMaps (internal/agent/agent.go's missingMaps()) folds
// two different things into one string slice on purpose: real missing BPF
// map names, and a capture-backend failure sentinel
// (captureBackendErr, e.g. "afpacket:CAP_NET_RAW" or
// "ebpf:capture_spec map unavailable") — reusing the existing node-health
// channel rather than inventing a second one. That's a deliberate Go-side
// choice; on this side, rendering every entry with the same "rebuild and
// roll the agent image" copy is wrong for a capture-capability problem, so
// this module classifies each entry to pick the right message instead.
export type MissingMapKind = 'bpf-map' | 'afpacket-backend' | 'ebpf-capture-backend';
export type MissingMapEntry = { raw: string; kind: MissingMapKind };

export function classifyMissingMaps(entries: string[]): MissingMapEntry[] {
  return entries.map((raw) => {
    if (raw.startsWith('afpacket:')) return { raw, kind: 'afpacket-backend' };
    if (raw.startsWith('ebpf:')) return { raw, kind: 'ebpf-capture-backend' };
    return { raw, kind: 'bpf-map' };
  });
}

export function missingMapMessage(kind: MissingMapKind): string {
  switch (kind) {
    case 'afpacket-backend':
      return 'AF_PACKET capture unavailable on this node — grant CAP_NET_RAW (or run the agent privileged) to enable raw-socket capture. This does not affect the core eBPF datapath.';
    case 'ebpf-capture-backend':
      return "The eBPF packet-capture object isn't attached on this node — roll the agent image to restore capture. This is isolated to Capture; the core datapath is unaffected.";
    case 'bpf-map':
    default:
      return 'Rebuild and roll the agent image so allow/rate/icmp maps exist. Until then those controls fail open.';
  }
}
