import { describe, expect, it } from 'vitest';
import { classifyMissingMaps, missingMapMessage } from './missingMaps';

describe('classifyMissingMaps', () => {
  it('classifies real BPF map names', () => {
    expect(classifyMissingMaps(['rate_state_v4', 'icmp_type_stats'])).toEqual([
      { raw: 'rate_state_v4', kind: 'bpf-map' },
      { raw: 'icmp_type_stats', kind: 'bpf-map' },
    ]);
  });

  it('classifies an afpacket capture-backend failure', () => {
    expect(classifyMissingMaps(['afpacket:CAP_NET_RAW'])).toEqual([
      { raw: 'afpacket:CAP_NET_RAW', kind: 'afpacket-backend' },
    ]);
  });

  it('classifies an ebpf capture-backend failure', () => {
    expect(classifyMissingMaps(['ebpf:capture_events map unavailable'])).toEqual([
      { raw: 'ebpf:capture_events map unavailable', kind: 'ebpf-capture-backend' },
    ]);
  });

  it('classifies a mixed list without cross-contamination', () => {
    const got = classifyMissingMaps(['rate_state_v4', 'afpacket:CAP_NET_RAW', 'icmp_type_stats']);
    expect(got.map((e) => e.kind)).toEqual(['bpf-map', 'afpacket-backend', 'bpf-map']);
  });
});

describe('missingMapMessage', () => {
  it('gives distinct copy per kind', () => {
    const bpfMap = missingMapMessage('bpf-map');
    const afpacket = missingMapMessage('afpacket-backend');
    const ebpfCapture = missingMapMessage('ebpf-capture-backend');
    expect(new Set([bpfMap, afpacket, ebpfCapture]).size).toBe(3);
    expect(afpacket).toMatch(/CAP_NET_RAW/);
    expect(ebpfCapture).toMatch(/capture/i);
  });
});
