import { describe, it, expect } from 'vitest';
import { buildIPIndex, labelForIP } from './workloadAttribution';

describe('buildIPIndex / labelForIP', () => {
  it('indexes pods by podIP', () => {
    const idx = buildIPIndex([{ namespace: 'netra-system', name: 'netra-0', podIP: '10.42.0.12' }], []);
    expect(labelForIP(idx, '10.42.0.12')).toBe('pod netra-system/netra-0');
  });

  it('indexes VMs by podIP and prefers pods on collision', () => {
    const idx = buildIPIndex(
      [{ namespace: 'ns', name: 'pod-a', podIP: '10.42.0.5' }],
      [{ namespace: 'ns', name: 'vm-a', podIP: '10.42.0.5' }, { namespace: 'ns', name: 'vm-b', podIP: '10.42.0.6' }],
    );
    expect(labelForIP(idx, '10.42.0.5')).toBe('pod ns/pod-a');
    expect(labelForIP(idx, '10.42.0.6')).toBe('vm ns/vm-b');
  });

  it('returns undefined for an unknown or missing IP', () => {
    const idx = buildIPIndex([{ namespace: 'ns', name: 'pod-a', podIP: '10.42.0.5' }], []);
    expect(labelForIP(idx, '1.2.3.4')).toBeUndefined();
    expect(labelForIP(idx, undefined)).toBeUndefined();
  });

  it('skips entities with no podIP', () => {
    const idx = buildIPIndex([{ namespace: 'ns', name: 'pending-pod' }], []);
    expect(idx.size).toBe(0);
  });
});
