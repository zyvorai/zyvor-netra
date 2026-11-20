import { describe, it, expect } from 'vitest';
import { upsertPreset, removePreset, type CapturePreset } from './capturePresets';

const base: CapturePreset[] = [
  { name: 'ssh', protocol: 'tcp', port: '22' },
  { name: 'dns', protocol: 'udp', port: '53' },
];

describe('upsertPreset', () => {
  it('adds a new preset, sorted by name', () => {
    const out = upsertPreset(base, { name: 'https', protocol: 'tcp', port: '443' });
    expect(out.map((p) => p.name)).toEqual(['dns', 'https', 'ssh']);
  });

  it('replaces an existing preset with the same name', () => {
    const out = upsertPreset(base, { name: 'ssh', protocol: 'tcp', port: '2222' });
    expect(out).toHaveLength(2);
    expect(out.find((p) => p.name === 'ssh')?.port).toBe('2222');
  });
});

describe('removePreset', () => {
  it('removes a preset by name', () => {
    expect(removePreset(base, 'ssh').map((p) => p.name)).toEqual(['dns']);
  });

  it('is a no-op for an unknown name', () => {
    expect(removePreset(base, 'nope')).toHaveLength(2);
  });
});
