import { describe, it, expect } from 'vitest';
import { hasGlob, matchGlob } from './glob';

describe('glob', () => {
  it('detects wildcards', () => {
    expect(hasGlob('kube-*')).toBe(true);
    expect(hasGlob('prod-?')).toBe(true);
    expect(hasGlob('default')).toBe(false);
  });

  it('matches exact and substring', () => {
    expect(matchGlob('default', 'default')).toBe(true);
    expect(matchGlob('Default', 'default')).toBe(true);
    expect(matchGlob('def', 'default')).toBe(false);
    expect(matchGlob('def', 'default', { substring: true })).toBe(true);
    expect(matchGlob('', 'anything')).toBe(true);
  });

  it('matches * and ?', () => {
    expect(matchGlob('kube-*', 'kube-system')).toBe(true);
    expect(matchGlob('kube-*', 'default')).toBe(false);
    expect(matchGlob('prod-?', 'prod-a')).toBe(true);
    expect(matchGlob('prod-?', 'prod-ab')).toBe(false);
    expect(matchGlob('*web*', 'my-web-pod', { substring: true })).toBe(true);
  });
});
