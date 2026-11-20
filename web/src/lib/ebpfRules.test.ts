import { describe, it, expect } from 'vitest';
import { ruleTypeClass } from './ebpfRules';

describe('ruleTypeClass', () => {
  it('classifies bare deny types', () => {
    expect(ruleTypeClass('ip4')).toBe('rule-deny');
    expect(ruleTypeClass('cidr')).toBe('rule-deny');
    expect(ruleTypeClass('port')).toBe('rule-deny');
    expect(ruleTypeClass('uid')).toBe('rule-deny');
    expect(ruleTypeClass('dns')).toBe('rule-deny');
    expect(ruleTypeClass('sni')).toBe('rule-deny');
    expect(ruleTypeClass('process')).toBe('rule-deny');
  });

  it('classifies allow-* types', () => {
    expect(ruleTypeClass('allow-cidr')).toBe('rule-allow');
    expect(ruleTypeClass('allow-port')).toBe('rule-allow');
  });

  it('classifies rate/shield as throttle', () => {
    expect(ruleTypeClass('rate')).toBe('rule-rate');
    expect(ruleTypeClass('shield')).toBe('rule-rate');
  });

  it('classifies netpol engines as deny', () => {
    expect(ruleTypeClass('netpol')).toBe('rule-deny');
    expect(ruleTypeClass('netpol-v2')).toBe('rule-deny');
  });

  it('defaults unknown/missing types to deny', () => {
    expect(ruleTypeClass(undefined)).toBe('rule-deny');
    expect(ruleTypeClass('')).toBe('rule-deny');
  });
});
