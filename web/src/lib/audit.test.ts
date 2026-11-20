import { describe, it, expect } from 'vitest';
import { auditActionClass } from './audit';

describe('auditActionClass', () => {
  it('classifies delete and deny actions as destructive', () => {
    expect(auditActionClass('policy.delete')).toBe('action-destructive');
    expect(auditActionClass('ebpf.deny.add')).toBe('action-destructive');
    expect(auditActionClass('ebpf.deny.delete')).toBe('action-destructive');
  });

  it('classifies add/apply/mode actions as mutating', () => {
    expect(auditActionClass('ebpf.allow.add')).toBe('action-mutating');
    expect(auditActionClass('policy.apply')).toBe('action-mutating');
    expect(auditActionClass('ebpf.mode')).toBe('action-mutating');
  });

  it('classifies start/stop/rollback actions as lifecycle', () => {
    expect(auditActionClass('capture.start')).toBe('action-lifecycle');
    expect(auditActionClass('capture.stop')).toBe('action-lifecycle');
    expect(auditActionClass('policy.rollback')).toBe('action-lifecycle');
  });

  it('returns empty string for unrecognized or missing actions', () => {
    expect(auditActionClass('insights.baseline.capture')).toBe('');
    expect(auditActionClass(undefined)).toBe('');
    expect(auditActionClass('')).toBe('');
  });
});
