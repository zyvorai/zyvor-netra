import { describe, expect, it } from 'vitest';
import { draftQuestionFromFinding } from './ExplainFinding';

describe('draftQuestionFromFinding', () => {
  it('drafts an IP deny from a drop subject', () => {
    expect(draftQuestionFromFinding('kfree_skb', 'pay/api → 10.9.8.7:443', 'policy drop')).toBe('deny 10.9.8.7');
  });

  it('drafts a DNS deny from a dns finding', () => {
    expect(draftQuestionFromFinding('dns-failure', 'kube-system/coredns', 'SERVFAIL for malware.example')).toBe(
      'deny dns malware.example',
    );
  });

  it('returns null when there is no exact match', () => {
    expect(draftQuestionFromFinding('stale-agent', 'node/n1', 'agent heartbeat missed')).toBeNull();
  });
});
