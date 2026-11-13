import { describe, expect, it } from 'vitest';
import { ASK_SUGGESTIONS, canAsk, formatGraphSteps, looksLikeDraft } from './AskNetra';

describe('AskNetra helpers', () => {
  it('ships a short read-only suggestion set', () => {
    expect(ASK_SUGGESTIONS.length).toBeGreaterThanOrEqual(3);
    expect(ASK_SUGGESTIONS.every((q) => q.length < 80)).toBe(true);
  });

  it('blocks empty or in-flight questions', () => {
    expect(canAsk('', false)).toBe(false);
    expect(canAsk('   ', false)).toBe(false);
    expect(canAsk('what dropped?', true)).toBe(false);
    expect(canAsk('what dropped?', false)).toBe(true);
  });

  it('detects deny/rate/allow sentences for the preview pane', () => {
    expect(looksLikeDraft('deny dns malware.example')).toBe(true);
    expect(looksLikeDraft('allow 10.0.0.5')).toBe(true);
    expect(looksLikeDraft('quarantine that workload')).toBe(true);
    expect(looksLikeDraft('why is DNS failing?')).toBe(false);
    expect(ASK_SUGGESTIONS.some((q) => /JA3|ECH/i.test(q))).toBe(true);
    expect(ASK_SUGGESTIONS.some((q) => /GenAI|shadow SaaS|netlink/i.test(q))).toBe(true);
  });

  it('formats the in-process graph step trace', () => {
    expect(formatGraphSteps(undefined)).toBe('');
    expect(formatGraphSteps([
      { node: 'classify', detail: 'drops' },
      { node: 'synthesize', detail: 'answer from snapshot' },
    ])).toBe('classify:drops → synthesize:answer from snapshot');
  });
});
