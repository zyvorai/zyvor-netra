// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
import { describe, expect, it } from 'vitest';
import { aiStatusLine } from './AskNetra';

describe('aiStatusLine', () => {
  it('labels the server\'s mutations clause instead of gluing it on', () => {
    expect(aiStatusLine({ enabled: false, heuristicOnly: true, mutations: 'never — AI endpoints are read-only' })).toBe(
      'Heuristic engine only · Mutations: never — AI endpoints are read-only',
    );
  });
  it('names the rewrite model when one is configured, falling back to the provider', () => {
    expect(aiStatusLine({ enabled: true, heuristicOnly: false, model: 'gpt-x', provider: 'acme', mutations: 'never' })).toBe('Optional rewrite on · gpt-x · Mutations: never');
    expect(aiStatusLine({ enabled: true, heuristicOnly: false, provider: 'acme', mutations: 'never' })).toBe('Optional rewrite on · acme · Mutations: never');
  });
  it('never prints "undefined" when fields are missing', () => {
    const line = aiStatusLine({ enabled: true, heuristicOnly: false } as never);
    expect(line).toBe('Optional rewrite on');
    expect(line).not.toContain('undefined');
  });
});
