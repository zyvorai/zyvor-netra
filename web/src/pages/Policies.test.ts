// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
import { describe, expect, it } from 'vitest';
import { gitopsHint } from './Policies';

describe('gitopsHint', () => {
  it('does not repeat a message the controller already sent', () => {
    expect(gitopsHint('Error: GitOps is not enabled (set NETRA_GITOPS_DIR)')).toBe('GitOps is not enabled (set NETRA_GITOPS_DIR)');
  });
  it('appends an unrelated failure to the hint', () => {
    expect(gitopsHint('Error: Failed to fetch')).toBe('GitOps is not enabled (set NETRA_GITOPS_DIR) — Failed to fetch');
  });
  it('falls back to the hint when there is no detail', () => {
    expect(gitopsHint('Error:')).toBe('GitOps is not enabled (set NETRA_GITOPS_DIR)');
  });
});
