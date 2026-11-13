// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

import { describe, expect, it } from 'vitest';
import { surfaceRowHandoff } from './surfaceHandoff';

describe('surfaceRowHandoff', () => {
  it('sends shadow SaaS rows to flow observe', () => {
    const h = surfaceRowHandoff('shadow', { namespace: 'ns', pod: 'api', host: 'slack.com' });
    expect(h?.page).toBe('flow-observe');
    expect(h?.scope.query).toBe('slack.com');
  });

  it('sends DNS intel to security review', () => {
    const h = surfaceRowHandoff('dnsintel', { host: 'evil.example' });
    expect(h?.page).toBe('security-review');
  });

  it('sends lateral drafts to deny preview', () => {
    const h = surfaceRowHandoff('lateral', { namespace: 'payments', pod: 'worker' });
    expect(h?.page).toBe('deny-preview');
  });

  it('sends TLS risk to fingerprints page', () => {
    const h = surfaceRowHandoff('tls-risk', { ja3: 'abc' });
    expect(h?.page).toBe('tls-fingerprints');
  });
});
