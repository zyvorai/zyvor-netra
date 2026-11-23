// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0
import { describe, expect, it } from 'vitest';
import { bundleFileName, bundleQuery, headline, rowCount, truncatedLists } from './incidentBundle';

describe('incident bundle helpers', () => {
  it('clamps minutes and drops unknown sections and masks', () => {
    expect(bundleQuery(5000, '', [], '')).toBe('minutes=1440');
    expect(bundleQuery(-3, ' n1 ', ['audit', 'bogus'], 'prefix')).toBe('minutes=1&node=n1&exclude=audit&mask_ips=prefix');
    expect(bundleQuery(Number.NaN, '', [], 'weird')).toBe('minutes=15');
  });

  it('counts rows but not truncation notes', () => {
    expect(rowCount(undefined)).toBe(0);
    expect(rowCount({ events: [1, 2], truncated: [{ list: 'events', total: 9, kept: 2 }], available: true })).toBe(2);
  });

  it('lists truncations per section and writes a headline', () => {
    const doc = {
      window: { minutes: 15 },
      identity: { nodes: 1 },
      bounds: { bytes: 2048 },
      sections: { flows: { truncated: [{ list: 'flows', total: 300, kept: 100 }] }, audit: { truncated: [] } },
    };
    expect(truncatedLists(doc)).toEqual([{ section: 'flows', list: 'flows', total: 300, kept: 100 }]);
    expect(headline(doc)).toBe('15 min, 1 node, 2 KiB, 1 truncated list');
    expect(headline(undefined)).toBe('');
  });

  it('names the download from the generation time', () => {
    expect(bundleFileName({ generatedAt: '2026-11-20T12:00:00Z' })).toBe('netra-incident-20261120T120000Z.json');
    expect(bundleFileName(undefined)).toBe('netra-incident-bundle.json');
  });
});
