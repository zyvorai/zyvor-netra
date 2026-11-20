// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
import { describe, expect, it } from 'vitest';
import { pages } from './investigation';
import { navGroups } from './navGroups';

const navPages = navGroups.flatMap((g) => (g.page ? [g.page] : (g.children || []).map((c) => c.page)));

describe('navGroups', () => {
  it('makes every routable page reachable from the menu', () => {
    for (const p of pages) expect(navPages, `page "${p}" is missing from the nav`).toContain(p);
  });

  it('only links to real pages', () => {
    for (const p of navPages) expect(pages as readonly string[], `nav links to unknown page "${p}"`).toContain(p);
  });

  it('gives every menu link a label and a blurb', () => {
    for (const g of navGroups) {
      for (const c of g.children || []) {
        expect(c.label.trim(), `label for ${c.page}`).not.toBe('');
        expect(c.blurb.trim(), `blurb for ${c.page}`).not.toBe('');
      }
    }
  });
});
