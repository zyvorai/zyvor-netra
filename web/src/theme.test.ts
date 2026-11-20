import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

const store = new Map<string, string>();

vi.stubGlobal('localStorage', {
  getItem: (k: string) => store.get(k) ?? null,
  setItem: (k: string, v: string) => {
    store.set(k, v);
  },
  removeItem: (k: string) => {
    store.delete(k);
  },
});

const attrs = new Map<string, string>();
vi.stubGlobal('document', {
  documentElement: {
    setAttribute: (k: string, v: string) => {
      attrs.set(k, v);
    },
    getAttribute: (k: string) => attrs.get(k) ?? null,
    removeAttribute: (k: string) => {
      attrs.delete(k);
    },
  },
  querySelector: () => null,
});

import { applyTheme, readStoredTheme, toggleTheme } from './theme';

describe('theme', () => {
  beforeEach(() => {
    store.clear();
    attrs.clear();
  });

  afterEach(() => {
    store.clear();
    attrs.clear();
  });

  it('defaults to light when unset', () => {
    expect(readStoredTheme()).toBe('light');
  });

  it('respects an explicitly stored dark preference', () => {
    store.set('netra-theme', 'dark');
    expect(readStoredTheme()).toBe('dark');
  });

  it('applies dark and persists', () => {
    applyTheme('dark');
    expect(attrs.get('data-theme')).toBe('dark');
    expect(store.get('netra-theme')).toBe('dark');
    expect(readStoredTheme()).toBe('dark');
  });

  it('toggles light ↔ dark', () => {
    expect(toggleTheme('light')).toBe('dark');
    expect(attrs.get('data-theme')).toBe('dark');
    expect(toggleTheme('dark')).toBe('light');
    expect(attrs.get('data-theme')).toBe('light');
  });
});
