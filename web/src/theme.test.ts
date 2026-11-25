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
const meta = new Map<string, string>();
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
  querySelector: () => ({
    setAttribute: (k: string, v: string) => {
      meta.set(k, v);
    },
  }),
});

let systemDark = false;
const listeners = new Set<() => void>();
vi.stubGlobal('window', {
  matchMedia: () => ({
    get matches() {
      return systemDark;
    },
    addEventListener: (_: string, f: () => void) => listeners.add(f),
    removeEventListener: (_: string, f: () => void) => listeners.delete(f),
  }),
});
const osChange = (dark: boolean) => {
  systemDark = dark;
  listeners.forEach((f) => f());
};

import { applyPreference, followSystemTheme, paintedTheme, readStoredPreference, resolveTheme } from './theme';
import initScript from '../public/theme-init.js?raw';

const runInitScript = () => new Function(initScript)();

describe('theme', () => {
  beforeEach(() => {
    store.clear();
    attrs.clear();
    meta.clear();
    listeners.clear();
    systemDark = false;
  });

  afterEach(() => {
    store.clear();
    attrs.clear();
  });

  it('defaults to system when unset, resolved from the operating system', () => {
    expect(readStoredPreference()).toBe('system');
    expect(resolveTheme('system')).toBe('light');
    systemDark = true;
    expect(resolveTheme('system')).toBe('dark');
  });

  it('respects an explicit choice over the operating system', () => {
    systemDark = true;
    store.set('netra-appearance', 'light');
    expect(readStoredPreference()).toBe('light');
    expect(resolveTheme(readStoredPreference())).toBe('light');
  });

  it('applies a preference and persists it', () => {
    applyPreference('dark');
    expect(attrs.get('data-theme')).toBe('dark');
    expect(meta.get('content')).toBe('#000000');
    expect(store.get('netra-appearance')).toBe('dark');
    expect(readStoredPreference()).toBe('dark');
    expect(paintedTheme()).toBe('dark');
    applyPreference('system');
    expect(attrs.get('data-theme')).toBe('light');
    expect(meta.get('content')).toBe('#f5f5f7');
    expect(store.get('netra-appearance')).toBe('system');
  });

  it('keeps a legacy dark choice and treats the old automatic light as system', () => {
    store.set('netra-theme', 'dark');
    expect(readStoredPreference()).toBe('dark');
    store.set('netra-theme', 'light');
    expect(readStoredPreference()).toBe('system');
    store.set('netra-theme', 'dark');
    store.set('netra-appearance', 'system');
    expect(readStoredPreference()).toBe('system');
  });

  it('ignores an unknown stored value', () => {
    store.set('netra-appearance', 'sepia');
    expect(readStoredPreference()).toBe('system');
  });

  it('follows operating-system changes only while the preference is system', () => {
    const stop = followSystemTheme('system');
    osChange(true);
    expect(attrs.get('data-theme')).toBe('dark');
    osChange(false);
    expect(attrs.get('data-theme')).toBe('light');
    stop();
    expect(listeners.size).toBe(0);
    followSystemTheme('light');
    expect(listeners.size).toBe(0);
  });

  it('the pre-paint script agrees with the app for every stored state', () => {
    const states: [string, string][][] = [
      [],
      [['netra-appearance', 'light']],
      [['netra-appearance', 'dark']],
      [['netra-appearance', 'system']],
      [['netra-appearance', 'sepia']],
      [['netra-theme', 'dark']],
      [['netra-theme', 'light']],
      [['netra-theme', 'dark'], ['netra-appearance', 'light']],
    ];
    for (const dark of [false, true]) {
      for (const state of states) {
        systemDark = dark;
        store.clear();
        attrs.clear();
        state.forEach(([k, v]) => store.set(k, v));
        runInitScript();
        expect(attrs.get('data-theme'), `${dark} ${JSON.stringify(state)}`).toBe(resolveTheme(readStoredPreference()));
      }
    }
  });
});
