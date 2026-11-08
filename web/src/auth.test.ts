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

import { bearerCandidates, checkCredentials, logout } from './auth';

describe('auth', () => {
  beforeEach(() => {
    store.clear();
  });

  afterEach(() => {
    store.clear();
  });

  it('uses the password as the NETRA_API_KEY bearer', () => {
    expect(checkCredentials('admin', 'deadbeef')).toBe('deadbeef');
    expect(bearerCandidates('admin', 'deadbeef')).toEqual(['deadbeef']);
  });

  it('has no built-in credential: no password maps to a different token', () => {
    for (const pw of ['Admin@321', 'admin', 'password']) {
      expect(bearerCandidates('admin', pw)).toEqual([pw]);
    }
  });

  it('rejects a wrong username', () => {
    expect(checkCredentials('nobody', 'deadbeef')).toBeNull();
    expect(bearerCandidates('nobody', 'deadbeef')).toEqual([]);
  });

  it('rejects empty password', () => {
    expect(bearerCandidates('admin', '')).toEqual([]);
  });

  it('logout clears the stored token', () => {
    store.set('netra-token', 'deadbeef');
    logout();
    expect(store.get('netra-token')).toBeUndefined();
  });
});
