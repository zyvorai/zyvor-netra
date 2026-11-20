import { describe, expect, it } from 'vitest';
import { pages } from '../lib/investigation';

describe('features route wiring', () => {
  it('registers features in investigation pages', () => {
    expect(pages).toContain('features');
  });
});
