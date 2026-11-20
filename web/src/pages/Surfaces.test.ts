import { describe, expect, it } from 'vitest';
import { pages } from '../lib/investigation';

describe('surfaces route wiring', () => {
  it('registers surfaces in investigation pages', () => {
    expect(pages).toContain('surfaces');
  });
});
