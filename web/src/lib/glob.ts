/** True if pattern contains glob wildcards (* or ?). */
export function hasGlob(pattern: string): boolean {
  return /[*?]/.test(pattern);
}

/**
 * Match value against a shell-style glob (* = any run, ? = one char).
 * Empty pattern matches everything. Matching is case-insensitive.
 * Patterns without wildcards use substring includes (for search boxes).
 */
export function matchGlob(pattern: string, value: string, opts?: { substring?: boolean }): boolean {
  const p = pattern.trim();
  if (!p) return true;
  const v = value ?? '';
  const lowerP = p.toLowerCase();
  const lowerV = v.toLowerCase();
  if (!hasGlob(p)) {
    if (opts?.substring) return lowerV.includes(lowerP);
    return lowerV === lowerP;
  }
  let re = '^';
  for (const ch of lowerP) {
    if (ch === '*') re += '.*';
    else if (ch === '?') re += '.';
    else if (/[.+^${}()|[\]\\]/.test(ch)) re += '\\' + ch;
    else re += ch;
  }
  re += '$';
  try {
    return new RegExp(re, 'i').test(v);
  } catch {
    return false;
  }
}
