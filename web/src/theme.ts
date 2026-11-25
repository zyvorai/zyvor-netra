/** What is painted. */
export type Theme = 'light' | 'dark';
/** What the user chose in the Appearance menu. System is the default. */
export type ThemePreference = Theme | 'system';

const STORAGE_KEY = 'netra-appearance';
/** Written by releases before the Appearance menu; only "dark" was a choice. */
const LEGACY_KEY = 'netra-theme';
const DARK_QUERY = '(prefers-color-scheme: dark)';

export function readStoredPreference(): ThemePreference {
  try {
    const v = localStorage.getItem(STORAGE_KEY);
    if (v === 'light' || v === 'dark' || v === 'system') return v;
    if (!v && localStorage.getItem(LEGACY_KEY) === 'dark') return 'dark';
  } catch {
    /* ignore */
  }
  return 'system';
}

function darkQuery(): MediaQueryList | null {
  return typeof window !== 'undefined' && typeof window.matchMedia === 'function' ? window.matchMedia(DARK_QUERY) : null;
}

export function resolveTheme(preference: ThemePreference): Theme {
  if (preference !== 'system') return preference;
  return darkQuery()?.matches ? 'dark' : 'light';
}

function paint(theme: Theme) {
  document.documentElement.setAttribute('data-theme', theme);
  const meta = document.querySelector('meta[name="theme-color"]');
  if (meta) meta.setAttribute('content', theme === 'dark' ? '#000000' : '#f5f5f7');
}

/** Paint a preference and remember it. */
export function applyPreference(preference: ThemePreference) {
  paint(resolveTheme(preference));
  try {
    localStorage.setItem(STORAGE_KEY, preference);
  } catch {
    /* ignore */
  }
}

/** Repaint when the operating system changes, while the preference is "system". */
export function followSystemTheme(preference: ThemePreference): () => void {
  const query = darkQuery();
  if (preference !== 'system' || !query) return () => {};
  const onChange = () => paint(resolveTheme('system'));
  query.addEventListener('change', onChange);
  return () => query.removeEventListener('change', onChange);
}

/** The theme currently on screen. */
export function paintedTheme(): Theme {
  return document.documentElement.getAttribute('data-theme') === 'dark' ? 'dark' : 'light';
}
