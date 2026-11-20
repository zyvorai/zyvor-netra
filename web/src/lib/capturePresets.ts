// Named capture filter presets, persisted per-browser via localStorage —
// there is no server-side per-user preferences store in this app, and a
// saved filter is a pure convenience, not state that needs to survive a
// browser switch or be shared between operators.
export type CapturePreset = { name: string; backend?: string; protocol?: string; host?: string; port?: string; duration?: string };

const STORAGE_KEY = 'netra-capture-presets';

export function loadPresets(): CapturePreset[] {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    const parsed = raw ? JSON.parse(raw) : [];
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}

export function savePresets(presets: CapturePreset[]): void {
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(presets));
  } catch {
    // Private browsing, storage quota, or a disabled store — a preset
    // that fails to save is a lost convenience, never a broken page.
  }
}

export function upsertPreset(presets: CapturePreset[], preset: CapturePreset): CapturePreset[] {
  return [...presets.filter((p) => p.name !== preset.name), preset].sort((a, b) => a.name.localeCompare(b.name));
}

export function removePreset(presets: CapturePreset[], name: string): CapturePreset[] {
  return presets.filter((p) => p.name !== name);
}
