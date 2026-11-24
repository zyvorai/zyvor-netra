// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

// Types and helpers for GET /api/v1/incident/bundle (internal/incidentbundle).
export const bundleSections = ['nodes', 'metrics', 'flows', 'network_changes', 'metadata', 'ebpf', 'audit', 'insights', 'timeline'] as const;
export type BundleSection = (typeof bundleSections)[number];

export type BundleTrunc = { list: string; total: number; kept: number };
export type BundleDoc = {
  schema?: string;
  generatedAt?: string;
  window?: { start?: string; end?: string; minutes?: number };
  identity?: { version?: string; scope?: string; node?: string; mode?: string; nodes?: number; staleNodes?: number };
  redaction?: {
    approach?: string;
    maskIps?: string;
    excludedSections?: string[];
    neverIncluded?: { section: string; fields: string[]; reason: string }[];
    applied?: { rule: string; count: number }[];
  };
  bounds?: { bytes?: number; maxTotalBytes?: number };
  sections?: Record<string, { available?: boolean; excluded?: boolean; note?: string; truncated?: BundleTrunc[]; [k: string]: unknown }>;
  integrity?: { head?: string; chain?: { section: string; sha256: string; chain: string; bytes: number }[] };
  caveats?: string[];
};

// bundleQuery builds the request query; minutes is clamped to 1..1440.
export function bundleQuery(minutes: number, node: string, exclude: string[], mask: string): string {
  const q = new URLSearchParams();
  const m = Math.min(1440, Math.max(1, Math.floor(Number.isFinite(minutes) ? minutes : 15)));
  q.set('minutes', String(m));
  if (node.trim()) q.set('node', node.trim());
  const ex = exclude.filter((e) => (bundleSections as readonly string[]).includes(e));
  if (ex.length) q.set('exclude', ex.join(','));
  if (mask === 'ips' || mask === 'prefix') q.set('mask_ips', mask);
  return q.toString();
}

// rowCount counts the rows in a section's lists (not its truncation notes).
export function rowCount(section: Record<string, unknown> | undefined): number {
  if (!section) return 0;
  let n = 0;
  for (const [k, v] of Object.entries(section)) if (k !== 'truncated' && Array.isArray(v)) n += v.length;
  return n;
}

export function truncatedLists(doc: BundleDoc | undefined): { section: string; list: string; total: number; kept: number }[] {
  const out: { section: string; list: string; total: number; kept: number }[] = [];
  for (const name of bundleSections) for (const t of doc?.sections?.[name]?.truncated || []) out.push({ section: name, ...t });
  return out;
}

export function headline(doc: BundleDoc | undefined): string {
  if (!doc?.window) return '';
  const t = truncatedLists(doc).length;
  const kb = Math.round((doc.bounds?.bytes || 0) / 1024);
  return `${doc.window.minutes} min, ${doc.identity?.nodes ?? 0} node${doc.identity?.nodes === 1 ? '' : 's'}, ${kb} KiB, ${t} truncated list${t === 1 ? '' : 's'}`;
}

export function bundleFileName(doc: BundleDoc | undefined): string {
  const stamp = (doc?.generatedAt || '').replace(/[^0-9TZ]/g, '').slice(0, 16) || 'bundle';
  return `netra-incident-${stamp}.json`;
}

// verifySummary renders the POST /api/v1/incident/verify answer in one line.
export function verifySummary(res: { verify?: { ok?: boolean; problems?: string[] | null; sections?: number }; seal?: { ok?: boolean; error?: string } } | undefined): string {
  const v = res?.verify;
  if (!v) return 'no verification result';
  const parts = [v.ok ? `bundle verifies (${v.sections ?? 0} sections, hash chain intact)` : `bundle does NOT verify: ${(v.problems || [])[0] || 'unknown problem'}`];
  if (res?.seal) parts.push(res.seal.ok ? 'seal matches' : `seal check failed: ${res.seal.error || 'mismatch'}`);
  return parts.join('; ');
}
