// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

// Types and helpers for the network-risk page: GET /api/v1/security/floods,
// /api/v1/capacity/forecast and /api/v1/insights/tls-posture. Display only:
// nothing here applies a deny or changes a setting.

export type NodeFlood = {
  node: string;
  vector: string;
  signal: string;
  currentPerSecond: number;
  baselinePerSecond: number;
  ratio?: number;
  severity: string;
  message: string;
};

export type FloodSuggestion = {
  kind: string;
  value: string;
  direction: string;
  protocol?: string;
  previewRequest: Record<string, unknown>;
  steps: string[];
};

export type SourceFlood = {
  node: string;
  class: string;
  address: string;
  perSecond: number;
  shareOfClass: number;
  severity: string;
  message: string;
  suggestion?: FloodSuggestion;
  noSuggestion?: string;
  lockout?: { risk: string; warnings?: { protected: string; reason: string }[] };
};

export type FloodResult = {
  nodeFindings?: NodeFlood[];
  sourceFindings?: SourceFlood[];
  sourcesWarming?: boolean;
  signalsEvaluated?: number;
  gaps?: string[];
  caveats?: string[];
};

export type CapacityForecast = {
  node: string;
  resource: string;
  current: number;
  limit: number;
  slopePerHour: number;
  secondsToExhaustion?: number;
  severity: string;
  confidence?: string;
  note?: string;
};

export type CapacityResult = { forecasts?: CapacityForecast[]; gaps?: string[]; caveats?: string[] };

export type TlsPostureResult = {
  summary?: { hellos: number; versions: Record<string, number>; tls13Percent: number; legacyMaxHellos: number; ech: number; quic: number; unparsed: number; workloadsSeen: number };
  findings?: { severity: string; kind: string; workload?: string; namespace?: string; sni?: string; hellos: number; message: string }[];
  caveats?: string[];
};

export const severityTone = (s: string | undefined): string => (s === 'critical' || s === 'high' ? 'critical' : s === 'warning' ? 'warning' : 'info');

// humanEta turns seconds into "42m", "3h 10m" or "2d 4h". Non-finite or
// negative input is "unknown"; zero is "now".
export function humanEta(sec: number | undefined): string {
  if (sec === undefined || !Number.isFinite(sec) || sec < 0) return 'unknown';
  if (sec < 60) return sec === 0 ? 'now' : '<1m';
  const m = Math.floor(sec / 60);
  if (m < 60) return `${m}m`;
  const h = Math.floor(m / 60);
  if (h < 48) return `${h}h ${m % 60}m`;
  return `${Math.floor(h / 24)}d ${h % 24}h`;
}

// floodHeadline summarises both finding lists, with the suggestion count.
export function floodHeadline(r: FloodResult | undefined): string {
  if (!r) return '';
  const n = r.nodeFindings?.length || 0;
  const s = r.sourceFindings?.length || 0;
  const sg = (r.sourceFindings || []).filter((x) => x.suggestion).length;
  if (n === 0 && s === 0) return r.sourcesWarming ? 'no flood findings (source rates warming)' : 'no flood findings';
  return `${n} node vector${n === 1 ? '' : 's'}, ${s} source${s === 1 ? '' : 's'}, ${sg} suggested deny${sg === 1 ? '' : 's'} (review only)`;
}

// worstCapacity returns the most urgent forecast or undefined.
export function worstCapacity(r: CapacityResult | undefined): CapacityForecast | undefined {
  const rank = (s: string) => (s === 'critical' ? 3 : s === 'warning' ? 2 : s === 'info' ? 1 : 0);
  let worst: CapacityForecast | undefined;
  for (const f of r?.forecasts || []) {
    if (!worst || rank(f.severity) > rank(worst.severity)) worst = f;
  }
  return worst && worst.severity !== 'ok' ? worst : undefined;
}

export type BeaconCandidate = {
  namespace?: string;
  workload: string;
  pod?: string;
  node?: string;
  peer: string;
  peerClass: string;
  port: number;
  protocol?: string;
  name?: string;
  comm?: string;
  events: number;
  periodSeconds: number;
  jitterSeconds: number;
  score: number;
  medianBytes: number;
  hint?: string;
};

export type BeaconResult = {
  ready?: boolean;
  notReadyReason?: string;
  series?: number;
  candidates?: BeaconCandidate[];
  total?: number;
  truncated?: boolean;
  listTruncated?: boolean;
  limitations?: string[];
};

// humanPeriod keeps seconds visible, unlike humanEta: "45s", "5m", "1h 30m".
export function humanPeriod(sec: number | undefined): string {
  if (sec === undefined || !Number.isFinite(sec) || sec < 0) return 'unknown';
  const s = Math.round(sec);
  if (s < 60) return `${s}s`;
  if (s < 3600) return s % 60 ? `${Math.floor(s / 60)}m ${s % 60}s` : `${s / 60}m`;
  const m = Math.round(s / 60);
  return m % 60 ? `${Math.floor(m / 60)}h ${m % 60}m` : `${m / 60}h`;
}

export function beaconHeadline(r: BeaconResult | undefined): string {
  if (!r) return '';
  if (r.ready === false) return `not ready: ${r.notReadyReason || 'not enough history'}`;
  const n = r.total || 0;
  if (n === 0) return 'no periodic egress found in the window';
  return `${n} periodic destination${n === 1 ? '' : 's'} to identify`;
}

export function beaconLabel(c: BeaconCandidate): string {
  const who = `${c.namespace ? c.namespace + '/' : ''}${c.pod || c.workload}`;
  const peer = c.name ? `${c.name} (${c.peer})` : c.peer;
  return `${who} -> ${peer}:${c.port}${c.protocol ? '/' + c.protocol.toLowerCase() : ''}`;
}

// versionShare formats a version histogram as "1.3 90%, 1.2 10%", largest first.
export function versionShare(versions: Record<string, number> | undefined): string {
  const entries = Object.entries(versions || {}).filter(([, n]) => n > 0);
  const total = entries.reduce((a, [, n]) => a + n, 0);
  if (total === 0) return 'none sampled';
  return entries
    .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))
    .map(([v, n]) => `${v} ${Math.round((n / total) * 100)}%`)
    .join(', ');
}
