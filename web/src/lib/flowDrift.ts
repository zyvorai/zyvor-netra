// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

// Types and helpers for GET /api/v1/insights/dependency-drift and /volume-shift (internal/flowdrift).
export type DriftEdge = {
  namespace?: string;
  workload: string;
  direction?: string;
  peer: string;
  peerClass: string;
  port: number;
  protocol?: string;
  appProtocol?: string;
  name?: string;
  bytes: number;
  observations: number;
  firstSeen: string;
  lastSeen: string;
  attention?: boolean;
};

export type DriftReport = {
  ready?: boolean;
  notReadyReason?: string;
  baselineSpanSeconds?: number;
  persistentEdges?: number;
  newEdges?: DriftEdge[];
  newTotal?: number;
  newPublicEgress?: number;
  vanishedEdges?: DriftEdge[];
  vanishedTotal?: number;
  truncated?: boolean;
  listsTruncated?: boolean;
  limitations?: string[];
};

export type Shift = {
  namespace?: string;
  workload: string;
  direction: string;
  kind: 'surge' | 'drop';
  recentBytes: number;
  baselineBytes: number;
  recentBytesPerHour: number;
  baselineBytesPerHour: number;
  ratio: number;
};

export type ShiftReport = {
  ready?: boolean;
  notReadyReason?: string;
  factor?: number;
  shifts?: Shift[];
  total?: number;
  truncated?: boolean;
  limitations?: string[];
};

export function humanBytes(n: number | undefined): string {
  if (n === undefined || !Number.isFinite(n) || n < 0) return 'unknown';
  const units = ['B', 'KiB', 'MiB', 'GiB', 'TiB'];
  let v = n;
  let i = 0;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i++;
  }
  return `${i === 0 ? v : v.toFixed(v >= 100 ? 0 : 1)} ${units[i]}`;
}

export function humanSpan(seconds: number | undefined): string {
  if (seconds === undefined || !Number.isFinite(seconds) || seconds < 0) return 'unknown';
  if (seconds < 3600) return `${Math.round(seconds / 60)}m`;
  if (seconds < 172800) return `${Math.round(seconds / 3600)}h`;
  return `${Math.round(seconds / 86400)}d`;
}

export function driftHeadline(r: DriftReport | undefined): string {
  if (!r) return '';
  if (r.ready === false) return `not ready: ${r.notReadyReason || 'not enough history'}`;
  const n = r.newTotal || 0;
  const pub = r.newPublicEgress || 0;
  const g = r.vanishedTotal || 0;
  if (!n && !g) return `no new or vanished dependencies (baseline ${humanSpan(r.baselineSpanSeconds)})`;
  return `${n} new dependenc${n === 1 ? 'y' : 'ies'} (${pub} public egress), ${g} gone quiet, baseline ${humanSpan(r.baselineSpanSeconds)}`;
}

export function edgeLabel(e: DriftEdge): string {
  const peer = e.name ? `${e.name} (${e.peer})` : e.peer;
  const arrow = e.direction === 'ingress' ? '<-' : '->';
  return `${e.namespace ? e.namespace + '/' : ''}${e.workload} ${arrow} ${peer}:${e.port}${e.protocol ? '/' + e.protocol.toLowerCase() : ''}`;
}

export function shiftHeadline(r: ShiftReport | undefined): string {
  if (!r) return '';
  if (r.ready === false) return `not ready: ${r.notReadyReason || 'not enough history'}`;
  const s = (r.shifts || []).filter((x) => x.kind === 'surge').length;
  const d = (r.shifts || []).filter((x) => x.kind === 'drop').length;
  if (!s && !d) return `no workload moved by ${r.factor || 3}x or more`;
  return `${s} surge${s === 1 ? '' : 's'}, ${d} drop${d === 1 ? '' : 's'} at ${r.factor || 3}x or more`;
}

export function driftQuery(recent: string, baseline: string, publicOnly: boolean): string {
  const q = new URLSearchParams();
  if (/^\d+[mh]$/.test(recent.trim())) q.set('recent', recent.trim());
  if (/^\d+h$/.test(baseline.trim())) q.set('baseline', baseline.trim());
  if (publicOnly) q.set('public_only', 'true');
  const s = q.toString();
  return s ? `?${s}` : '';
}
