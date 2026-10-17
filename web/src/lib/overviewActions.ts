// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

import type { Page } from './navGroups';
import type { Tone } from '../components/kit/tone';

export type ActionSeverity = 'critical' | 'warning' | 'info';

export type OverviewAction = {
  id: string;
  severity: ActionSeverity;
  title: string;
  detail: string;
  page: Page;
  tone: Tone;
  /** Lower rank = higher priority for ordering and the primary CTA. */
  rank: number;
};

export type AnomalyLike = { kind?: string; severity?: string; subject?: string; message?: string };
export type IncidentCluster = { sourceKey?: string; subject?: string; severity?: string; findings?: { message?: string; kind?: string }[] };
export type MetricAlertLike = { id?: string; rule?: string; node?: string; status?: string; info?: string; chart?: string };
export type DetectFinding = { kind?: string; message?: string; domain?: string; namespace?: string; pod?: string };
export type KernelFindingLike = { severity?: string; signal?: string; explanation?: string; layer?: string; node?: string };

const PAGE_CTA: Partial<Record<Page, string>> = {
  congestion: 'Open Congestion Map',
  'metric-alerts': 'Open Metric Alerts',
  incidents: 'Open Incidents',
  health: 'Open Network Health',
  path: 'Open Path Diagnostics',
  drops: 'Open Drop Diagnostics',
  detect: 'Open Detect',
  surfaces: 'Open Surfaces',
  'deny-preview': 'Open Deny Preview',
  netlink: 'Open Netlink',
  'bpf-attachments': 'Open BPF Attachments',
  metrics: 'Open Metrics',
  'metric-anomalies': 'Open Anomalies',
  connections: 'Investigate connections',
};

export function ctaLabel(page: Page | undefined): string {
  if (!page) return 'Investigate connections';
  return PAGE_CTA[page] || 'Investigate connections';
}

function toneFor(sev: ActionSeverity): Tone {
  if (sev === 'critical') return 'bad';
  if (sev === 'warning') return 'warn';
  return 'idle';
}

function sevOf(raw?: string): ActionSeverity {
  const s = (raw || '').toLowerCase();
  if (s === 'critical' || s === 'crit') return 'critical';
  if (s === 'warning' || s === 'warn') return 'warning';
  return 'info';
}

/** Fixed priority bands (lower = worse / shown first). */
const RANK = {
  congestionCritical: 10,
  alertCritical: 20,
  incident: 30,
  anomaly: 40,
  detect: 50,
  alertWarning: 60,
  congestionWarning: 70,
} as const;

export type RankInputs = {
  kernelFindings?: KernelFindingLike[];
  alerts?: MetricAlertLike[];
  incidents?: IncidentCluster[];
  healthAnoms?: AnomalyLike[];
  pathAnoms?: AnomalyLike[];
  dropAnoms?: AnomalyLike[];
  dnsFindings?: DetectFinding[];
  scanFindings?: DetectFinding[];
  limit?: number;
};

export function rankOverviewActions(input: RankInputs): { items: OverviewAction[]; worst?: OverviewAction } {
  const out: OverviewAction[] = [];
  const limit = input.limit ?? 8;

  for (const f of input.kernelFindings || []) {
    const sev = sevOf(f.severity);
    if (sev === 'info') continue;
    const node = f.node ? ` on ${f.node}` : '';
    out.push({
      id: `cong:${f.layer || ''}:${f.signal || ''}:${f.node || ''}`,
      severity: sev,
      title: f.signal || 'Kernel congestion',
      detail: (f.explanation || f.layer || 'Congestion Map finding') + node,
      page: 'congestion',
      tone: toneFor(sev),
      rank: sev === 'critical' ? RANK.congestionCritical : RANK.congestionWarning,
    });
  }

  for (const a of input.alerts || []) {
    const status = (a.status || '').toLowerCase();
    if (status !== 'critical' && status !== 'warning' && status !== 'warn' && status !== 'crit') continue;
    const sev = status.startsWith('crit') ? 'critical' : 'warning';
    out.push({
      id: `alert:${a.id || a.rule || ''}:${a.node || ''}`,
      severity: sev,
      title: a.rule || 'Metric alert',
      detail: [a.node, a.chart, a.info].filter(Boolean).join(' · ') || 'Raised metric alert',
      page: 'metric-alerts',
      tone: toneFor(sev),
      rank: sev === 'critical' ? RANK.alertCritical : RANK.alertWarning,
    });
  }

  for (const c of input.incidents || []) {
    const sev = sevOf(c.severity);
    if (sev === 'info') continue;
    const first = (c.findings || [])[0];
    out.push({
      id: `inc:${c.sourceKey || c.subject || ''}`,
      severity: sev === 'critical' ? 'critical' : 'warning',
      title: c.subject || 'Incident cluster',
      detail: first?.message || `${(c.findings || []).length} agreeing signals`,
      page: 'incidents',
      tone: toneFor(sev === 'critical' ? 'critical' : 'warning'),
      rank: RANK.incident,
    });
  }

  const pushAnoms = (list: AnomalyLike[] | undefined, page: Page, prefix: string) => {
    for (const a of list || []) {
      const sev = sevOf(a.severity);
      if (sev === 'info' && !a.message) continue;
      out.push({
        id: `${prefix}:${a.kind || ''}:${a.subject || ''}`,
        severity: sev === 'critical' ? 'critical' : 'warning',
        title: a.kind || prefix,
        detail: [a.subject, a.message].filter(Boolean).join(' — ') || 'Anomaly raised',
        page,
        tone: toneFor(sev === 'critical' ? 'critical' : 'warning'),
        rank: RANK.anomaly,
      });
    }
  };
  pushAnoms(input.healthAnoms, 'health', 'health');
  pushAnoms(input.pathAnoms, 'path', 'path');
  pushAnoms(input.dropAnoms, 'drops', 'drop');

  const pushDetect = (list: DetectFinding[] | undefined, kind: string) => {
    for (const f of list || []) {
      const where = [f.namespace, f.pod || f.domain].filter(Boolean).join('/');
      out.push({
        id: `detect:${kind}:${f.kind || ''}:${where}`,
        severity: 'warning',
        title: f.kind || `${kind} finding`,
        detail: f.message || where || 'Observe-only detector finding',
        page: 'detect',
        tone: 'warn',
        rank: RANK.detect,
      });
    }
  };
  pushDetect(input.dnsFindings, 'dns');
  pushDetect(input.scanFindings, 'scan');

  out.sort((a, b) => a.rank - b.rank || a.title.localeCompare(b.title));
  // Dedupe by id keeping first (best) rank.
  const seen = new Set<string>();
  const items: OverviewAction[] = [];
  for (const a of out) {
    if (seen.has(a.id)) continue;
    seen.add(a.id);
    items.push(a);
    if (items.length >= limit) break;
  }
  return { items, worst: items[0] };
}
