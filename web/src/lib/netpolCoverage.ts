// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

// Types and helpers for GET /api/v1/insights/netpol-coverage (internal/netpolcoverage).
// Display only: nothing here creates or suggests a policy.

export type DirectionCounts = { open: number; allowAll: number; restricted: number; restrictedButAnyAddress: number };

export type PublicTraffic = { peers: number; bytes: number };

export type CoverageWorkload = {
  namespace: string;
  kind?: string;
  name: string;
  pods: number;
  status: 'uncovered' | 'partial' | 'covered';
  ingress: DirectionCounts;
  egress: DirectionCounts;
  policies?: string[];
  publicEgress: PublicTraffic;
  publicIngress: PublicTraffic;
  attention?: boolean;
  reasons?: string[];
};

export type CoverageReport = {
  summary?: {
    policies: number;
    pods: number;
    hostNetworkPods: number;
    workloads: number;
    uncovered: number;
    partial: number;
    covered: number;
    attention: number;
    ingressUnrestrictedPods: number;
    egressUnrestrictedPods: number;
  };
  namespacesWithoutPolicy?: string[];
  workloads?: CoverageWorkload[];
  total?: number;
  truncated?: boolean;
  listTruncated?: boolean;
  gaps?: string[];
  limitations?: string[];
};

export function coverageHeadline(r: CoverageReport | undefined): string {
  const s = r?.summary;
  if (!s) return '';
  if (s.workloads === 0) return 'no pod-network workloads found';
  const open = s.uncovered + s.partial;
  if (open === 0) return `every one of ${s.workloads} workload${s.workloads === 1 ? ' is' : 's are'} restricted in both directions`;
  return `${open} of ${s.workloads} workload${s.workloads === 1 ? '' : 's'} unrestricted in some direction, ${s.attention} with public traffic`;
}

// directionLabel says what policy does to a workload's pods in one direction.
export function directionLabel(d: DirectionCounts | undefined): string {
  if (!d) return 'unknown';
  const parts: string[] = [];
  if (d.open) parts.push(`${d.open} no policy`);
  if (d.allowAll) parts.push(`${d.allowAll} allow-all`);
  if (d.restricted) {
    parts.push(`${d.restricted} restricted${d.restrictedButAnyAddress ? ` (${d.restrictedButAnyAddress} still any address)` : ''}`);
  }
  return parts.join(', ') || 'no pods';
}

export function coverageQuery(namespace: string, window: string, all: boolean): string {
  const q = new URLSearchParams();
  const ns = namespace.trim();
  // A namespace is a DNS label; anything else is not sent.
  if (/^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$/.test(ns)) q.set('namespace', ns);
  if (/^\d+[mh]$/.test(window.trim())) q.set('window', window.trim());
  if (all) q.set('all', 'true');
  const s = q.toString();
  return s ? `?${s}` : '';
}
