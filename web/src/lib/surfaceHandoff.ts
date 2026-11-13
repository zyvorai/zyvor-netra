// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

import type { Page } from './navGroups';
import type { Scope } from './investigation';
import { emptyScope } from './investigation';

/** Map a Surfaces board row to an investigation navigation target. */
export function surfaceRowHandoff(
  boardId: string,
  row: Record<string, unknown>,
): { page: Page; scope: Partial<Scope>; label: string } | null {
  const ns = String(row.namespace || row.ns || '');
  const pod = String(row.pod || row.workload || row.workloadName || '');
  const node = String(row.node || '');
  const host = String(row.host || row.hostname || row.sni || row.destination || row.dest || '');
  const base: Partial<Scope> = {};
  if (ns) base.namespace = ns;
  if (pod) base.pod = pod;
  if (node) base.node = node;

  switch (boardId) {
    case 'shadow':
    case 'destrisk':
    case 'exfil':
    case 'experience':
    case 'ainet':
    case 'appcat':
      return {
        page: 'flow-observe',
        scope: { ...base, query: host || pod || ns },
        label: 'Flow observe',
      };
    case 'dnsintel':
    case 'intel':
    case 'encdns':
      return {
        page: 'security-review',
        scope: { ...base, query: host },
        label: 'Security Review',
      };
    case 'lateral':
    case 'catdeny':
    case 'microseg':
    case 'zt':
    case 'packs':
    case 'identity':
      return {
        page: 'deny-preview',
        scope: { ...base, query: host || pod },
        label: 'Deny Preview',
      };
    case 'tls':
    case 'tls-risk':
    case 'ech':
      return {
        page: 'tls-fingerprints',
        scope: { ...base, query: String(row.ja3 || host || '') },
        label: 'TLS / JA3',
      };
    case 'reasons':
      return { page: 'drop-reasons', scope: base, label: 'Drop reasons' };
    case 'automitigate':
    case 'automitigate-preview':
      return { page: 'detect', scope: base, label: 'Detect' };
    case 'clusters':
    case 'tenants':
      return { page: 'fleet', scope: { query: String(row.tenant || row.name || row.id || '') }, label: 'Fleet' };
    case 'compliance':
      return { page: 'report', scope: base, label: 'Report' };
    case 'prevention':
      return { page: 'handoff', scope: emptyScope, label: 'Handoff' };
    default:
      if (ns || pod) {
        return { page: 'investigate', scope: base, label: 'Investigate' };
      }
      return null;
  }
}
