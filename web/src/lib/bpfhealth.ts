// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
export type NamedCount = { name: string; count: number };

// Keep classification and scope boundaries aligned with cmd/netractl/bpfhealth.go.
export function bpfMapsMissingFinding(missingMaps?: string[]) {
  if (!missingMaps || missingMaps.length === 0) return null;
  const kind = 'bpf-maps-missing';
  const evidence = `missing-maps=${JSON.stringify(missingMaps.join(','))}`;
  const nextCheck = 'Rebuild and roll the agent image so allow/rate/icmp maps exist. Until then those controls fail open.';
  return { kind, evidence, nextCheck };
}

export function rateDropFinding(d: NamedCount) {
  if (!(d.count > 0)) return null;
  const kind = 'rate-drop';
  const evidence = `destination=${JSON.stringify(d.name)} dropped=${d.count}`;
  const nextCheck = "Check whether this destination's PPS ceiling is set too low for legitimate traffic; rate-drop counters are cumulative since the map was created and do not identify which flows were dropped or when.";
  return { kind, evidence, nextCheck };
}
