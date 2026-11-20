// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

export function compact(n: number): string {
  if (!Number.isFinite(n)) return '—';
  const abs = Math.abs(n);
  if (abs >= 1e9) return (n / 1e9).toFixed(1) + 'B';
  if (abs >= 1e6) return (n / 1e6).toFixed(1) + 'M';
  if (abs >= 1e4) return (n / 1e3).toFixed(1) + 'K';
  if (abs >= 100) return Math.round(n).toLocaleString();
  return n.toFixed(abs < 10 && n !== 0 && !Number.isInteger(n) ? 1 : 0);
}

export function bytes(n: number): string {
  if (!Number.isFinite(n)) return '—';
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  let i = 0;
  while (n >= 1000 && i < units.length - 1) {
    n /= 1000;
    i++;
  }
  return `${n >= 100 || i === 0 ? Math.round(n) : n.toFixed(1)} ${units[i]}`;
}

export function bytesRate(n: number): string {
  return Number.isFinite(n) ? bytes(n) + '/s' : '—';
}

export function msFromUs(us: number): string {
  if (!Number.isFinite(us)) return '—';
  const ms = us / 1000;
  return `${ms >= 100 ? Math.round(ms) : ms.toFixed(1)} ms`;
}

export function pct(n: number, d: number): string {
  return d ? `${((n * 100) / d).toFixed(1)}%` : '0%';
}
