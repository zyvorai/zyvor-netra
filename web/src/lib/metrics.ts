// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

/** One output line of GET /api/v1/metrics/data or a stream push. */
export type ResultDim = {
  name: string;
  labels?: Record<string, string>;
  values: (number | null)[];
  anomalyRate: (number | null)[];
  series: number;
};

export type MetricResult = {
  context: string;
  title?: string;
  units?: string;
  family?: string;
  chartType?: string;
  tier: number;
  interval: number;
  after: number;
  before: number;
  timestamps: number[];
  dimensions: ResultDim[] | null;
  matched: number;
};

export type ChartInfo = { node: string; chart: string; labels?: Record<string, string>; dimensions: string[] };

export type ContextInfo = {
  context: string;
  family?: string;
  title?: string;
  units?: string;
  chartType?: string;
  charts: ChartInfo[];
  firstT: number;
  lastT: number;
};

export type StreamQuery = {
  id: string;
  context: string;
  charts?: string[];
  nodes?: string[];
  labels?: Record<string, string>;
  window: number;
  points: number;
  groupBy?: string;
  group?: string;
  aggregate?: string;
};

/** The order families appear in the sidebar; anything else follows, sorted. */
const familyOrder = ['cpu', 'load', 'ram', 'swap', 'pressure', 'disk', 'net', 'ip', 'tcp', 'udp', 'ipv4', 'ipv6', 'softnet', 'connection tracker', 'drops', 'datapath', 'shield', 'processes', 'apps'];

export function familyOf(c: ContextInfo): string {
  if (c.family) return c.family;
  const dot = c.context.indexOf('.');
  return dot > 0 ? c.context.slice(0, dot) : c.context;
}

/** Top-level section: system, network, workloads, ebpf, apps, other. */
export function sectionOf(context: string): string {
  const head = context.split('.')[0];
  if (head === 'system' || head === 'cpu' || head === 'mem' || head === 'disk') return 'System';
  if (head === 'net' || head === 'ip' || head === 'ipv4' || head === 'ipv6' || head === 'netfilter') return 'Network';
  if (head === 'cgroup' || head === 'app' || head === 'apps') return 'Workloads';
  if (head === 'ebpf') return 'eBPF datapath';
  if (head === 'netra') return 'Netra';
  return 'Applications';
}

export function groupContexts(cs: ContextInfo[]): { section: string; families: { family: string; contexts: ContextInfo[] }[] }[] {
  const sections = new Map<string, Map<string, ContextInfo[]>>();
  for (const c of cs) {
    const s = sectionOf(c.context);
    const f = familyOf(c);
    if (!sections.has(s)) sections.set(s, new Map());
    const fam = sections.get(s)!;
    if (!fam.has(f)) fam.set(f, []);
    fam.get(f)!.push(c);
  }
  const sectionRank = ['System', 'Network', 'Workloads', 'eBPF datapath', 'Applications', 'Netra'];
  const famRank = (f: string) => {
    const i = familyOrder.indexOf(f);
    return i < 0 ? familyOrder.length : i;
  };
  return [...sections.entries()]
    .sort((a, b) => sectionRank.indexOf(a[0]) - sectionRank.indexOf(b[0]))
    .map(([section, fams]) => ({
      section,
      families: [...fams.entries()]
        .sort((a, b) => famRank(a[0]) - famRank(b[0]) || a[0].localeCompare(b[0]))
        .map(([family, contexts]) => ({ family, contexts: contexts.sort((x, y) => x.context.localeCompare(y.context)) })),
    }));
}

/** y-axis range over every non-null value; stacked charts sum per point. */
export function valueRange(r: MetricResult, stacked: boolean): [number, number] {
  const dims = r.dimensions || [];
  let lo = Infinity;
  let hi = -Infinity;
  if (stacked) {
    for (let i = 0; i < r.timestamps.length; i++) {
      let pos = 0;
      let neg = 0;
      for (const d of dims) {
        const v = d.values[i];
        if (v == null) continue;
        if (v >= 0) pos += v;
        else neg += v;
      }
      hi = Math.max(hi, pos);
      lo = Math.min(lo, neg);
    }
  } else {
    for (const d of dims)
      for (const v of d.values) {
        if (v == null) continue;
        lo = Math.min(lo, v);
        hi = Math.max(hi, v);
      }
  }
  if (!isFinite(lo) || !isFinite(hi)) return [0, 1];
  if (r.units === '%' && hi <= 100 && lo >= 0) return [0, Math.max(hi, 1) > 50 ? 100 : niceCeil(hi)];
  lo = Math.min(lo, 0);
  if (hi === lo) hi = lo + 1;
  return [lo, niceCeil(hi)];
}

export function niceCeil(v: number): number {
  if (v <= 0) return v === 0 ? 1 : -niceFloor(-v);
  const p = Math.pow(10, Math.floor(Math.log10(v)));
  for (const m of [1, 1.2, 1.5, 2, 2.5, 3, 4, 5, 6, 8, 10]) if (m * p >= v) return m * p;
  return 10 * p;
}

function niceFloor(v: number): number {
  const p = Math.pow(10, Math.floor(Math.log10(v)));
  return Math.floor(v / p) * p;
}

const si = ['', 'k', 'M', 'G', 'T', 'P'];

export function formatValue(v: number | null | undefined, units = ''): string {
  if (v == null || !isFinite(v)) return '—';
  const a = Math.abs(v);
  if (units === '%') return `${v.toFixed(a < 10 ? 1 : 0)}%`;
  let i = 0;
  let x = v;
  while (Math.abs(x) >= 1000 && i < si.length - 1) {
    x /= 1000;
    i++;
  }
  const digits = Math.abs(x) >= 100 || Number.isInteger(x) ? 0 : Math.abs(x) >= 10 ? 1 : 2;
  return `${x.toFixed(digits)}${si[i]}${units ? ' ' + units : ''}`;
}

export function formatTime(t: number, span: number): string {
  const d = new Date(t * 1000);
  const hh = String(d.getHours()).padStart(2, '0');
  const mm = String(d.getMinutes()).padStart(2, '0');
  const ss = String(d.getSeconds()).padStart(2, '0');
  if (span <= 3600) return `${hh}:${mm}:${ss}`;
  if (span <= 86400) return `${hh}:${mm}`;
  return `${d.getMonth() + 1}/${d.getDate()} ${hh}:${mm}`;
}

/** Latest non-null value of a dimension. */
export function latest(d: ResultDim): number | null {
  for (let i = d.values.length - 1; i >= 0; i--) if (d.values[i] != null) return d.values[i];
  return null;
}

/** Highest anomaly rate across dimensions at each point, 0..100 or null. */
export function anomalyBand(r: MetricResult): (number | null)[] {
  const dims = r.dimensions || [];
  return r.timestamps.map((_, i) => {
    let m: number | null = null;
    for (const d of dims) {
      const a = d.anomalyRate[i];
      if (a != null) m = Math.max(m ?? 0, a);
    }
    return m;
  });
}

export function streamId(context: string, node: string, chart?: string): string {
  return [context, node || '*', chart || '*'].join('|');
}

/** ws(s)://host/api/v1/metrics/stream for the current page origin. */
export function streamSocketURL(loc: { protocol: string; host: string }): string {
  return `${loc.protocol === 'https:' ? 'wss' : 'ws'}://${loc.host}/api/v1/metrics/stream`;
}

export const windows: { label: string; seconds: number }[] = [
  { label: '5m', seconds: 300 },
  { label: '15m', seconds: 900 },
  { label: '1h', seconds: 3600 },
  { label: '6h', seconds: 21600 },
  { label: '24h', seconds: 86400 },
  { label: '7d', seconds: 604800 },
  { label: '30d', seconds: 2592000 },
];

/** Live 1-second streaming is used up to one hour; longer windows poll. */
export const streamMaxWindow = 3600;

export const palette = ['#3b82f6', '#22c55e', '#f59e0b', '#ef4444', '#a855f7', '#06b6d4', '#ec4899', '#84cc16', '#f97316', '#14b8a6', '#6366f1', '#eab308'];
