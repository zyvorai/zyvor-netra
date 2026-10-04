// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

import { useEffect, useMemo, useRef, useState } from 'react';
import { anomalyBand, formatTime, formatValue, latest, palette, valueRange, type MetricResult } from '../lib/metrics';

type Props = {
  result?: MetricResult;
  title?: string;
  subtitle?: string;
  height?: number;
  /** Called with a dragged time range (unix seconds). */
  onHighlight?: (after: number, before: number) => void;
  highlight?: [number, number];
};

const PAD = { l: 52, r: 10, t: 8, b: 20 };
const BAND = 4;

function cssVar(name: string, fallback: string): string {
  if (typeof window === 'undefined') return fallback;
  const v = getComputedStyle(document.documentElement).getPropertyValue(name).trim();
  return v || fallback;
}

export default function MetricChart({ result, title, subtitle, height = 160, onHighlight, highlight }: Props) {
  const wrap = useRef<HTMLDivElement>(null);
  const canvas = useRef<HTMLCanvasElement>(null);
  const [width, setWidth] = useState(600);
  const [hover, setHover] = useState<number | null>(null);
  const [drag, setDrag] = useState<[number, number] | null>(null);
  const [hidden, setHidden] = useState<Record<string, boolean>>({});

  const stacked = result?.chartType === 'stacked' || result?.chartType === 'area';
  const dims = useMemo(() => (result?.dimensions || []).filter((d) => !hidden[d.name]), [result, hidden]);
  const view = useMemo(() => (result ? { ...result, dimensions: dims } : undefined), [result, dims]);

  useEffect(() => {
    const el = wrap.current;
    if (!el || typeof ResizeObserver === 'undefined') return;
    const ro = new ResizeObserver((es) => setWidth(Math.max(200, Math.floor(es[0].contentRect.width))));
    ro.observe(el);
    return () => ro.disconnect();
  }, []);

  const plotW = width - PAD.l - PAD.r;
  const plotH = height - PAD.t - PAD.b - BAND - 2;
  const n = view?.timestamps.length || 0;
  const xOf = (i: number) => PAD.l + (n <= 1 ? 0 : (i / (n - 1)) * plotW);
  const tOfX = (x: number) => {
    if (!view || n === 0) return 0;
    const i = Math.round(((x - PAD.l) / plotW) * (n - 1));
    return view.timestamps[Math.min(n - 1, Math.max(0, i))];
  };

  useEffect(() => {
    const c = canvas.current;
    if (!c || !view) return;
    const dpr = window.devicePixelRatio || 1;
    c.width = width * dpr;
    c.height = height * dpr;
    const g = c.getContext('2d');
    if (!g) return;
    g.setTransform(dpr, 0, 0, dpr, 0, 0);
    g.clearRect(0, 0, width, height);
    const grid = cssVar('--border', 'rgba(127,127,127,0.18)');
    const muted = cssVar('--text-tertiary', '#86868b');
    const [lo, hi] = valueRange(view, stacked);
    const yOf = (v: number) => PAD.t + plotH - ((v - lo) / (hi - lo)) * plotH;

    g.font = '10px ui-sans-serif, system-ui, sans-serif';
    g.fillStyle = muted;
    g.strokeStyle = grid;
    g.lineWidth = 1;
    for (let k = 0; k <= 4; k++) {
      const v = lo + ((hi - lo) * k) / 4;
      const y = Math.round(yOf(v)) + 0.5;
      g.beginPath();
      g.moveTo(PAD.l, y);
      g.lineTo(PAD.l + plotW, y);
      g.stroke();
      g.textAlign = 'right';
      g.textBaseline = 'middle';
      g.fillText(formatValue(v, view.units === '%' ? '%' : ''), PAD.l - 6, y);
    }
    if (n > 1) {
      const span = view.timestamps[n - 1] - view.timestamps[0];
      g.textAlign = 'center';
      g.textBaseline = 'top';
      for (let k = 0; k <= 4; k++) {
        const i = Math.round(((n - 1) * k) / 4);
        g.fillText(formatTime(view.timestamps[i], span), Math.min(Math.max(xOf(i), PAD.l + 24), PAD.l + plotW - 24), height - PAD.b + 4);
      }
    }

    if (highlight || drag) {
      const [a, b] = drag ? [Math.min(drag[0], drag[1]), Math.max(drag[0], drag[1])] : highlight!;
      const t0 = view.timestamps[0];
      const t1 = view.timestamps[n - 1];
      if (t1 > t0) {
        const xa = PAD.l + ((a - t0) / (t1 - t0)) * plotW;
        const xb = PAD.l + ((b - t0) / (t1 - t0)) * plotW;
        g.fillStyle = 'rgba(59,130,246,0.12)';
        g.fillRect(Math.max(PAD.l, xa), PAD.t, Math.min(PAD.l + plotW, xb) - Math.max(PAD.l, xa), plotH);
      }
    }

    const base = new Array(n).fill(0);
    (result?.dimensions || []).forEach((d, di) => {
      if (hidden[d.name]) return;
      const color = palette[di % palette.length];
      g.strokeStyle = color;
      g.lineWidth = 1.5;
      g.beginPath();
      let open = false;
      const top: [number, number][] = [];
      for (let i = 0; i < n; i++) {
        const v = d.values[i];
        if (v == null) {
          open = false;
          continue;
        }
        const y = yOf(stacked ? base[i] + v : v);
        if (open) g.lineTo(xOf(i), y);
        else g.moveTo(xOf(i), y);
        open = true;
        top.push([i, y]);
      }
      g.stroke();
      if (stacked && top.length > 1) {
        g.globalAlpha = 0.18;
        g.fillStyle = color;
        g.beginPath();
        top.forEach(([i, y], k) => (k === 0 ? g.moveTo(xOf(i), y) : g.lineTo(xOf(i), y)));
        for (let k = top.length - 1; k >= 0; k--) g.lineTo(xOf(top[k][0]), yOf(base[top[k][0]]));
        g.closePath();
        g.fill();
        g.globalAlpha = 1;
        for (let i = 0; i < n; i++) if (d.values[i] != null) base[i] += d.values[i]!;
      }
    });

    const band = anomalyBand(view);
    const by = PAD.t + plotH + 2;
    for (let i = 0; i < n; i++) {
      const a = band[i];
      if (a == null || a <= 0) continue;
      g.fillStyle = `rgba(239,68,68,${Math.min(1, 0.25 + a / 100)})`;
      const x0 = i === 0 ? PAD.l : (xOf(i - 1) + xOf(i)) / 2;
      const x1 = i === n - 1 ? PAD.l + plotW : (xOf(i) + xOf(i + 1)) / 2;
      g.fillRect(x0, by, Math.max(1, x1 - x0), BAND);
    }

    if (hover != null && hover < n) {
      g.strokeStyle = muted;
      g.setLineDash([3, 3]);
      g.beginPath();
      g.moveTo(Math.round(xOf(hover)) + 0.5, PAD.t);
      g.lineTo(Math.round(xOf(hover)) + 0.5, PAD.t + plotH);
      g.stroke();
      g.setLineDash([]);
    }
  }, [view, result, hidden, width, height, hover, stacked, plotW, plotH, n, highlight, drag]);

  const onMove = (e: React.MouseEvent) => {
    if (!view || n === 0) return;
    const x = e.clientX - e.currentTarget.getBoundingClientRect().left;
    const i = Math.round(((x - PAD.l) / plotW) * (n - 1));
    setHover(i >= 0 && i < n ? i : null);
    if (drag) setDrag([drag[0], tOfX(x)]);
  };

  const onDown = (e: React.MouseEvent) => {
    if (!onHighlight) return;
    const x = e.clientX - e.currentTarget.getBoundingClientRect().left;
    const t = tOfX(x);
    setDrag([t, t]);
  };

  const onUp = () => {
    if (drag && onHighlight) {
      const [a, b] = [Math.min(...drag), Math.max(...drag)];
      if (b - a >= 2) onHighlight(a, b);
    }
    setDrag(null);
  };

  const all = result?.dimensions || [];
  const tipIdx = hover;
  return (
    <div className="metric-chart" ref={wrap}>
      {(title || subtitle) && (
        <div className="metric-chart__head">
          {title && <span className="metric-chart__title">{title}</span>}
          {subtitle && <span className="metric-chart__sub">{subtitle}</span>}
          {result?.units && <span className="metric-chart__units">{result.units}</span>}
        </div>
      )}
      <div className="metric-chart__plot" style={{ height }}>
        {!result && <div className="metric-chart__empty">Loading…</div>}
        {result && all.length === 0 && <div className="metric-chart__empty">No data in this window.</div>}
        <canvas
          ref={canvas}
          style={{ width, height, cursor: onHighlight ? 'crosshair' : 'default' }}
          onMouseMove={onMove}
          onMouseLeave={() => {
            setHover(null);
            setDrag(null);
          }}
          onMouseDown={onDown}
          onMouseUp={onUp}
          role="img"
          aria-label={`${title || result?.context || 'metric'} chart`}
        />
        {tipIdx != null && view && tipIdx < n && (
          <div className="metric-chart__tip" style={{ left: Math.min(xOf(tipIdx) + 12, width - 190) }}>
            <div className="metric-chart__tip-time">{new Date(view.timestamps[tipIdx] * 1000).toLocaleString()}</div>
            {dims.slice(0, 12).map((d) => (
              <div key={d.name} className="metric-chart__tip-row">
                <i style={{ background: palette[all.indexOf(d) % palette.length] }} />
                <span>{d.name}</span>
                <b>{formatValue(d.values[tipIdx], result?.units)}</b>
                {(d.anomalyRate[tipIdx] || 0) > 0 && <em title="anomaly rate">{Math.round(d.anomalyRate[tipIdx]!)}% anom</em>}
              </div>
            ))}
          </div>
        )}
      </div>
      {all.length > 0 && (
        <div className="metric-chart__legend">
          {all.slice(0, 24).map((d, i) => (
            <button
              type="button"
              key={d.name}
              className={hidden[d.name] ? 'off' : ''}
              onClick={() => setHidden((h) => ({ ...h, [d.name]: !h[d.name] }))}
              title={hidden[d.name] ? 'Show' : 'Hide'}
            >
              <i style={{ background: palette[i % palette.length] }} />
              {d.name}
              <b>{formatValue(latest(d), result?.units === '%' ? '%' : '')}</b>
            </button>
          ))}
          {all.length > 24 && <span className="metric-chart__more">+{all.length - 24} more</span>}
        </div>
      )}
    </div>
  );
}
