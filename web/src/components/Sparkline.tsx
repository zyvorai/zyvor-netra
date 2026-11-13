// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

import { useId } from 'react';

// A small inline-SVG trend line, no npm dependency — reagraph (the only
// chart lib in this repo) is a force-directed graph library, the wrong
// tool for a fixed sequence of points. Kept deliberately minimal: last N
// values, no axes/labels/tooltips.
export default function Sparkline({
  values,
  width = 160,
  height = 32,
  fill = false,
}: {
  values: number[];
  width?: number;
  height?: number;
  fill?: boolean;
}) {
  const gid = useId().replace(/:/g, '');
  if (values.length < 2) return null;
  const max = Math.max(...values, 0.0001);
  const pts = values.map((v, i) => `${(i / (values.length - 1)) * width},${height - (v / max) * (height - 2) - 1}`);
  const points = pts.join(' ');
  return (
    <svg width={width} height={height} viewBox={`0 0 ${width} ${height}`} preserveAspectRatio="none" className="sparkline" role="img" aria-label="trend">
      <defs>
        <linearGradient id={`${gid}-stroke`} x1="0" y1="0" x2="1" y2="0">
          <stop offset="0%" stopColor="var(--chart-6)" />
          <stop offset="55%" stopColor="var(--chart-1)" />
          <stop offset="100%" stopColor="var(--chart-5)" />
        </linearGradient>
        <linearGradient id={`${gid}-fill`} x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" stopColor="var(--chart-1)" stopOpacity="0.28" />
          <stop offset="100%" stopColor="var(--chart-1)" stopOpacity="0" />
        </linearGradient>
      </defs>
      {fill && <polygon points={`0,${height} ${points} ${width},${height}`} fill={`url(#${gid}-fill)`} stroke="none" />}
      <polyline
        points={points}
        fill="none"
        stroke={`url(#${gid}-stroke)`}
        strokeWidth="2"
        strokeLinejoin="round"
        strokeLinecap="round"
        vectorEffect="non-scaling-stroke"
      />
    </svg>
  );
}
