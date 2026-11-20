// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

import { useEffect, useRef, useState } from 'react';

/**
 * History of a figure across a page's own polls: one sample per change of
 * `tick` (pass the fetched object), so sparklines need no extra API call.
 */
export function useSeries(value: number | undefined, tick: unknown, max = 30): number[] {
  const [series, setSeries] = useState<number[]>([]);
  useEffect(() => {
    if (tick === undefined || value === undefined || !Number.isFinite(value)) return;
    setSeries((s) => [...s, value].slice(-max));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [tick]);
  return series;
}

/** Per-second rate of a cumulative counter between successive `tick`s; resets count as zero. */
export function useRate(counter: number | undefined, tick: unknown): number | undefined {
  const prev = useRef<{ at: number; v: number } | undefined>(undefined);
  const [rate, setRate] = useState<number | undefined>(undefined);
  useEffect(() => {
    if (tick === undefined || counter === undefined || !Number.isFinite(counter)) return;
    const now = Date.now();
    const p = prev.current;
    if (p && now > p.at) setRate(Math.max(0, counter - p.v) / ((now - p.at) / 1000));
    prev.current = { at: now, v: counter };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [tick]);
  return rate;
}
