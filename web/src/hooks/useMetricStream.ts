// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

import { useEffect, useRef, useState } from 'react';
import { api } from '../api';
import { streamMaxWindow, streamSocketURL, type MetricResult, type StreamQuery } from '../lib/metrics';

export function dataURL(q: StreamQuery): string {
  const p = new URLSearchParams({ context: q.context, after: String(-q.window), points: String(q.points) });
  if (q.nodes?.length) p.set('nodes', q.nodes.join(','));
  if (q.charts?.length) p.set('charts', q.charts.join(','));
  if (q.groupBy) p.set('group_by', q.groupBy);
  if (q.group) p.set('group', q.group);
  if (q.aggregate) p.set('aggregate', q.aggregate);
  if (q.labels) p.set('labels', Object.entries(q.labels).map(([k, v]) => `${k}:${v}`).join(','));
  return `/api/v1/metrics/data?${p.toString()}`;
}

/**
 * Live results for a set of queries. Windows up to an hour stream once per
 * second over one WebSocket; longer windows, or a refused socket, poll.
 */
export function useMetricStream(queries: StreamQuery[]): { results: Record<string, MetricResult>; live: boolean; error: string } {
  const [results, setResults] = useState<Record<string, MetricResult>>({});
  const [live, setLive] = useState(false);
  const [error, setError] = useState('');
  const key = JSON.stringify(queries);
  const ws = useRef<WebSocket | null>(null);
  const failed = useRef(false);

  useEffect(() => {
    setResults({});
    const streamable = queries.filter((q) => q.window <= streamMaxWindow);
    const polled = queries.filter((q) => q.window > streamMaxWindow);
    let cancelled = false;
    const timers: ReturnType<typeof setInterval>[] = [];

    if (streamable.length && (failed.current || typeof WebSocket === 'undefined')) {
      poll(streamable, 2000);
    } else if (streamable.length) {
      const sock = new WebSocket(streamSocketURL(window.location));
      ws.current = sock;
      sock.onopen = () => {
        setLive(true);
        sock.send(JSON.stringify({ subscribe: streamable.slice(0, 50) }));
      };
      sock.onmessage = (ev) => {
        try {
          const msg = JSON.parse(ev.data as string);
          if (msg.error) setError(String(msg.error));
          if (msg.results) setResults((r) => ({ ...r, ...msg.results }));
        } catch {
          /* ignore malformed frames */
        }
      };
      sock.onerror = () => {
        failed.current = true;
      };
      sock.onclose = () => {
        setLive(false);
        if (cancelled) return;
        failed.current = true;
        poll(streamable, 2000);
      };
    }

    function poll(qs: StreamQuery[], every: number) {
      if (!qs.length) return;
      const run = () =>
        Promise.all(
          qs.map((q) =>
            api<MetricResult>(dataURL(q))
              .then((r) => [q.id, r] as const)
              .catch((e) => {
                setError(String(e.message || e));
                return null;
              })
          )
        ).then((rs) => {
          if (cancelled) return;
          const upd: Record<string, MetricResult> = {};
          for (const r of rs) if (r) upd[r[0]] = r[1];
          setResults((cur) => ({ ...cur, ...upd }));
        });
      run();
      timers.push(setInterval(run, every));
    }

    poll(polled, polled.some((q) => q.window > 86400) ? 60000 : 10000);

    return () => {
      cancelled = true;
      timers.forEach(clearInterval);
      if (ws.current) {
        ws.current.onclose = null;
        ws.current.close();
        ws.current = null;
      }
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [key]);

  return { results, live, error };
}
