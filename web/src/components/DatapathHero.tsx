// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

import { useEffect, useState } from 'react';
import { compact } from './kit/format';

type NamedCount = { name: string; count: number };

type DatapathHeroProps = {
  workloads: NamedCount[];
  hooks: Record<string, number>;
  agents: number;
  packetsPerSecond?: number;
  blockedPerSecond?: number;
  /** When true, agent→controller link shows a detect badge. */
  detectActive?: boolean;
  /** Health / drop pressure: elevates node/link styling without inventing topology. */
  pressure?: 'idle' | 'ok' | 'warn' | 'bad';
};

type Node = { id: string; label: string; sub?: string; x: number; y: number; w: number; h: number; active: boolean; hot?: boolean };

const HOOKS: { key: string; label: string; sub: string }[] = [
  { key: 'cgroup', label: 'cgroup/skb', sub: 'root cgroup' },
  { key: 'sockops', label: 'sockops', sub: 'TCP health' },
  { key: 'tcx', label: 'TCX', sub: 'selected ifaces' },
  { key: 'xdp', label: 'XDP', sub: 'edge shield' },
];

function useMedia(query: string): boolean {
  const get = () => typeof window !== 'undefined' && typeof window.matchMedia === 'function' && window.matchMedia(query).matches;
  const [match, setMatch] = useState(get);
  useEffect(() => {
    if (typeof window.matchMedia !== 'function') return;
    const m = window.matchMedia(query);
    const on = () => setMatch(m.matches);
    m.addEventListener('change', on);
    return () => m.removeEventListener('change', on);
  }, [query]);
  return match;
}

// "kube-system/hubble-relay-59cc868d4d-jmg7l (ReplicaSet/...)" -> "hubble-relay"
export function workloadLabel(name: string, max = 18): string {
  const pod = name.split(' (')[0].split('/').pop() || name;
  const deployment = /-[a-z0-9]{8,10}-[a-z0-9]{5}$/;
  const short = deployment.test(pod) ? pod.replace(deployment, '') : pod.replace(/-[a-z0-9]{5}$/, '');
  return short.length > max ? short.slice(0, max - 1) + '…' : short;
}

function hookCount(hooks: Record<string, number>, key: string): number {
  return Object.entries(hooks).reduce((n, [k, v]) => (k.toLowerCase().includes(key) ? n + (Number(v) || 0) : n), 0);
}

// Packets per second -> seconds for one dot to cross a link: busier datapath, faster dots.
export function flowDuration(pps?: number): number {
  if (!pps || pps <= 0) return 6;
  return Math.max(1.2, 6 - Math.log10(pps + 1) * 1.1);
}

function link(a: Node, b: Node, vertical: boolean): string {
  if (vertical) {
    const ay = a.y + a.h / 2;
    const by = b.y - b.h / 2;
    const my = (ay + by) / 2;
    return `M${a.x},${ay} C${a.x},${my} ${b.x},${my} ${b.x},${by}`;
  }
  const ax = a.x + a.w / 2;
  const bx = b.x - b.w / 2;
  const mx = (ax + bx) / 2;
  return `M${ax},${a.y} C${mx},${a.y} ${mx},${b.y} ${bx},${b.y}`;
}

function midPoint(a: Node, b: Node): { x: number; y: number } {
  return { x: (a.x + b.x) / 2, y: (a.y + b.y) / 2 };
}

export default function DatapathHero({
  workloads,
  hooks,
  agents,
  packetsPerSecond,
  blockedPerSecond,
  detectActive,
  pressure = 'idle',
}: DatapathHeroProps) {
  const vertical = useMedia('(max-width: 640px)');
  const reduced = useMedia('(prefers-reduced-motion: reduce)');

  const W = vertical ? 360 : 960;
  const H = vertical ? 560 : 320;
  const nw = vertical ? 70 : 168;
  const nh = vertical ? 36 : 50;

  const place = (main: number, i: number, n: number) => {
    const cross = ((i + 1) / (n + 1)) * (vertical ? W : H);
    return vertical ? { x: cross, y: main } : { x: main, y: cross };
  };
  const cols = vertical ? [50, 200, 350, 470] : [110, 380, 650, 870];

  const busy = (packetsPerSecond ?? 0) > 0;
  const blocked = (blockedPerSecond ?? 0) > 0;
  const pressureClass = pressure === 'bad' ? 'dp-hero--bad' : pressure === 'warn' ? 'dp-hero--warn' : '';

  const wl = (workloads.length ? workloads.slice(0, 3) : [{ name: 'workloads', count: 0 }]).map((w, i, arr) => ({
    id: 'w' + i,
    label: workloadLabel(w.name, vertical ? 10 : 18),
    sub: vertical ? undefined : 'pod',
    ...place(cols[0], i, arr.length),
    w: nw,
    h: nh,
    active: w.count > 0,
    hot: w.count > 0 && busy,
  }));
  const hk = HOOKS.map((h, i) => {
    const n = hookCount(hooks, h.key);
    return {
      id: h.key,
      label: h.label,
      sub: vertical ? undefined : h.sub,
      ...place(cols[1], i, HOOKS.length),
      w: nw,
      h: nh,
      active: n > 0,
      hot: n > 0 && busy,
    };
  });
  const agent: Node = {
    id: 'agent',
    label: 'netra-agent',
    sub: vertical ? undefined : `${agents} node${agents === 1 ? '' : 's'}`,
    ...place(cols[2], 0, 1),
    w: nw,
    h: nh,
    active: agents > 0,
    hot: agents > 0 && busy,
  };
  const ctrl: Node = {
    id: 'ctrl',
    label: 'netrad',
    sub: vertical ? undefined : 'controller',
    ...place(cols[3], 0, 1),
    w: nw,
    h: nh,
    active: agents > 0,
    hot: agents > 0 && busy,
  };

  const activeHooks = hk.filter((h) => h.active);
  const hookTargets = activeHooks.length ? activeHooks : hk.slice(0, 1);
  const links: { d: string; live: boolean; key: string; blocked?: boolean }[] = [];
  wl.forEach((w) => hookTargets.forEach((h) => links.push({ key: w.id + h.id, d: link(w, h, vertical), live: w.active && h.active, blocked })));
  hk.forEach((h) => links.push({ key: h.id + 'agent', d: link(h, agent, vertical), live: h.active && agent.active }));
  links.push({ key: 'agentctrl', d: link(agent, ctrl, vertical), live: agent.active });

  const dur = flowDuration(packetsPerSecond);
  const nodes = [...wl, ...hk, agent, ctrl];
  const columnTitles = ['Workloads', 'Kernel hooks', 'Node agent', 'Controller'];
  const rateMid = midPoint(agent, ctrl);
  const ppsLabel = packetsPerSecond !== undefined ? `${compact(packetsPerSecond)} pkt/s` : '';
  const blkLabel = blocked ? `${compact(blockedPerSecond || 0)} blocked/s` : '';

  return (
    <figure
      className={`dp-hero${vertical ? ' dp-hero--vertical' : ''}${pressureClass ? ` ${pressureClass}` : ''}`}
      aria-label="Live Netra datapath: workloads, kernel hooks, node agent and controller"
    >
      <svg viewBox={`0 0 ${W} ${H}`} role="img" aria-hidden="true" preserveAspectRatio="xMidYMid meet">
        {!vertical &&
          cols.map((x, i) => (
            <text key={'t' + i} className="dp-col-title" x={x} y={18} textAnchor="middle">
              {columnTitles[i]}
            </text>
          ))}
        {links.map((l) => (
          <path
            key={l.key}
            d={l.d}
            className={[
              'dp-link',
              l.live ? 'dp-link--live' : '',
              l.blocked ? 'dp-link--blocked' : '',
              pressure === 'bad' && l.live ? 'dp-link--pressure' : '',
            ]
              .filter(Boolean)
              .join(' ')}
          />
        ))}
        {!reduced &&
          links
            .filter((l) => l.live)
            .map((l, i) =>
              [0, 1].map((k) => (
                <circle key={l.key + k} r={vertical ? 3 : 3.5} className="dp-dot">
                  <animateMotion dur={`${dur}s`} begin={`-${((i * 0.37 + (k * dur) / 2) % dur).toFixed(2)}s`} repeatCount="indefinite" path={l.d} />
                </circle>
              )),
            )}
        {!reduced &&
          blocked &&
          wl.slice(0, 2).map((w, i) => (
            <circle key={'b' + i} r={vertical ? 3.5 : 4} className="dp-dot dp-dot--blocked">
              <animateMotion dur="2.4s" begin={`-${i * 1.2}s`} repeatCount="indefinite" path={link(w, hookTargets[0], vertical)} />
              <animate attributeName="opacity" values="1;1;0" keyTimes="0;0.85;1" dur="2.4s" begin={`-${i * 1.2}s`} repeatCount="indefinite" />
            </circle>
          ))}
        {nodes.map((n) => (
          <g key={n.id} className={['dp-node', n.active ? 'dp-node--active' : '', n.hot ? 'dp-node--hot' : ''].filter(Boolean).join(' ')}>
            <rect x={n.x - n.w / 2} y={n.y - n.h / 2} width={n.w} height={n.h} rx={n.h / 2} />
            <text x={n.x} y={n.sub ? n.y - 3 : n.y + 4} textAnchor="middle" className="dp-node-label">
              {n.label}
            </text>
            {n.sub && (
              <text x={n.x} y={n.y + 13} textAnchor="middle" className="dp-node-sub">
                {n.sub}
              </text>
            )}
          </g>
        ))}
        {!vertical && ppsLabel && (
          <text className="dp-rate-label" x={rateMid.x} y={rateMid.y - 10} textAnchor="middle">
            {ppsLabel}
            {blkLabel ? ` · ${blkLabel}` : ''}
          </text>
        )}
        {detectActive && (
          <g className="dp-detect-badge" transform={`translate(${ctrl.x - 36}, ${ctrl.y - nh / 2 - 18})`}>
            <rect width="72" height="18" rx="9" />
            <text x="36" y="13" textAnchor="middle">
              detect
            </text>
          </g>
        )}
      </svg>
    </figure>
  );
}
