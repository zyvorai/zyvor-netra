// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

import { SEVERITY_GLOSS, STAGES, stageSummaries, type StageSeverity } from '../pages/CongestionMap';

type KernelNode = {
  node: string;
  window?: { warming?: boolean };
  findings?: { severity: string; layer: string; signal: string; explanation: string; recommendation?: string; risk?: string }[];
};

type Props = {
  nodes?: KernelNode[];
  onOpen?: () => void;
};

const STRIP_STAGES = STAGES.filter((s) =>
  ['nic-driver', 'napi-softnet', 'ip', 'conntrack', 'tcp-listen', 'socket-receive', 'qdisc', 'tcp-quality'].includes(s.key),
);

export function flattenKernelFindings(nodes: KernelNode[] | undefined): { severity: string; signal: string; explanation: string; layer: string; node: string }[] {
  const out: { severity: string; signal: string; explanation: string; layer: string; node: string }[] = [];
  for (const n of nodes || []) {
    for (const f of n.findings || []) {
      out.push({
        severity: f.severity,
        signal: f.signal,
        explanation: f.explanation,
        layer: f.layer,
        node: n.node,
      });
    }
  }
  return out;
}

export default function KernelStackStrip({ nodes, onOpen }: Props) {
  const list = nodes || [];
  const summaries = stageSummaries(list as any);
  const anyCritical = [...summaries.values()].some((s) => s.severity === 'critical');
  const anyWarn = [...summaries.values()].some((s) => s.severity === 'warning');

  return (
    <div className="ks-strip" aria-label="Kernel network stack pressure">
      <div className="ks-strip__head">
        <p className="apple-eyebrow">Kernel stack</p>
        <span className="ks-strip__gloss">
          {anyCritical ? SEVERITY_GLOSS.critical : anyWarn ? SEVERITY_GLOSS.warning : list.length ? SEVERITY_GLOSS.ok : 'no nodes yet'}
        </span>
        {onOpen && (
          <button type="button" className="overview-link" onClick={onOpen}>
            Open Congestion Map ›
          </button>
        )}
      </div>
      <ol className="ks-strip__stages">
        {STRIP_STAGES.map((stage) => {
          const sev = (summaries.get(stage.key)?.severity || 'warming') as StageSeverity;
          return (
            <li key={stage.key} className={`ks-stage ks-stage--${sev}`}>
              <button type="button" className="ks-stage__btn" onClick={onOpen} disabled={!onOpen} title={stage.title}>
                <span className="ks-stage__dot" aria-hidden="true" />
                <span className="ks-stage__title">{stage.title}</span>
                <span className="ks-stage__gloss">{SEVERITY_GLOSS[sev]}</span>
              </button>
            </li>
          );
        })}
      </ol>
    </div>
  );
}
