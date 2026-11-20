import type { ReactNode } from 'react';
import AskNetra from '../components/AskNetra';
import DatapathHero from '../components/DatapathHero';
import KernelStackStrip, { flattenKernelFindings } from '../components/KernelStackStrip';
import Reveal from '../components/Reveal';
import type { Page } from '../components/Nav';
import { useCountUp } from '../hooks/useCountUp';
import { PulseFigure } from '../components/kit/PagePulse';
import RankedList from '../components/kit/RankedList';
import { ToneDot, type Tone } from '../components/kit/tone';
import { bytesRate, compact } from '../components/kit/format';
import { PULSE_INTERVAL_MS, useOverviewPulse } from '../hooks/useOverviewPulse';
import { ctaLabel, rankOverviewActions } from '../lib/overviewActions';

type Navigate = (page: Page) => void;

function Metric({ value, label }: { value: number | string; label: string }) {
  const numeric = typeof value === 'number' && Number.isFinite(value);
  const animated = useCountUp(numeric ? (value as number) : 0);
  return (
    <div>
      <b>{numeric ? Math.round(animated).toLocaleString() : value}</b>
      <span>{label}</span>
    </div>
  );
}

export { bytesRate, compact };

function StatusPill({ agents, stale, leaseUntil }: { agents: number; stale: number; leaseUntil?: string }) {
  if (leaseUntil) {
    return (
      <span className="overview-status tone-lease" role="status">
        <i aria-hidden="true" /> Enforcing under lease until {new Date(leaseUntil).toLocaleTimeString()}
      </span>
    );
  }
  if (!agents) {
    return (
      <span className="overview-status tone-idle" role="status">
        <i aria-hidden="true" /> Waiting for node agents
      </span>
    );
  }
  const tone = stale > 0 ? 'warn' : 'ok';
  return (
    <span className={`overview-status tone-${tone}`} role="status">
      <i aria-hidden="true" /> Observing · {agents} agent{agents === 1 ? '' : 's'}
      {stale > 0 ? ` · ${stale} stale` : ''}
    </span>
  );
}

function Chapter({
  eyebrow,
  title,
  tone,
  children,
  figures,
  link,
  onOpen,
  flip,
}: {
  eyebrow: string;
  title: string;
  tone: Tone;
  children: ReactNode;
  figures: ReactNode;
  link: string;
  onOpen?: () => void;
  flip?: boolean;
}) {
  return (
    <Reveal>
      <section className={`overview-chapter${flip ? ' overview-chapter--flip' : ''}`}>
        <div className="overview-chapter__copy">
          <p className="apple-eyebrow">
            <ToneDot tone={tone} />
            {eyebrow}
          </p>
          <h2>{title}</h2>
          {children}
          {onOpen && (
            <button type="button" className="overview-link" onClick={onOpen}>
              {link} ›
            </button>
          )}
        </div>
        <div className="metrics overview-chapter__figures">{figures}</div>
      </section>
    </Reveal>
  );
}

function Signals({ items }: { items: any[] }) {
  if (!items.length) return null;
  return (
    <ul className="overview-signals">
      {items.slice(0, 3).map((a: any, i: number) => (
        <li key={(a.kind || '') + (a.subject || '') + i}>
          <span className={`severity-badge ${a.severity || 'info'}`}>{a.severity || 'info'}</span> {a.message || a.kind}
        </li>
      ))}
    </ul>
  );
}

export default function Overview({ onNavigate }: { onNavigate?: Navigate }) {
  const {
    status: data,
    obs,
    health,
    l7,
    insights,
    path,
    drops,
    features: featSummary,
    dnsFindings,
    scanFindings,
    tlsfp,
    incidents,
    metricAlerts,
    metricAnomalies,
    kernelNetwork,
    digest,
    err,
    rates,
    history,
  } = useOverviewPulse();
  const go = (p: Page) => (onNavigate ? () => onNavigate(p) : undefined);

  const fp = data?.fastPath;
  const hs = health?.summary || {};
  const ls = l7?.summary || {};
  const ps = path?.summary || {};
  const ds = drops?.summary || {};
  const ins = insights || {};
  const agents = data?.agents ?? 0;
  const stale = data?.staleAgents ?? 0;
  const healthAnoms = hs.anomalies || [];
  const pathAnoms = ps.anomalies || [];
  const dropAnoms = ds.anomalies || [];
  const score = typeof hs.healthScore === 'number' ? hs.healthScore : undefined;

  const healthTone: Tone = score === undefined ? 'idle' : healthAnoms.length || score < 80 ? 'warn' : 'ok';
  const healthTitle =
    score === undefined
      ? 'Waiting for TCP and DNS samples.'
      : healthAnoms.length
        ? `${healthAnoms.length} health signal${healthAnoms.length === 1 ? '' : 's'} need a look.`
        : `Health ${score}/100. Nothing out of line.`;

  const congested = ps.congestedFlows ?? 0;
  const lossy = (ps.lostOut ?? 0) + (ps.retransOut ?? 0);
  const pathTone: Tone = !path ? 'idle' : congested || pathAnoms.length ? 'warn' : 'ok';
  const pathTitle = congested
    ? `${congested.toLocaleString()} flow${congested === 1 ? '' : 's'} under congestion pressure.`
    : pathAnoms.length
      ? `${pathAnoms.length} path signal${pathAnoms.length === 1 ? '' : 's'} raised.`
      : 'Connects are clean.';

  const kernelDrops = ds.kernelDropEvents ?? 0;
  const dropTone: Tone = !drops ? 'idle' : kernelDrops || dropAnoms.length ? 'warn' : 'ok';
  const dropTitle = kernelDrops ? `${kernelDrops.toLocaleString()} kernel drops recorded.` : 'No packets going missing.';

  const drift = (ins.driftFindings ?? 0) + (ins.rateDriftFindings ?? 0);
  const behaviorTone: Tone = !insights ? 'idle' : drift || ins.highExposure ? 'warn' : 'ok';
  const behaviorTitle = drift
    ? `${drift.toLocaleString()} behavior change${drift === 1 ? '' : 's'} to review.`
    : ins.highExposure
      ? `${ins.highExposure} workload${ins.highExposure === 1 ? '' : 's'} highly exposed.`
      : 'Behavior matches what Netra learned.';

  const tls = ls.tlsHandshakes ?? 0;
  const http = ls.httpRequests ?? 0;
  const l7Tone: Tone = !l7 ? 'idle' : (ls.connectBlocked ?? 0) > 0 ? 'warn' : 'ok';
  const l7Title = tls || http ? `${compact(tls + http)} named connections.` : 'TLS and HTTP, named — no payloads.';

  const dnsList = Array.isArray(dnsFindings?.findings) ? dnsFindings!.findings! : [];
  const scanList = Array.isArray(scanFindings?.findings) ? scanFindings!.findings! : [];
  const dnsCount = dnsList.length;
  const scanCount = scanList.length;
  const ja3Raw = tlsfp?.stats?.uniqueJa3;
  const ja3 =
    typeof ja3Raw === 'number' ? ja3Raw : Array.isArray(tlsfp?.fingerprints) ? tlsfp!.fingerprints!.length : 0;
  const detectTone: Tone =
    dnsFindings == null && scanFindings == null && tlsfp == null ? 'idle' : dnsCount || scanCount ? 'warn' : 'ok';
  const detectTitle =
    dnsCount || scanCount
      ? `${dnsCount + scanCount} detect finding${dnsCount + scanCount === 1 ? '' : 's'} to review.`
      : 'DNS and scan detect quiet; TLS fingerprints sampling.';

  const kernelFindings = flattenKernelFindings(kernelNetwork?.nodes);
  const { items: actionItems, worst } = rankOverviewActions({
    kernelFindings,
    alerts: metricAlerts?.active,
    incidents: incidents?.items,
    healthAnoms,
    pathAnoms,
    dropAnoms,
    dnsFindings: dnsList,
    scanFindings: scanList,
    limit: 8,
  });
  const actionTone: Tone = !worst ? 'ok' : worst.tone;
  const actionEyebrow = actionItems.length ? 'Needs action' : 'All clear';
  const actionTitle = worst
    ? digest?.headline || worst.title
    : digest?.headline || 'Nothing needs you right now.';
  const datapathPressure: Tone =
    actionTone === 'bad' || dropTone === 'warn' || (rates?.blocked ?? 0) > 0 ? (actionTone === 'bad' ? 'bad' : 'warn') : agents ? 'ok' : 'idle';

  const series = (k: 'packets' | 'bytes' | 'dns' | 'blocked') => history.map((h) => h[k]);

  return (
    <div className="overview">
      <header className="hero">
        <p className="eyebrow">STANDALONE eBPF DATAPATH</p>
        <h1>See the network. Diagnose it. Contain it.</h1>
        <p>
          Netra runs its own eBPF datapath for workload flows, TCP health, DNS timing, socket identity, and leased emergency
          controls.
        </p>
        <div className="overview-hero-row">
          <StatusPill agents={agents} stale={stale} leaseUntil={fp?.enforceUntil} />
          {onNavigate && (
            <button type="button" className="overview-link" onClick={go('ebpf')}>
              Open Firewall ›
            </button>
          )}
        </div>
      </header>

      {fp?.enforceUntil && <p className="warning">Enforcement lease expires {new Date(fp.enforceUntil).toLocaleString()}.</p>}
      {stale > 0 && (
        <p className="warning">
          One or more agents are stale. Each node independently fails back to observe mode after its controller timeout.
        </p>
      )}

      <section className="overview-stage" aria-labelledby="overview-stage-title">
        <div className="overview-stage__head">
          <h2 id="overview-stage-title">The datapath, live.</h2>
          <span className="overview-live">
            <i aria-hidden="true" /> refreshes every {PULSE_INTERVAL_MS / 1000}s
          </span>
        </div>
        <DatapathHero
          workloads={obs?.topWorkloads || []}
          hooks={obs?.hooks || {}}
          agents={agents}
          packetsPerSecond={rates?.packets}
          blockedPerSecond={rates?.blocked}
          detectActive={dnsCount + scanCount > 0}
          pressure={datapathPressure}
        />
        <div className="overview-pulse">
          <PulseFigure label="packets / s" value={rates?.packets} format={compact} series={series('packets')} />
          <PulseFigure label="throughput" value={rates?.bytes} format={bytesRate} series={series('bytes')} />
          <PulseFigure label="DNS queries / s" value={rates?.dns} format={compact} series={series('dns')} />
          <PulseFigure
            label="blocked / s"
            value={rates?.blocked}
            format={compact}
            series={series('blocked')}
            tone={(rates?.blocked ?? 0) > 0 ? 'warn' : undefined}
          />
        </div>
        <div className="metrics overview-totals">
          <Metric value={agents} label="node agents" />
          <Metric value={obs?.packets ?? 0} label="packets counted" />
          <Metric value={obs?.blocked ?? 0} label="blocked packets" />
          <Metric value={obs?.dnsQueries ?? 0} label="DNS events" />
          <Metric value={featSummary?.on ?? '—'} label="features on" />
        </div>
      </section>

      <Reveal>
        <section className="overview-action" aria-labelledby="overview-action-title">
          <div className="overview-action__copy">
            <p className="apple-eyebrow">
              <ToneDot tone={actionTone} />
              {actionEyebrow}
            </p>
            <h2 id="overview-action-title">{actionTitle}</h2>
            {actionItems.length === 0 ? (
              <p>Incidents, metric alerts, congestion and detectors are quiet. Keep watching the live datapath above.</p>
            ) : (
              <p>
                Ranked from congestion and raised alerts through incidents, anomalies and detect findings. Read-only —
                open the page to investigate.
              </p>
            )}
            <div className="overview-action__cta">
              {onNavigate && (
                <button type="button" className="primary" onClick={go(worst?.page || 'connections')}>
                  {ctaLabel(worst?.page)}
                </button>
              )}
              {digest?.headline && worst && <p className="overview-action__digest">{digest.headline}</p>}
            </div>
            {actionItems.length > 0 && (
              <ul className="overview-action__list">
                {actionItems.map((a) => (
                  <li key={a.id}>
                    <span className={`severity-badge ${a.severity}`}>{a.severity}</span>
                    <div>
                      <b>{a.title}</b>
                      <small>{a.detail}</small>
                    </div>
                    {onNavigate && (
                      <button type="button" className="overview-link" onClick={go(a.page)}>
                        Open ›
                      </button>
                    )}
                  </li>
                ))}
              </ul>
            )}
          </div>
          <KernelStackStrip nodes={kernelNetwork?.nodes} onOpen={go('congestion')} />
        </section>
      </Reveal>

      <Chapter eyebrow="Network health" title={healthTitle} tone={healthTone} link="Open Network Health" onOpen={go('health')}
        figures={
          <>
            <Metric value={score ?? '—'} label="health score /100" />
            <Metric value={hs.tcpConnections ?? 0} label="TCP connections" />
            <Metric value={hs.estimatedConnectFailures ?? 0} label="est. TCP failures" />
            <Metric value={hs.dnsFailures ?? 0} label="DNS failures" />
          </>
        }
      >
        <p>Sockops and packet hooks time every TCP connect and cleartext DNS answer, straight from the kernel.</p>
        <Signals items={healthAnoms} />
      </Chapter>

      <Chapter eyebrow="L7 metadata" title={l7Title} tone={l7Tone} link="Open L7 Metadata" onOpen={go('l7')} flip
        figures={
          <>
            <Metric value={tls} label="TLS SNI" />
            <Metric value={http} label="HTTP/1 requests" />
            <Metric value={ls.connectAttempts ?? 0} label="socket attempts" />
            <Metric value={ls.connectBlocked ?? 0} label="blocked attempts" />
          </>
        }
      >
        <p>Best-effort SNI and HTTP Host from the datapath. Evidence for review, never a proxy.</p>
      </Chapter>

      <Chapter
        eyebrow="Detect (GA)"
        title={detectTitle}
        tone={detectTone}
        link="Open Detect"
        onOpen={go('detect')}
        figures={
          <>
            <Metric value={dnsFindings == null ? '—' : dnsCount} label="DNS findings" />
            <Metric value={scanFindings == null ? '—' : scanCount} label="scan findings" />
            <Metric value={tlsfp == null ? '—' : ja3} label="unique JA3" />
            <Metric value={featSummary?.on ?? '—'} label="features on" />
          </>
        }
      >
        <p>
          Observe-only DNS and scan detectors run by default. JA3/JA4 fingerprints live under Surfaces and L7 — no decrypt,
          no payloads.
        </p>
        <Signals
          items={[...dnsList, ...scanList].slice(0, 2).map((f: any) => ({
            severity: 'warning',
            kind: f.kind || 'detect',
            message: f.message || [f.namespace, f.pod || f.domain].filter(Boolean).join('/'),
          }))}
        />
        {onNavigate && (
          <button type="button" className="overview-link" onClick={go('security-review')} style={{ marginTop: 8 }}>
            Correlate on Security Review ›
          </button>
        )}
      </Chapter>

      <Chapter eyebrow="Path diagnostics" title={pathTitle} tone={pathTone} link="Open Path Diagnostics" onOpen={go('path')}
        figures={
          <>
            <Metric value={ps.connectionsMeasured ?? 0} label="connects timed" />
            <Metric value={congested} label="cwnd-pressure flows" />
            <Metric value={lossy} label="lost + retrans out" />
            <Metric value={pathAnoms.length} label="path signals" />
          </>
        }
      >
        <p>Measured TCP establishment and congestion-window pressure, observe-only.</p>
        <Signals items={pathAnoms} />
      </Chapter>

      <Chapter eyebrow="Drop diagnostics" title={dropTitle} tone={dropTone} link="Open Drop Diagnostics" onOpen={go('drops')} flip
        figures={
          <>
            <Metric value={kernelDrops} label="kernel drop events" />
            <Metric value={ds.softnetDropped ?? 0} label="softnet dropped" />
            <Metric value={(ds.rxDropped ?? 0) + (ds.txDropped ?? 0)} label="iface rx+tx drops" />
            <Metric value={dropAnoms.length} label="drop signals" />
          </>
        }
      >
        <p>Kernel skb reasons, softnet pressure and interface counters, per node.</p>
        <Signals items={dropAnoms} />
      </Chapter>

      <Chapter eyebrow="Behavior insights" title={behaviorTitle} tone={behaviorTone} link="Open Insights" onOpen={go('insights')}
        figures={
          <>
            <Metric value={ins.dependencyEdges ?? 0} label="dependency edges" />
            <Metric value={ins.driftFindings ?? 0} label="behavior drift" />
            <Metric value={ins.rateDriftFindings ?? 0} label="rate anomalies" />
            <Metric value={ins.highExposure ?? 0} label="high exposure" />
          </>
        }
      >
        <p>Baselines and drift from exact eBPF counters. Drafts are review-only; Netra never auto-enforces learned policy.</p>
      </Chapter>

      {(() => {
        const activeAlerts = metricAlerts?.active || [];
        const crit = activeAlerts.filter((a: any) => String(a.status || '').toLowerCase().startsWith('crit')).length;
        const warn = activeAlerts.filter((a: any) => {
          const s = String(a.status || '').toLowerCase();
          return s === 'warning' || s === 'warn';
        }).length;
        const rate = metricAnomalies?.anomalyRate ?? metricAnomalies?.nodes?.[0]?.anomalyRate;
        const metricsTone = crit ? 'bad' : warn || (typeof rate === 'number' && rate > 5) ? 'warn' : 'idle';
        const metricsTitle = crit || warn
          ? `${crit} critical · ${warn} warning metric alert${crit + warn === 1 ? '' : 's'} (notify only).`
          : typeof rate === 'number'
            ? `Anomaly rate ${rate.toFixed(1)}% — charts and evidence only.`
            : 'Per-second metrics and anomaly rates. Alerts never apply policy.';
        return (
          <Chapter
            eyebrow="Metrics"
            title={metricsTitle}
            tone={metricsTone}
            link="Open Metrics"
            onOpen={go('metrics')}
            flip
            figures={
              <>
                <Metric value={crit} label="critical alerts" />
                <Metric value={warn} label="warning alerts" />
                <Metric value={typeof rate === 'number' ? `${rate.toFixed(1)}%` : '—'} label="anomaly rate" />
                <Metric value={activeAlerts.length} label="active alerts" />
              </>
            }
          >
            <p>
              Notify-only metric alerts and anomaly rates from the per-second platform. Never wired to mode, deny, or
              auto-mitigate.
            </p>
            {onNavigate && (
              <button type="button" className="overview-link" onClick={go('metric-alerts')} style={{ marginTop: 8 }}>
                Open Metric Alerts ›
              </button>
            )}
          </Chapter>
        );
      })()}

      <Reveal>
        <section className="overview-talking" aria-labelledby="overview-talking-title">
          <div className="overview-stage__head">
            <h2 id="overview-talking-title">Who is talking.</h2>
            {onNavigate && (
              <button type="button" className="overview-link" onClick={go('talkers')}>
                Open Talkers ›
              </button>
            )}
          </div>
          <div className="overview-talking__grid">
            <RankedList title="Destinations" items={obs?.topDestinations || []} empty="No destinations observed yet." limit={6} />
            <RankedList title="DNS names" items={obs?.topDns || []} empty="No cleartext DNS observed yet." limit={6} />
            <RankedList title="Processes" items={obs?.topProcesses || []} empty="No socket processes observed yet." limit={6} />
          </div>
        </section>
      </Reveal>

      <Reveal>
        <section className="overview-platform" aria-label="Datapath capabilities">
          {err && <p className="warning">{err}</p>}
          <ul>
            <li><span>Datapath</span><b>{data?.datapath || '—'}</b></li>
            <li><span>Fast path</span><b>{fp?.mode || '—'}</b></li>
            <li><span>Cilium</span><b>{data?.ciliumRequired ? 'Required' : 'Optional'}</b></li>
            <li><span>Hubble</span><b>{data?.hubble ? 'Enabled' : 'Disabled'}</b></li>
            <li><span>Blocked reasons</span><b>{(obs?.blockReasons || []).length ? obs.blockReasons.slice(0, 2).map((x: any) => `${x.name} · ${x.count}`).join(', ') : 'none'}</b></li>
          </ul>
        </section>
      </Reveal>

      <div className="grid overview-ask">
        <AskNetra />
      </div>

      <p className="overview-closing">
        Cilium is an integration, not a dependency. With Cilium or Hubble installed, Netra can build CiliumNetworkPolicy and
        show Hubble flows — the standalone eBPF engine never depends on them.
      </p>
    </div>
  );
}
