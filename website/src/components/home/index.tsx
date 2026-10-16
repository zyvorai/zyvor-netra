import {useState} from 'react';
import type {ReactNode} from 'react';
import clsx from 'clsx';
import Link from '@docusaurus/Link';
import useBaseUrl from '@docusaurus/useBaseUrl';
import Reveal from '@site/src/components/Reveal';
import facts from '@site/src/data/facts.generated.json';
import {Section} from '@site/src/components/marketing/Shell';
import s from './Home.module.css';

export const F = facts;

/* ------------------------------------------------------------- shared */

function Code({children}: {children: string}): ReactNode {
  const [done, setDone] = useState(false);
  const copy = () => {
    try {
      void navigator.clipboard.writeText(children).then(() => {
        setDone(true);
        window.setTimeout(() => setDone(false), 1500);
      });
    } catch {
      /* clipboard unavailable: leave the text selectable */
    }
  };
  return (
    <pre className={s.code}>
      {children}
      <button type="button" className={s.copy} onClick={copy} aria-label="Copy to clipboard">
        {done ? 'Copied' : 'Copy'}
      </button>
    </pre>
  );
}

function Tabs<T extends {id: string; label: string}>({
  items,
  value,
  onChange,
  label,
}: {
  items: readonly T[];
  value: string;
  onChange: (id: string) => void;
  label: string;
}): ReactNode {
  return (
    <div className={s.tabs} role="tablist" aria-label={label}>
      {items.map((t) => (
        <button
          key={t.id}
          type="button"
          role="tab"
          aria-selected={t.id === value}
          className={clsx(s.tab, t.id === value && s.tabOn)}
          onClick={() => onChange(t.id)}>
          {t.label}
        </button>
      ))}
    </div>
  );
}

/* ---------------------------------------------------------------- why */

export function Why(): ReactNode {
  const cards: [string, string][] = [
    [
      'Standalone',
      'The node agent owns its own eBPF programs and maps under /sys/fs/bpf/netra. No CNI dependency; Cilium and Hubble add context when they are present.',
    ],
    [
      'Observe first',
      'Drops, TCP paths, DNS, L7 metadata, per-second metrics and anomalies, read from the kernel without touching the data path.',
    ],
    [
      'Leased enforcement',
      'Deny rules preview first, then sit behind a time-limited lease that fails open on expiry, restart or failover.',
    ],
  ];
  return (
    <Section
      id="why"
      eyebrow="Why Netra"
      title="Built for the incident, not the dashboard wall."
      lede="Most network tools couple to one CNI or sit permanently in the data path. Netra is an emergency layer you reach for: it shows what the kernel sees, and lets you contain a problem without betting the cluster on it.">
      <div className={s.why}>
        {cards.map(([t, p], i) => (
          <Reveal key={t} delay={i * 80}>
            <div className={s.whyCard}>
              <h3>{t}</h3>
              <p>{p}</p>
            </div>
          </Reveal>
        ))}
      </div>
    </Section>
  );
}

/* -------------------------------------------------------- stack scene */

export function StackScene(): ReactNode {
  const Box = ({x, y, w, h, t, sub, accent}: {x: number; y: number; w: number; h: number; t: string; sub: string; accent?: boolean}) => (
    <g>
      <rect x={x} y={y} width={w} height={h} rx="14" className={accent ? s.sceneBoxAccent : s.sceneBox} />
      <text x={x + 16} y={y + 28} className={s.sceneTitle}>{t}</text>
      <text x={x + 16} y={y + 50} className={s.sceneSub}>{sub}</text>
    </g>
  );
  const outs: [string, string][] = [
    ['Dashboard', 'web UI on :30870'],
    ['netractl', 'CLI for every API'],
    [`MCP, ${F.mcpTools} tools`, `${F.mcpReadTools} read-only by default`],
    ['Loki, OTLP, SIEM', 'push exporters'],
  ];
  return (
    <Section
      id="how"
      tint
      eyebrow="How it works"
      title="Kernel to controller to you."
      lede="One privileged agent per node loads the programs and reports to a single controller. Everything you see in the dashboard, CLI, MCP or an exporter comes from that one path.">
      <Reveal>
        <div className={s.scene}>
          <svg viewBox="0 0 920 330" role="img" aria-label="Kernel hooks feed the node agent, which reports to the netrad controller, which serves the dashboard, netractl, MCP and exporters">
            <Box x={10} y={120} w={200} h={70} t="Linux kernel" sub="cgroup, sockops, TCX, XDP" />
            <Box x={270} y={120} w={210} h={70} t="Node agent" sub="DaemonSet, owns /sys/fs/bpf/netra" accent />
            <Box x={540} y={120} w={150} h={70} t="netrad" sub="API, leases, store" accent />
            {outs.map(([t, sub], i) => (
              <Box key={t} x={740} y={10 + i * 80} w={170} h={64} t={t} sub={sub} />
            ))}
            <path d="M210 155 H270" className={s.sceneLink} />
            <path d="M480 155 H540" className={s.sceneLink} />
            {outs.map(([t], i) => (
              <path key={t} d={`M690 155 C 715 155, 715 ${42 + i * 80}, 740 ${42 + i * 80}`} className={s.sceneLink} />
            ))}
          </svg>
          <p className={s.sceneNote}>
            Enforcement is a lease. If the controller, agent or HA leader goes away, rules expire back to observe.
          </p>
        </div>
      </Reveal>
    </Section>
  );
}

/* --------------------------------------------------------- walkthrough */

const SHOTS = [
  {id: 'overview', label: 'Overview', src: '/v022/00-overview.png', q: 'What is the cluster doing right now?', body: 'Agents, health, flows and findings on one page, from a live lab deployment.', to: '/docs/getting-started/quickstart', cta: 'Quickstart'},
  {id: 'drops', label: 'Drop diagnostics', src: '/v022/05-drop-diagnostics.png', q: 'Why was this connection dropped?', body: 'Kernel drop attribution: which connections are dropped, why, and by which function.', to: '/docs/diagnose/drop-diagnostics', cta: 'Drop diagnostics'},
  {id: 'path', label: 'Path diagnostics', src: '/v022/04-path-diagnostics.png', q: 'Where along the path does it stall?', body: 'TCP path and congestion diagnostics for a pair of endpoints.', to: '/docs/core-concepts/sensors', cta: 'Sensors'},
  {id: 'l7', label: 'L7 metadata', src: '/v022/06-l7-metadata.png', q: 'Who is talking to what, by name?', body: 'DNS names, TLS server names and HTTP status codes without decrypting payloads.', to: '/docs/diagnose/l7-metadata', cta: 'L7 metadata'},
  {id: 'firewall', label: 'Firewall', src: '/v022/08-ebpf.png', q: 'What is enforced, and until when?', body: 'Unified rules with their leases. Previews first; everything expires back to observe.', to: '/docs/contain/deny-preview', cta: 'Deny preview'},
] as const;

function Shot({src, alt}: {src: string; alt: string}): ReactNode {
  return <img className={s.shot} src={useBaseUrl(src)} alt={alt} loading="lazy" />;
}

export function Walkthrough(): ReactNode {
  const [id, setId] = useState<string>(SHOTS[0].id);
  const cur = SHOTS.find((x) => x.id === id) ?? SHOTS[0];
  return (
    <Section
      id="product"
      eyebrow="The product"
      title="A real dashboard, captured live."
      lede="Every screenshot comes from a running lab deployment, not a mockup.">
      <Reveal>
        <Tabs items={SHOTS} value={id} onChange={setId} label="Dashboard pages" />
        <div className={s.panel}>
          <Shot src={cur.src} alt={`Netra ${cur.label} page`} />
          <div className={s.panelText}>
            <h3>{cur.label}</h3>
            <p className={s.q}>{cur.q}</p>
            <p>{cur.body}</p>
            <Link to={cur.to}>{cur.cta} →</Link>
            <p style={{marginTop: '1rem'}}>
              <Link to="/gallery">See the full tour →</Link>
            </p>
          </div>
        </div>
      </Reveal>
    </Section>
  );
}

/* ------------------------------------------------------------ explorer */

const CAPS = [
  {id: 'diagnose', label: 'Diagnose', q: 'Why was this connection dropped?', body: 'Kernel drop attribution shows which connections the kernel drops, why, and by which function, with the context captured around the drop.', cmd: 'netractl ebpf drops', to: '/docs/diagnose/drop-diagnostics', cta: 'Drop diagnostics'},
  {id: 'capture', label: 'Capture', q: 'What is actually on the wire?', body: 'Start a filtered, time-bounded packet capture on one node and stream it live to the dashboard, netractl or MCP.', cmd: 'netractl capture start node-1 --backend afpacket --protocol tcp --host 10.0.0.5', to: '/docs/diagnose/capture', cta: 'Packet capture'},
  {id: 'contain', label: 'Contain', q: 'Can I stop it without risking an outage?', body: 'Preview a deny rule against live traffic first. Applied rules sit behind a lease that fails open to observe.', cmd: 'netractl ebpf deny-preview cidr 203.0.113.0/24 egress', to: '/docs/contain/deny-preview', cta: 'Deny preview'},
  {id: 'measure', label: 'Measure', q: 'What changed in the last hour?', body: 'Per-second host, network and workload metrics, scored for anomalies and evaluated by alert rules.', cmd: 'netractl metrics anomalies --after -3600', to: '/docs/operate/metrics', cta: 'Metrics platform'},
  {id: 'automate', label: 'Automate', q: 'Can my agent do this?', body: `netra-mcp exposes ${F.mcpTools} tools over stdio. ${F.mcpReadTools} are read-only; the rest need NETRA_MCP_ALLOW_MUTATIONS=true.`, cmd: `docker run -i --rm -e NETRA_URL -e NETRA_API_KEY ${F.mcpImage}`, to: '/docs/integrations/mcp-integration', cta: 'MCP integration'},
] as const;

export function Explorer(): ReactNode {
  const [id, setId] = useState<string>(CAPS[0].id);
  const cur = CAPS.find((x) => x.id === id) ?? CAPS[0];
  return (
    <Section
      id="capabilities"
      tint
      eyebrow="Capabilities"
      title="Pick the question you have."
      lede="Each answer is a command you can run today, backed by a page of docs.">
      <Reveal>
        <Tabs items={CAPS} value={id} onChange={setId} label="Capabilities" />
        <div className={clsx(s.panel, s.panelWide)}>
          <div className={s.panelText}>
            <h3>{cur.q}</h3>
            <p>{cur.body}</p>
            <Link to={cur.to}>{cur.cta} →</Link>
          </div>
          <Code>{cur.cmd}</Code>
        </div>
      </Reveal>
    </Section>
  );
}

/* ----------------------------------------------------------- agents/MCP */

export function Agents(): ReactNode {
  const cfg = `{
  "mcpServers": {
    "netra": {
      "command": "docker",
      "args": ["run", "-i", "--rm",
               "-e", "NETRA_URL", "-e", "NETRA_API_KEY",
               "${F.mcpImage}"],
      "env": { "NETRA_URL": "https://netra.example:30870", "NETRA_API_KEY": "..." }
    }
  }
}`;
  return (
    <Section
      id="agents"
      eyebrow="For AI agents"
      title="Network intelligence your agent can use."
      lede={`Netra is listed in the official MCP Registry as ${F.mcpName}. The server is stdlib-only Go, with no MCP SDK.`}>
      <Reveal>
        <div className={s.numbers}>
          <div><b>{F.mcpTools}</b><span>tools</span></div>
          <div><b>{F.mcpReadTools}</b><span>read-only by default</span></div>
          <div><b>{F.mcpPrompts}</b><span>prompts</span></div>
          <div><b>{F.mcpResources}</b><span>resources</span></div>
        </div>
        <div className={s.agents}>
          <div className={s.panelText}>
            <p>
              Ask for the drop context of a pod, the anomalous metrics of the last hour or a security review, and get structured answers from the live controller.
            </p>
            <div className={s.gate}>
              <b>Mutations are opt-in.</b> {F.mcpMutatingTools} mutating tools stay hidden unless
              {' '}<code>NETRA_MCP_ALLOW_MUTATIONS=true</code>. Policy apply still needs a plan token and risk confirmation, and enforcement stays leased.
            </div>
            <p style={{marginTop: '1rem'}}>
              <Link to="/docs/reference/mcp-tools">Browse the tool catalog →</Link>
              {'  '}
              <Link to="/docs/integrations/mcp-integration">Setup →</Link>
            </p>
          </div>
          <Code>{cfg}</Code>
        </div>
      </Reveal>
    </Section>
  );
}

/* ------------------------------------------------------------ receipts */

export function Receipts(): ReactNode {
  const items: [string, string][] = [
    ['Tested on every push', 'Go build, vet and test, web typecheck and tests, Helm lint and render, a clang BPF compile and PROG_TEST_RUN, and live veth smokes for capture, flows, metrics, netlink and TLS fingerprints.'],
    ['Read-only where it matters', 'No payload, argv or Secret collection. Netra never modifies or pins over Cilium-owned maps, and the security review only suggests.'],
    ['Signed and listed', 'Release images are cosign-signed with an SBOM, and the MCP server is in the official MCP Registry.'],
  ];
  return (
    <Section
      id="receipts"
      eyebrow="Receipts"
      title="Boring in the right places."
      lede="The guarantees are written down, tested and enforced in CI, not just promised.">
      <div className={s.cards3}>
        {items.map(([t, p], i) => (
          <Reveal key={t} delay={i * 80}>
            <div className={s.receipt}>
              <h3>{t}</h3>
              <p>{p}</p>
            </div>
          </Reveal>
        ))}
      </div>
      <div className={s.badges}>
        <img src="https://github.com/zyvorai/zyvor-netra/actions/workflows/ci.yml/badge.svg" alt="CI status" />
        <img src="https://img.shields.io/badge/License-Zyvor%20Production%20v1.0-blue.svg" alt="Zyvor Production License v1.0" />
        <Link to="/docs/security">Read the security model →</Link>
      </div>
    </Section>
  );
}

/* ------------------------------------------------------------ timeline */

const SHIPPED = [
  {v: '0.30.1', d: '2026-10-15', t: 'Listed in the MCP Registry', p: 'netra-mcp ships as an OCI image and as io.github.zyvorai/netra.'},
  {v: '0.30.0', d: '2026-10-07', t: 'Metrics, node isolation, security review', p: 'Per-second metrics with anomaly detection and alerts, a per-node allow-only egress filter (shadow or enforce), and read-only security intelligence.'},
  {v: 'main', d: 'unreleased', t: 'Envoy in front', p: 'Optional Gateway API route and backend TLS policy in the Helm chart, tested against Envoy Gateway.'},
];

export function Shipped(): ReactNode {
  return (
    <Section
      id="shipped"
      tint
      eyebrow="Shipped"
      title="What landed recently."
      lede="The full history is in the changelog.">
      <Reveal>
        <ul className={s.timeline}>
          {SHIPPED.map((r) => (
            <li key={r.v}>
              <span>{r.v} · {r.d}</span>
              <b>{r.t}</b>
              <p>{r.p}</p>
            </li>
          ))}
        </ul>
        <p><Link to="/docs/reference/changelog">Open the changelog →</Link></p>
      </Reveal>
    </Section>
  );
}

/* ----------------------------------------------------------- quickstart */

export function Quickstart(): ReactNode {
  return (
    <Section
      id="quickstart"
      eyebrow="Quickstart"
      title="Copy, paste, run."
      lede="Needs Linux with cgroup v2 and bpffs. The practical baseline is kernel 5.8, and TCX needs 6.6.">
      <Reveal>
        <div className={s.agents}>
          <Code>{`make install
netractl install --namespace netra-system
netractl status --wait`}</Code>
          <div className={s.panelText}>
            <p>
              The dashboard comes up on <code>https://&lt;node-ip&gt;:30870</code>. The chart pins image tags to the checkout, so clone a release tag rather than <code>main</code>.
            </p>
            <Link to="/docs/getting-started/quickstart">Full quickstart →</Link>
            {'  '}
            <Link to="/docs/getting-started/install">Install options →</Link>
          </div>
        </div>
      </Reveal>
    </Section>
  );
}
