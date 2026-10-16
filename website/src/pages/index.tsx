import type {ReactNode} from 'react';
import Link from '@docusaurus/Link';
import Layout from '@theme/Layout';
import Reveal from '@site/src/components/Reveal';
import {CtaBand, HeroShell, HonestyBand, Page} from '@site/src/components/marketing/Shell';
import {
  Agents,
  Explorer,
  F,
  Quickstart,
  Receipts,
  Shipped,
  StackScene,
  Walkthrough,
  Why,
} from '@site/src/components/home';
import s from '@site/src/components/home/Home.module.css';

export default function Home(): ReactNode {
  return (
    <Layout
      title="Netra — standalone eBPF network observability and emergency control"
      description="Standalone eBPF network observability and emergency network control for Linux and Kubernetes, with optional Cilium and Hubble enrichment and an MCP server for AI agents.">
      <Page>
        <HeroShell
          eyebrow="Standalone eBPF network observability"
          title="See the network. Diagnose it."
          accent="Contain it."
          sub="Kernel-level drop attribution, TCP path diagnostics, live capture and leased deny rules for Linux and Kubernetes. No CNI required; Cilium and Hubble optional."
          buttons={
            <>
              <Link className={`${s.btn} ${s.btnPrimary}`} to="/docs/getting-started/quickstart">
                Get started
              </Link>
              <a className={`${s.btn} ${s.btnGhost}`} href="#product">
                See the product
              </a>
              <Link className={`${s.btn} ${s.btnGhost}`} to="https://github.com/zyvorai/zyvor-netra">
                GitHub
              </Link>
            </>
          }
          stats={[
            [String(F.mcpTools), `MCP tools, ${F.mcpReadTools} read-only`],
            ['4', 'kernel hooks: cgroup, sockops, TCX, XDP'],
            ['Leased', 'every deny fails open to observe'],
            [String(F.docPages), 'pages of docs in the repo'],
          ]}
          cueHref="#why"
          cueLabel="Scroll to the next section"
        />
        <Why />
        <StackScene />
        <Walkthrough />
        <Explorer />
        <Agents />
        <Receipts />
        <Shipped />
        <Quickstart />
        <HonestyBand
          items={[
            <>Netra is not a CNI and not a standing policy engine; it is an emergency layer.</>,
            <>Envoy support is a front door through the Gateway API, not a data-plane integration.</>,
            <>Production use needs a commercial license; evaluation and lab use are free.</>,
            <>Some probes need newer kernels (TCX needs 6.6); the dashboard reports what is unavailable and why.</>,
          ]}
        />
        <CtaBand title="Put it on a lab cluster today.">
          <Link className={`${s.btn} ${s.btnPrimary}`} to="/docs/getting-started/quickstart">
            Quickstart
          </Link>
          <Link className={`${s.btn} ${s.btnGhost}`} to="mailto:sales@zyvor.dev">
            Talk to sales
          </Link>
        </CtaBand>
      </Page>
    </Layout>
  );
}
