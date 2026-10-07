import type {ReactNode} from 'react';
import clsx from 'clsx';
import Link from '@docusaurus/Link';
import useBaseUrl from '@docusaurus/useBaseUrl';
import Layout from '@theme/Layout';
import Heading from '@theme/Heading';
import FeatureHighlights from '@site/src/components/FeatureHighlights';
import ScreenshotStrip from '@site/src/components/ScreenshotStrip';
import Reveal from '@site/src/components/Reveal';

import styles from './index.module.css';

function HomepageHeader() {
  const demoGif = useBaseUrl('/netra-live-demo.gif');
  return (
    <header className={clsx('hero hero--primary', styles.heroBanner)}>
      <div className="container">
        <div className={styles.heroGrid}>
          <div>
            <Heading as="h1" className="hero__title">
              See the network.
              <br />
              Diagnose it.
              <br />
              Contain it.
            </Heading>
            <p className="hero__subtitle">
              Standalone eBPF network observability and emergency network
              control for Linux/Kubernetes — with optional Cilium + Hubble
              enrichment. No CNI dependency required.
            </p>
            <div className={styles.buttons}>
              <Link
                className="button button--secondary button--lg"
                to="/docs/getting-started/quickstart">
                Get Started
              </Link>
              <Link
                className="button button--outline button--lg button--secondary"
                to="/resources">
                Download resources
              </Link>
              <Link
                className="button button--outline button--lg button--secondary"
                to="https://github.com/zyvorai/zyvor-netra">
                View on GitHub
              </Link>
            </div>
          </div>
          <div className={styles.heroMedia}>
            <img
              src={demoGif}
              alt="Netra live demo — Overview, Firewall/NetPol v2, in-browser VNC console"
            />
            <p className={styles.heroMediaCaption}>
              Captured against a live lab deployment, not a mockup.
            </p>
          </div>
        </div>
      </div>
    </header>
  );
}

function ProblemStatement() {
  return (
    <section className={styles.problem}>
      <div className="container">
        <Reveal className="row">
          <div className="col col--8 col--offset-2 text--center">
            <Heading as="h2" className={styles.sectionHeading}>
              Why standalone?
            </Heading>
            <p>
              Most network visibility and enforcement tools couple to a
              specific CNI. Netra's node agent owns its own eBPF programs and
              maps below <code>/sys/fs/bpf/netra</code>, attaches to Linux
              cgroup v2, and works whether you're running Cilium, another
              CNI, or nothing at all. When Cilium and Hubble{' '}
              <em>are</em> present, Netra reads Hubble flows and manages{' '}
              <code>CiliumNetworkPolicy</code> too — as an addition, never a
              requirement.
            </p>
            <p>
              Every enforcement rule — deny lists, the DDoS shield, per-workload
              allow/default-deny — sits behind a time-limited lease that
              fails open automatically on expiry, agent/controller restart,
              or HA failover. It's an emergency containment layer you
              deliberately reach for during an incident, not a standing
              policy engine you have to trust blindly.
            </p>
          </div>
        </Reveal>
      </div>
    </section>
  );
}

function TrustBand() {
  return (
    <section className={styles.trust}>
      <div className="container">
        <Reveal className={styles.trustGrid}>
          <div>
            <Heading as="h3" className={styles.sectionHeading}>
              Open, and honest about its limits
            </Heading>
            <p>
              Zyvor Production License. Real CI on every push (Go build/vet/test, web
              typecheck/test/build, Helm lint/render, and a live{' '}
              <code>clang</code> BPF compile check). Observe-first by design —
              enforcement is leased and fails open, never a silent standing
              default.
            </p>
            <Link to="/docs/security">Read the full security model →</Link>
          </div>
          <div className={styles.trustBadges}>
            <img
              src="https://github.com/zyvorai/zyvor-netra/actions/workflows/ci.yml/badge.svg"
              alt="CI status"
            />
            <img
              src="https://img.shields.io/badge/License-Zyvor%20Production%20v1.0-blue.svg"
              alt="Zyvor Production License v1.0"
            />
          </div>
        </Reveal>
      </div>
    </section>
  );
}

function EnterpriseCTA() {
  return (
    <section className={styles.enterprise}>
      <div className="container text--center">
        <Reveal>
          <Heading as="h2" className={styles.sectionHeading}>
            Need production support or SLAs?
          </Heading>
          <p className={styles.enterpriseCopy}>
            Non-production evaluation and lab use are free. Production
            deployments need a commercial license from Zyvor.
          </p>
          <Link
            className="button button--primary button--lg"
            to="mailto:sales@zyvor.dev">
            Contact sales@zyvor.dev
          </Link>
        </Reveal>
      </div>
    </section>
  );
}

export default function Home(): ReactNode {
  return (
    <Layout
      title="Netra — standalone eBPF network observability and emergency control"
      description="Standalone eBPF network observability and emergency network control for Linux/Kubernetes, with optional Cilium + Hubble enrichment.">
      <HomepageHeader />
      <main>
        <ProblemStatement />
        <Reveal>
          <FeatureHighlights />
        </Reveal>
        <Reveal>
          <ScreenshotStrip />
        </Reveal>
        <TrustBand />
        <EnterpriseCTA />
      </main>
    </Layout>
  );
}
