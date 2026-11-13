import type {ReactNode} from 'react';
import Layout from '@theme/Layout';
import Heading from '@theme/Heading';
import useBaseUrl from '@docusaurus/useBaseUrl';
import styles from './gallery.module.css';

type Shot = {
  src: string;
  caption: string;
};

// Prefer the current docs/ux lab captures (grouped nav, Ask Netra, path/capture)
// over the archived docs/ux/v022 flat-nav tour.
const TOUR: Shot[] = [
  {src: '/00-overview.png', caption: 'Overview — Ask Netra'},
  {src: '/07-login.png', caption: 'Sign in'},
  {src: '/08-path-edge-intel.png', caption: 'Path diagnostics'},
  {src: '/09-congestion-map.jpg', caption: 'Congestion map'},
  {src: '/03-drops.png', caption: 'Drop diagnostics'},
  {src: '/10-capture-live.jpg', caption: 'Live capture'},
  {src: '/11-capture-decode.jpg', caption: 'Capture decode'},
  {src: '/01-flows.png', caption: 'Flows'},
  {src: '/02-policy.png', caption: 'Policies'},
  {src: '/04-ebpf.png', caption: 'eBPF / firewall'},
  {src: '/05-policy-dryrun.png', caption: 'Policy dry-run'},
  {src: '/06-lockdown.png', caption: 'Workload lockdown'},
];

function ShotCard({shot}: {shot: Shot}) {
  const src = useBaseUrl(shot.src);
  return (
    <figure className={styles.shot}>
      <img src={src} alt={shot.caption} loading="lazy" />
      <figcaption>{shot.caption}</figcaption>
    </figure>
  );
}

export default function Gallery(): ReactNode {
  const gif = useBaseUrl('/capture-diagnostics-demo.gif');
  return (
    <Layout
      title="Gallery"
      description="A walkthrough of the Netra dashboard — overview, path and drop diagnostics, live capture, and leased controls — from a real lab deployment.">
      <header className={styles.header}>
        <div className="container">
          <Heading as="h1">Product tour</Heading>
          <p>
            Screenshots from a running lab deployment. Observe boards (Surfaces,
            Handoff, SLO, Investigate, Flow observe) ship in the dashboard and
            docs; this gallery tracks the live captures in <code>docs/ux/</code>.
          </p>
        </div>
      </header>
      <main className="container">
        <div className={styles.demo}>
          <img
            src={gif}
            alt="Netra live demo — congestion finding to packet capture"
          />
          <p className={styles.caption}>
            Live demo: congestion map finding into a filtered, time-bounded
            packet capture with decode — no mockups.
          </p>
        </div>
        <div className={styles.grid}>
          {TOUR.map((shot) => (
            <ShotCard key={shot.src} shot={shot} />
          ))}
        </div>
      </main>
    </Layout>
  );
}
