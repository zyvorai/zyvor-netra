import type {ReactNode} from 'react';
import Layout from '@theme/Layout';
import Heading from '@theme/Heading';
import useBaseUrl from '@docusaurus/useBaseUrl';
import styles from './gallery.module.css';

type Shot = {
  src: string;
  caption: string;
};

// Live lab captures (2026-11-13) under docs/ux/current/ — not the archived
// docs/ux/v022 flat-nav tour.
const TOUR: Shot[] = [
  {src: '/current/00-overview.png', caption: 'Overview'},
  {src: '/current/01-surfaces.png', caption: 'Surfaces'},
  {src: '/current/02-handoff.png', caption: 'Handoff'},
  {src: '/current/03-slo.png', caption: 'SLO'},
  {src: '/current/04-drops.png', caption: 'Drop diagnostics'},
  {src: '/current/05-drop-reasons.png', caption: 'Drop reasons'},
  {src: '/current/06-path.png', caption: 'Path diagnostics'},
  {src: '/current/07-capture.png', caption: 'Capture'},
  {src: '/current/08-investigate.png', caption: 'Investigate'},
  {src: '/current/09-flow-observe.png', caption: 'Flow observe'},
  {src: '/current/10-ai.png', caption: 'Ask Netra'},
  {src: '/current/11-audit.png', caption: 'Audit / SIEM'},
  {src: '/current/12-listen-queues.png', caption: 'Listen Queues'},
  {src: '/current/13-process-integrity.png', caption: 'Process Integrity'},
  {src: '/current/14-incident-timeline.png', caption: 'Incident Timeline'},
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
      description="Current Netra dashboard tour — Surfaces, Handoff, SLO, Investigate, capture and Ask Netra — from a live lab deployment.">
      <header className={styles.header}>
        <div className="container">
          <Heading as="h1">Product tour</Heading>
          <p>
            Fresh captures from a running lab (Surfaces, Handoff, SLO, Listen
            Queues, Process Integrity, Incident Timeline). Archived v0.22 shots
            stay under <code>docs/ux/v022/</code> for history only.
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
            packet capture with decode.
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
