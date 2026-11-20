import { useEffect, useState } from 'react';
import { api } from '../api';

type Digest = {
  severity?: string;
  fingerprint?: string;
  changed?: boolean;
  headline?: string;
  whyChanged?: string[];
  whyChangedProse?: string;
};

export function digestTooltip(d: Digest): string {
  if (!d.changed) return d.headline || 'On-call digest';
  const why = d.whyChangedProse || (d.whyChanged || []).join('; ');
  return why ? `${d.headline || 'On-call digest'} — ${why}` : d.headline || 'On-call digest';
}

export function digestLabel(d: Digest): string {
  const sev = (d.severity || 'info').toLowerCase();
  const fp = d.fingerprint ? d.fingerprint.slice(0, 6) : '';
  if (d.changed) return `${sev} · changed ${fp}`.trim();
  return fp ? `${sev} · ${fp}` : sev;
}

export default function DigestChip({ onOpen }: { onOpen?: () => void }) {
  const [digest, setDigest] = useState<Digest | null>(null);

  useEffect(() => {
    let alive = true;
    const load = () => {
      api<Digest>('/api/v1/ai/digest')
        .then((d) => {
          if (alive) setDigest(d);
        })
        .catch(() => undefined);
    };
    load();
    const t = setInterval(load, 30000);
    return () => {
      alive = false;
      clearInterval(t);
    };
  }, []);

  if (!digest) return null;
  const sev = (digest.severity || 'info').toLowerCase();
  return (
    <button
      type="button"
      className={`digest-chip ${sev}${digest.changed ? ' changed' : ''}`}
      onClick={onOpen}
      title={digestTooltip(digest)}
      aria-label={`Incident digest ${digestLabel(digest)}`}
    >
      {digestLabel(digest)}
    </button>
  );
}
