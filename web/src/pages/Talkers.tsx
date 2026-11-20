import { useEffect, useState } from 'react';
import { api } from '../api';
import PagePulse from '../components/kit/PagePulse';
import RankedList from '../components/kit/RankedList';
import { countTone } from '../components/kit/tone';

type Row = { destination?: string; packets?: number; bytes?: number; blocked?: number; nodes?: number };
type Board = { rows?: Row[]; count?: number };

export default function Talkers() {
  const [board, setBoard] = useState<Board>();
  const [err, setErr] = useState('');
  const load = () => {
    api<Board>('/api/v1/talkers?limit=30').then((b) => { setBoard(b); setErr(''); }).catch((e) => setErr(String(e)));
  };
  useEffect(() => { load(); const t = setInterval(load, 20000); return () => clearInterval(t); }, []);
  const rows = board?.rows || [];
  const packets = rows.reduce((n, r) => n + (r.packets || 0), 0);
  const blocked = rows.reduce((n, r) => n + (r.blocked || 0), 0);
  const blockedDest = rows.filter((r) => r.blocked).length;
  const top = rows[0];
  return (
    <div className="grid">
      <PagePulse
        headline={board ? (top ? `${top.destination} leads with ${packets ? Math.round(((top.packets || 0) / packets) * 100) : 0}% of packets.` : 'No talkers observed yet.') : undefined}
        tone={board && blockedDest ? 'warn' : undefined}
        tick={board}
        error={err || undefined}
        figures={[
          { label: 'destinations', value: board ? rows.length : undefined },
          { label: 'packets', value: board ? packets : undefined },
          { label: 'blocked packets', value: board ? blocked : undefined, tone: board ? countTone(blocked) : undefined },
          { label: 'blocked destinations', value: board ? blockedDest : undefined, tone: board ? countTone(blockedDest) : undefined },
        ]}
      />
      <section className="card span3">
        <p className="eyebrow">TALKERS</p>
        <h2 className="card-title">Top destinations</h2>
        <p>Packet counts from current agent reports. Observe-only, no payloads.</p>
        {err && <p className="warning">{err}</p>}
        <RankedList
          limit={30}
          empty="No talkers observed yet."
          items={rows.map((r) => ({
            name: r.destination || '—',
            count: r.packets || 0,
            detail: `${r.blocked || 0} blocked · ${r.nodes || 0} nodes`,
            tone: r.blocked ? 'bad' as const : undefined,
          }))}
        />
      </section>
    </div>
  );
}
