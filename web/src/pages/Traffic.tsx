import { useEffect, useState } from 'react';
import { api } from '../api';
import { protoNameClass } from '../lib/flow';
import PagePulse from '../components/kit/PagePulse';
import RankedList from '../components/kit/RankedList';
import Section from '../components/kit/Section';
import { countTone } from '../components/kit/tone';
import { useSeries } from '../components/kit/useSeries';
import { bytes, compact } from '../components/kit/format';

type NSRow = { namespace: string; packets: number; bytes: number; blocked: number; destinations: number };
type ProtoRow = { protocol: string; packets: number; bytes: number; blocked: number; flows: number };
type PortRow = { port: number; protocol: string; key: string; packets: number; blocked: number; flows: number };
type DNSRow = { name: string; queries: number; responses: number; failures: number; failRate: number };

export default function Traffic() {
  const [ns, setNs] = useState<{ rows?: NSRow[] }>();
  const [proto, setProto] = useState<{ rows?: ProtoRow[] }>();
  const [ports, setPorts] = useState<{ rows?: PortRow[] }>();
  const [dns, setDns] = useState<{ rows?: DNSRow[]; queries?: number; failures?: number }>();
  const [err, setErr] = useState('');
  const load = () => Promise.all([
    api<{ rows?: NSRow[] }>('/api/v1/namespaces/heat'),
    api<{ rows?: ProtoRow[] }>('/api/v1/protocols'),
    api<{ rows?: PortRow[] }>('/api/v1/ports'),
    api<{ rows?: DNSRow[]; queries?: number; failures?: number }>('/api/v1/dns/board'),
  ]).then(([n, p, po, d]) => { setNs(n); setProto(p); setPorts(po); setDns(d); setErr(''); }).catch((e) => setErr(String(e)));
  useEffect(() => { load(); const t = setInterval(load, 20000); return () => clearInterval(t); }, []);

  const nsRows = ns?.rows || [];
  const totalPackets = nsRows.reduce((n, r) => n + (r.packets || 0), 0);
  const totalBytes = nsRows.reduce((n, r) => n + (r.bytes || 0), 0);
  const totalBlocked = nsRows.reduce((n, r) => n + (r.blocked || 0), 0);
  const dnsFail = dns?.failures ?? 0;
  const packetSeries = useSeries(ns ? totalPackets : undefined, ns);
  const top = nsRows[0];

  return (
    <div className="grid">
      <PagePulse
        headline={ns ? (top ? `${top.namespace} carries ${totalPackets ? Math.round((top.packets / totalPackets) * 100) : 0}% of observed packets.` : 'No namespace traffic observed yet.') : undefined}
        tick={ns}
        error={err || undefined}
        figures={[
          { label: 'packets observed', value: ns ? totalPackets : undefined, series: packetSeries },
          { label: 'bytes observed', value: ns ? totalBytes : undefined, format: bytes },
          { label: 'blocked packets', value: ns ? totalBlocked : undefined, tone: ns ? countTone(totalBlocked) : undefined },
          { label: 'DNS failures', value: dns ? dnsFail : undefined, tone: dns ? countTone(dnsFail) : undefined },
        ]}
      />

      <Section eyebrow="Namespace heat" title="Traffic by Kubernetes namespace" span={2} lede="Packets rolled up by namespace from current agent destination stats.">
        <RankedList
          mono={false}
          empty="No namespace traffic observed yet."
          items={nsRows.map((r) => ({
            name: r.namespace,
            count: r.packets,
            tone: r.blocked ? 'bad' : undefined,
            detail: `${bytes(r.bytes || 0)} · ${r.destinations} destinations · ${r.blocked} blocked`,
          }))}
        />
      </Section>

      <Section eyebrow="Protocol mix" title="L4 protocol breakdown" span={1} lede="Protocol mix across current destination stats.">
        <RankedList
          mono={false}
          empty="No protocol data yet."
          items={(proto?.rows || []).map((r) => ({
            name: r.protocol,
            count: r.packets,
            tone: r.blocked ? 'bad' : undefined,
            detail: <><span className={protoNameClass(r.protocol)}>{r.protocol}</span> · {compact(r.flows)} flows · {r.blocked} blocked</>,
          }))}
        />
      </Section>

      <Section eyebrow="Port heat" title="Top destination ports" span={2} lede="Top destination ports by packet count.">
        <RankedList
          empty="No port data yet."
          items={(ports?.rows || []).map((r) => ({
            key: r.key,
            name: `${r.protocol}/${r.port}`,
            count: r.packets,
            tone: r.blocked ? 'bad' : undefined,
            detail: `${compact(r.flows)} flows · ${r.blocked} blocked`,
          }))}
        />
      </Section>

      <Section
        eyebrow="DNS board"
        tone={dns ? countTone(dnsFail) : undefined}
        title={`${dns?.queries ?? 0} queries · ${dnsFail} failures`}
        span={1}
        lede="DNS names ranked by failure count from agent DNS health stats."
      >
        <RankedList
          empty="No DNS activity observed yet."
          items={(dns?.rows || []).map((r) => ({
            name: r.name,
            count: r.failures || r.queries,
            tone: r.failures ? 'bad' : undefined,
            detail: `${(r.failRate * 100).toFixed(1)}% fail · ${r.queries} queries · ${r.failures} failures`,
          }))}
        />
      </Section>
    </div>
  );
}
