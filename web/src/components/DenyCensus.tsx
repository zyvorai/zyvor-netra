import { useEffect, useState } from 'react';
import { api } from '../api';

type Census = {
  mode?: string;
  totalDenied?: number;
  totalAllowed?: number;
  blockedIPv4?: number; blockedIPv6?: number; blockedCidrs?: number; blockedPorts?: number;
  blockedDns?: number; blockedUids?: number; blockedIngressIPv4?: number; blockedIngressIPv6?: number;
  allowedIPv4?: number; allowedIPv6?: number; allowedCidrs?: number; allowedPorts?: number;
};

export default function DenyCensus() {
  const [c, setC] = useState<Census>();
  useEffect(() => {
    const load = () => api<Census>('/api/v1/ebpf/census').then(setC).catch(() => {});
    load();
    const t = setInterval(load, 20000);
    return () => clearInterval(t);
  }, []);
  return (
    <section className="card span3">
      <p className="eyebrow">DENY CENSUS</p>
      <h2 className="card-title">{c?.totalDenied ?? 0} deny entries · {c?.totalAllowed ?? 0} allow entries</h2>
      <p>Counts of deny/allow list entries only — never the entries themselves.</p>
      <div className="list">
        <div className="agent wide"><b>Blocked IPv4/IPv6</b><span>{c?.blockedIPv4 ?? 0} / {c?.blockedIPv6 ?? 0}</span></div>
        <div className="agent wide"><b>Blocked CIDRs / ports</b><span>{c?.blockedCidrs ?? 0} / {c?.blockedPorts ?? 0}</span></div>
        <div className="agent wide"><b>Blocked DNS / UIDs</b><span>{c?.blockedDns ?? 0} / {c?.blockedUids ?? 0}</span></div>
        <div className="agent wide"><b>Blocked ingress IPv4/IPv6</b><span>{c?.blockedIngressIPv4 ?? 0} / {c?.blockedIngressIPv6 ?? 0}</span></div>
        <div className="agent wide"><b>Allowed IPv4/IPv6</b><span>{c?.allowedIPv4 ?? 0} / {c?.allowedIPv6 ?? 0}</span></div>
        <div className="agent wide"><b>Allowed CIDRs / ports</b><span>{c?.allowedCidrs ?? 0} / {c?.allowedPorts ?? 0}</span></div>
      </div>
    </section>
  );
}
