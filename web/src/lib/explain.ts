import { dnsResponseFinding, type DNSResponseEvent } from './dns';
import { icmpFinding, type ICMPError } from './icmp';
import { bpfMapsMissingFinding, rateDropFinding, type NamedCount } from './bpfhealth';

// Client-side port of cmd/netractl/explain.go's parseExplain/buildExplain,
// so the web dashboard can offer the same passive, read-only connection
// diagnostics as `netractl explain` against the same /api/v1/agents data.
// Keep the validation rules and finding logic in sync with the Go source
// if either changes.

export type ExplainScope = {
  node: string;
  namespace: string;
  pod: string;
  pid: string;
  container: string;
  destination: string;
  dns: string;
  all: boolean;
  limit: number;
  maxAgeMinutes: number;
};

export const emptyExplainScope: ExplainScope = {
  node: '',
  namespace: '',
  pod: '',
  pid: '',
  container: '',
  destination: '',
  dns: '',
  all: false,
  limit: 50,
  maxAgeMinutes: 2,
};

type NormalizedScope = {
  node: string;
  namespace: string;
  pod: string;
  pid: number;
  container: string;
  destination: string;
  dns: string;
  all: boolean;
  limit: number;
  maxAgeMs: number;
  ip: string;
  port: number;
};

const CONTROL_OR_EDGE_WHITESPACE = /[\r\n\t\x00]/;

function unmapIPv6(ip: string): string {
  const m = /^::ffff:(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$/i.exec(ip.trim());
  return (m ? m[1] : ip.trim()).toLowerCase();
}

function isIPv4(s: string): boolean {
  const parts = s.split('.');
  if (parts.length !== 4) return false;
  return parts.every((p) => /^\d{1,3}$/.test(p) && Number(p) <= 255);
}

function isIPv6(s: string): boolean {
  // Best-effort, not a full RFC 5952 validator: at least two colons (or a
  // leading/trailing "::"), only hex digits/colons (optionally with a
  // trailing IPv4-mapped tail).
  if (!/^[0-9a-fA-F:]+(:\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})?$/.test(s)) return false;
  return s.includes(':') && (s.match(/:/g) || []).length >= 2;
}

function looksLikeIP(s: string): boolean {
  return isIPv4(s) || isIPv6(s);
}

/** Validates and normalizes a scope. Returns an error message, or the normalized scope. */
export function parseExplainScope(o: ExplainScope): { error: string } | { scope: NormalizedScope } {
  if (o.limit < 1 || o.limit > 1000) return { error: '--limit must be 1-1000' };
  if (o.maxAgeMinutes <= 0 || o.maxAgeMinutes > 24 * 60) {
    return { error: '--max-age must be greater than zero and at most 24h' };
  }
  for (const v of [o.node, o.namespace, o.pod, o.container, o.destination, o.dns]) {
    if (v !== v.trim() || CONTROL_OR_EDGE_WHITESPACE.test(v)) {
      return { error: 'selectors must not contain surrounding whitespace or control characters' };
    }
  }

  let namespace = o.namespace.trim();
  let pod = o.pod.trim();
  if (pod.includes('/')) {
    const parts = pod.split('/');
    if (parts.length !== 2 || !parts[0] || !parts[1]) return { error: '--pod must be namespace/name' };
    if (namespace && namespace !== parts[0]) return { error: '--namespace conflicts with --pod' };
    namespace = parts[0];
    pod = parts[1];
  }
  if (pod && !namespace) return { error: '--pod requires namespace/name or --namespace' };

  const pidStr = o.pid.trim();
  let pid = 0;
  if (pidStr) {
    if (!/^\d+$/.test(pidStr)) return { error: '--pid must be a positive integer' };
    pid = Number(pidStr);
    if (pid === 0) return { error: '--pid must be greater than zero' };
    if (pid > 4294967295 || !o.node.trim()) return { error: '--pid requires --node and a 32-bit PID' };
  }

  let ip = '';
  let port = 0;
  const destination = o.destination.trim();
  if (destination) {
    if (looksLikeIP(destination)) {
      ip = unmapIPv6(destination);
    } else {
      // IP:port or [IPv6]:port
      const bracket = /^\[([0-9a-fA-F:]+)\]:(\d+)$/.exec(destination);
      const plain = /^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(\d+)$/.exec(destination);
      const m = bracket || plain;
      if (!m) return { error: '--destination requires an IP or IP:port; use --dns for observed names' };
      const [, host, portStr] = m;
      if (!looksLikeIP(host)) return { error: 'destination host must be a literal IP; no DNS lookup is performed' };
      const n = Number(portStr);
      if (!Number.isInteger(n) || n < 1 || n > 65535) return { error: 'destination port must be 1-65535' };
      ip = unmapIPv6(host);
      port = n;
    }
  }

  let dns = o.dns.trim();
  if (dns) {
    dns = dns.toLowerCase().replace(/\.$/, '');
    if (!dns) return { error: 'DNS name must not be empty' };
    if (destination || pid !== 0 || o.container.trim()) {
      return {
        error:
          '--dns supports node/namespace/pod scope only; DNS counters cannot prove PID, container or destination-IP attribution',
      };
    }
  }

  if (!o.all && !o.node.trim() && !namespace && !pod && pid === 0 && !o.container.trim() && !destination && !dns) {
    return { error: 'provide a selector or explicitly use --all' };
  }

  return {
    scope: {
      node: o.node.trim(),
      namespace,
      pod,
      pid,
      container: o.container.trim(),
      destination,
      dns,
      all: o.all,
      limit: o.limit,
      maxAgeMs: o.maxAgeMinutes * 60_000,
      ip,
      port,
    },
  };
}

// —— Agent report shapes (mirrors internal/models.AgentStatus's JSON tags) ——

export type ExplainIdentity = { namespace?: string; pod?: string; pid?: number; containerId?: string };
export type ExplainEvent = ExplainIdentity & DNSResponseEvent & {
  observedAt: string;
  destinationIp: string;
  destinationPort: number;
  action: string;
  reason?: string;
  hook?: string;
  dnsQuery?: string;
  comm?: string;
};
export type ExplainTCP = ExplainIdentity & {
  remoteIp: string;
  remotePort: number;
  activeEstablished: number;
  passiveEstablished: number;
  retransmissions: number;
  rtos: number;
  ownershipStale?: boolean;
};
export type ExplainDNS = { namespace?: string; pod?: string; name: string; queries: number; responses: number; failures: number };
export type ExplainAgentStatus = {
  icmpErrors?: ICMPError[];
  missingMaps?: string[];
  rateDrops?: NamedCount[];
  node: string;
  stale: boolean;
  observedAt: string;
  events?: ExplainEvent[];
  tcpHealth?: ExplainTCP[];
  dnsHealth?: ExplainDNS[];
};

export type ExplainFinding = {
  kind: string;
  node: string;
  namespace?: string;
  pod?: string;
  evidence: string;
  nextCheck: string;
};
export type ExplainReport = {
  status: 'no-matching-evidence' | 'evidence-found';
  agentsConsidered: number;
  agentsExcluded: number;
  findings: ExplainFinding[];
  findingsTotal: number;
  truncated: boolean;
  limitations: string[];
};

function identityMatches(o: NormalizedScope, i: ExplainIdentity): boolean {
  return (
    (!o.namespace || o.namespace === (i.namespace || '')) &&
    (!o.pod || o.pod === (i.pod || '')) &&
    (o.pid === 0 || o.pid === (i.pid || 0)) &&
    (!o.container || o.container === (i.containerId || ''))
  );
}
function destinationMatches(o: NormalizedScope, ip: string, port: number): boolean {
  if (!o.ip) return true;
  return unmapIPv6(ip) === o.ip && (o.port === 0 || o.port === port);
}

export function buildExplainReport(agents: ExplainAgentStatus[], o: NormalizedScope, now: Date): ExplainReport {
  const limitations: string[] = [
    'ICMP errors are cumulative TC observations by node/interface/direction; one packet may be seen at multiple interfaces. No workload or quoted-flow attribution is inferred. Missing ICMP data can mean an older agent, unattached TC hooks, or no observed errors. Fragmented ICMP errors are excluded.',
    'DNS response findings use reported matched UDP/53 events and the four-bit base-header RCODE only. EDNS extended errors, answer records, TCP DNS, DoH, and DoT are not inferred. Event latency is the reported query-response interval, not resolver execution time.',
    'bpf-maps-missing reports an agent\'s BPF object load state, not a specific dropped connection; it appears only at node-wide or all-node scope.',
    'Rate-drop findings are cumulative PPS-ceiling drop counters by destination IP since the map was created; they do not identify which flows or ports were affected.',
    'Evidence is sampled or aggregated from agent reports; missing evidence does not prove no traffic or a healthy connection.',
    'TCP/DNS counters are cumulative snapshots, not measurements for a selected time window. Event timestamps are agent observation times.',
    'A passed/observed event does not prove end-to-end delivery. Events lack a stable historical winning rule ID and policy generation.',
    'No active probes, DNS resolution, policy changes, or packet payload collection are performed.',
  ];
  if (o.pid !== 0) limitations.push('PID events may describe an earlier process incarnation; DNS counters lack PID attribution and are excluded.');
  if (o.container) limitations.push('Container selection uses exact reported IDs; Docker names are not resolved. DNS counters lack container identity and are excluded.');
  if (o.destination) limitations.push('Destination matches packet destination for events and remote peer for TCP health. DNS counters are excluded because they do not identify the destination IP.');
  if (o.dns) limitations.push('DNS evidence covers reported cleartext DNS only; no hostname-to-IP or DNS-to-TCP correlation is inferred.');

  const findings: ExplainFinding[] = [];
  let findingsTotal = 0;
  const add = (kind: string, node: string, i: ExplainIdentity, evidence: string, nextCheck: string) => {
    findingsTotal++;
    if (findings.length < o.limit) findings.push({ kind, node, namespace: i.namespace, pod: i.pod, evidence, nextCheck });
  };

  let agentsConsidered = 0;
  let agentsExcluded = 0;
  const sorted = [...agents].sort((a, b) => a.node.localeCompare(b.node));
  for (const a of sorted) {
    if (o.node && a.node !== o.node) continue;
    agentsConsidered++;
    const observedAt = new Date(a.observedAt).getTime();
    const ageMs = now.getTime() - observedAt;
    if (!a.node || a.stale || !a.observedAt || Number.isNaN(observedAt) || ageMs > o.maxAgeMs || ageMs < -60_000) {
      agentsExcluded++;
      continue;
    }
    if (!o.namespace && !o.pod && !o.pid && !o.container && !o.destination && !o.dns) {
      for (const e of a.icmpErrors || []) {
        const f = icmpFinding(e);
        if (f) add(f.kind, a.node, {}, f.evidence, f.nextCheck);
      }
      const missing = bpfMapsMissingFinding(a.missingMaps);
      if (missing) add(missing.kind, a.node, {}, missing.evidence, missing.nextCheck);
    }
    if (!o.namespace && !o.pod && !o.pid && !o.container && !o.dns) {
      for (const d of a.rateDrops || []) {
        if (!destinationMatches(o, d.name, 0)) continue;
        const f = rateDropFinding(d);
        if (f) add(f.kind, a.node, {}, f.evidence, f.nextCheck);
      }
    }
    for (const e of a.events || []) {
      if (!identityMatches(o, e) || !destinationMatches(o, e.destinationIp, e.destinationPort)) continue;
      if (o.dns && (e.dnsQuery || '').toLowerCase().replace(/\.$/, '') !== o.dns) continue;
      const dns = dnsResponseFinding(e);
      if (dns) {
        add(dns.kind, a.node, e, dns.evidence, dns.nextCheck);
        continue;
      }
      const blocked = e.action === 'blocked';
      const kind = blocked ? 'observed-block' : 'network-event';
      const nextCheck = blocked
        ? 'Review Netra policy and its revision history; the reason does not identify a historical rule ID.'
        : 'Inspect peer availability and application logs; this event alone cannot establish delivery.';
      const evidence = `action="${e.action}" reason="${e.reason || ''}" hook="${e.hook || ''}" destination="${e.destinationIp}" port=${e.destinationPort} process="${e.comm || ''}" pid=${e.pid || 0} observedAt="${e.observedAt}"`;
      add(kind, a.node, e, evidence, nextCheck);
    }
    if (!o.dns) {
      for (const t of a.tcpHealth || []) {
        if (!identityMatches(o, t) || !destinationMatches(o, t.remoteIp, t.remotePort) || (o.pid !== 0 && t.ownershipStale)) continue;
        if (t.activeEstablished > 0 || t.passiveEstablished > 0) {
          add(
            'tcp-established',
            a.node,
            t,
            `remote="${t.remoteIp}" port=${t.remotePort} active-established=${t.activeEstablished} passive-established=${t.passiveEstablished}`,
            'TCP established at least once in these counters; check current application health separately.'
          );
        }
        if (t.retransmissions > 0 || t.rtos > 0) {
          add(
            'tcp-loss-signal',
            a.node,
            t,
            `remote="${t.remoteIp}" port=${t.remotePort} retransmissions=${t.retransmissions} retransmission-timeouts=${t.rtos}`,
            'Check path loss, congestion and peer response; these counters do not prove a firewall caused a timeout.'
          );
        }
      }
    }
    if (o.pid === 0 && !o.container && !o.destination) {
      for (const d of a.dnsHealth || []) {
        const id: ExplainIdentity = { namespace: d.namespace, pod: d.pod };
        if (!identityMatches(o, id)) continue;
        if (o.dns && d.name.toLowerCase().replace(/\.$/, '') !== o.dns) continue;
        if (d.queries === 0 && d.responses === 0 && d.failures === 0) continue;
        const nextCheck =
          d.failures > 0
            ? 'Inspect DNS response codes and resolver logs; reported failures are not proof of packet loss.'
            : 'Inspect resolver reachability and application DNS behavior. Unmatched queries do not establish timeouts.';
        add('dns-counters', a.node, id, `name="${d.name}" queries=${d.queries} matched-responses=${d.responses} failures=${d.failures}`, nextCheck);
      }
    }
  }

  if (agentsExcluded > 0) {
    limitations.push(`Excluded ${agentsExcluded} reports marked stale, too old, missing node/time, or more than one minute in the future.`);
  }

  return {
    status: findingsTotal > 0 ? 'evidence-found' : 'no-matching-evidence',
    agentsConsidered,
    agentsExcluded,
    findings,
    findingsTotal,
    truncated: findingsTotal > findings.length,
    limitations,
  };
}
