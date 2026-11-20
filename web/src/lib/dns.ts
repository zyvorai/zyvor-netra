// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
export type DNSResponseEvent = {
  type?: string; action: string; protocol?: string; hook?: string; direction?: string;
  sourcePort?: number; sourceIp?: string; dnsQuery?: string; dnsRcode?: number;
  latencyUs?: number; observedAt: string; namespace?: string; pod?: string;
};

// Mirrors cmd/netractl/dns.go. Zero RCODE is omitted by the agent's JSON encoder.
export function dnsResponseFinding(e: DNSResponseEvent) {
  const code = e.dnsRcode ?? 0;
  if (e.type !== 'dns-response' || e.action !== 'observed' || e.protocol !== 'UDP' ||
      e.hook !== 'cgroup' || e.direction !== 'ingress' || e.sourcePort !== 53 ||
      !e.dnsQuery || !Number.isInteger(code) || code < 0 || code > 15) return null;
  let name = `RCODE_${code}`, kind = 'dns-response-error', nextCheck: string;
  switch (code) {
    case 0:
      name = 'NOERROR'; kind = 'dns-response';
      nextCheck = 'The base DNS header reports no error. This does not prove an answer record exists, DNSSEC validation, or application connectivity.'; break;
    case 1:
      name = 'FORMERR'; nextCheck = 'The resolver reported a malformed request. Check client DNS encoding and resolver compatibility.'; break;
    case 2:
      name = 'SERVFAIL'; nextCheck = 'Check resolver and upstream logs, DNSSEC validation, and authoritative-server reachability; SERVFAIL alone does not identify which failed.'; break;
    case 3:
      name = 'NXDOMAIN'; nextCheck = 'The resolver reported that the queried name does not exist. Check spelling, search domains, namespace qualification, and authoritative records.'; break;
    case 4:
      name = 'NOTIMP'; nextCheck = 'Check whether the resolver supports the requested DNS operation.'; break;
    case 5:
      name = 'REFUSED'; nextCheck = 'Check resolver access controls and recursion policy for the requesting workload; refusal is not evidence of packet loss.'; break;
    default:
      nextCheck = 'Inspect the numeric base-header response code and resolver logs; no specific cause is inferred.';
  }
  const evidence = `name=${JSON.stringify(e.dnsQuery)} resolver=${JSON.stringify(e.sourceIp || '')} rcode=${name}(${code}) latency-us=${e.latencyUs || 0} hook=cgroup observedAt=${JSON.stringify(e.observedAt)}`;
  return { kind, name, code, evidence, nextCheck };
}
