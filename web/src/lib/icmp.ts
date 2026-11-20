// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
export type ICMPError = {
  interfaceName?: string; interfaceIndex: number; family: string; type: number; code: number;
  direction: string; hook: string; packets: number; advertisedMtu?: number;
};

// Keep classification and scope boundaries aligned with cmd/netractl/icmp.go.
export function icmpFinding(e: ICMPError) {
  if (!(e.packets > 0) || e.hook !== 'tc') return null;
  const v4 = e.family === 'IPv4', v6 = e.family === 'IPv6';
  let kind: string, label: string, nextCheck: string;
  if ((v4 && e.type === 3 && e.code === 4) || (v6 && e.type === 2 && e.code === 0)) {
    kind = 'icmp-pmtu'; label = 'MTU / packet too big';
    nextCheck = 'Check interface and tunnel MTUs and whether ICMP errors reach the sender. The advertised MTU is a peer claim, not a verified path MTU.';
  } else if ((v4 && e.type === 3) || (v6 && e.type === 1)) {
    kind = 'icmp-unreachable'; label = 'Destination unreachable';
    nextCheck = 'Inspect the ICMP type/code, destination listener, routes, and firewall rejects. This node-level signal does not identify the failing workload or connection.';
  } else if ((v4 && e.type === 11) || (v6 && e.type === 3)) {
    kind = 'icmp-time-exceeded'; label = 'Time exceeded';
    nextCheck = 'Check routing loops, hop limits, and fragment reassembly timeouts using the reported ICMP code.';
  } else if ((v4 && e.type === 12) || (v6 && e.type === 4)) {
    kind = 'icmp-parameter-problem'; label = 'IP parameter problem';
    nextCheck = 'Check IP header and tunnel configuration; peers reported a packet parameter problem.';
  } else return null;
  const evidence = `interface-index=${e.interfaceIndex} family=${e.family} direction=${JSON.stringify(e.direction)} hook=tc type=${e.type} code=${e.code} observations=${e.packets}` + (e.interfaceName ? ` interface-name=${JSON.stringify(e.interfaceName)}` : '') + (e.advertisedMtu ? ` last-advertised-mtu=${e.advertisedMtu}` : '');
  return { kind, label, evidence, nextCheck };
}
