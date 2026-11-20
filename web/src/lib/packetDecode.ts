// decodeL3L4 parses the Ethernet/IPv4/IPv6/TCP/UDP/ICMP headers that are
// already present in every buffered capture frame (frames start at the
// Ethernet header — see internal/capture/capture.go's Frame doc comment
// and Capture.tsx's decodeFrame). No L7 parsing: this covers what
// PROTOCOL_NAMES already tags (TCP/UDP/ICMP/ICMPv6), not HTTP/DNS/TLS.
export type DecodedHeaders = {
  srcIP: string;
  dstIP: string;
  srcPort?: number;
  dstPort?: number;
  tcpFlags?: string;
  icmpType?: number;
  summary: string;
};

const ETHERTYPE_IPV4 = 0x0800;
const ETHERTYPE_IPV6 = 0x86dd;

function ipv4ToString(data: Uint8Array, off: number): string {
  return `${data[off]}.${data[off + 1]}.${data[off + 2]}.${data[off + 3]}`;
}

function ipv6ToString(data: Uint8Array, off: number): string {
  const groups: string[] = [];
  for (let i = 0; i < 8; i++) {
    groups.push((((data[off + i * 2] << 8) | data[off + i * 2 + 1]) >>> 0).toString(16));
  }
  return groups.join(':');
}

const TCP_FLAG_BITS: [number, string][] = [
  [0x01, 'FIN'], [0x02, 'SYN'], [0x04, 'RST'], [0x08, 'PSH'], [0x10, 'ACK'], [0x20, 'URG'],
];

function tcpFlagsToString(flags: number): string {
  const names = TCP_FLAG_BITS.filter(([bit]) => (flags & bit) !== 0).map(([, name]) => name);
  return names.length ? names.join(',') : '-';
}

export function decodeL3L4(data: Uint8Array): DecodedHeaders | null {
  if (data.length < 14) return null;
  const etherType = (data[12] << 8) | data[13];

  let srcIP: string, dstIP: string, ipProto: number, l4Off: number;
  if (etherType === ETHERTYPE_IPV4 && data.length >= 34) {
    const ihl = (data[14] & 0x0f) * 4;
    ipProto = data[14 + 9];
    srcIP = ipv4ToString(data, 14 + 12);
    dstIP = ipv4ToString(data, 14 + 16);
    l4Off = 14 + ihl;
  } else if (etherType === ETHERTYPE_IPV6 && data.length >= 54) {
    ipProto = data[14 + 6];
    srcIP = ipv6ToString(data, 14 + 8);
    dstIP = ipv6ToString(data, 14 + 24);
    l4Off = 14 + 40;
  } else {
    return null;
  }

  let srcPort: number | undefined, dstPort: number | undefined, tcpFlags: string | undefined, icmpType: number | undefined;
  if ((ipProto === 6 || ipProto === 17) && data.length >= l4Off + 4) {
    srcPort = (data[l4Off] << 8) | data[l4Off + 1];
    dstPort = (data[l4Off + 2] << 8) | data[l4Off + 3];
    if (ipProto === 6 && data.length >= l4Off + 14) tcpFlags = tcpFlagsToString(data[l4Off + 13]);
  } else if ((ipProto === 1 || ipProto === 58) && data.length >= l4Off + 2) {
    icmpType = data[l4Off];
  }

  const endpoint = srcPort !== undefined ? `${srcIP}:${srcPort} → ${dstIP}:${dstPort}` : `${srcIP} → ${dstIP}`;
  const summary = tcpFlags ? `${endpoint} [${tcpFlags}]` : endpoint;
  return { srcIP, dstIP, srcPort, dstPort, tcpFlags, icmpType, summary };
}

export function hexDump(data: Uint8Array, max = 64): string {
  return Array.from(data.slice(0, max)).map((b) => b.toString(16).padStart(2, '0')).join(' ');
}

function macToString(data: Uint8Array, off: number): string {
  return Array.from(data.slice(off, off + 6)).map((b) => b.toString(16).padStart(2, '0')).join(':');
}

const IP_PROTOCOL_NAMES: Record<number, string> = { 1: 'ICMP', 6: 'TCP', 17: 'UDP', 58: 'ICMPv6' };
function protocolName(proto: number): string {
  return IP_PROTOCOL_NAMES[proto] ? `${IP_PROTOCOL_NAMES[proto]} (${proto})` : `Unknown (${proto})`;
}

export type DecodedField = { label: string; value: string };
export type DecodedLayer = { name: string; fields: DecodedField[] };

// decodeDetailed produces a Wireshark "packet details"-style layered
// breakdown (one section per protocol layer) for the click-to-expand view.
// Same header coverage as decodeL3L4 — L3/L4 only, no L7.
export function decodeDetailed(data: Uint8Array): DecodedLayer[] {
  const layers: DecodedLayer[] = [];
  layers.push({ name: 'Frame', fields: [{ label: 'Frame Length', value: `${data.length} bytes` }] });
  if (data.length < 14) return layers;

  const etherType = (data[12] << 8) | data[13];
  layers.push({
    name: 'Ethernet II',
    fields: [
      { label: 'Destination', value: macToString(data, 0) },
      { label: 'Source', value: macToString(data, 6) },
      { label: 'Type', value: etherType === ETHERTYPE_IPV4 ? 'IPv4 (0x0800)' : etherType === ETHERTYPE_IPV6 ? 'IPv6 (0x86dd)' : `0x${etherType.toString(16)}` },
    ],
  });

  let ipProto = -1, l4Off = 14;
  if (etherType === ETHERTYPE_IPV4 && data.length >= 34) {
    const ihl = (data[14] & 0x0f) * 4;
    ipProto = data[14 + 9];
    layers.push({
      name: 'Internet Protocol Version 4',
      fields: [
        { label: 'Version', value: String(data[14] >> 4) },
        { label: 'Header Length', value: `${ihl} bytes` },
        { label: 'Total Length', value: String((data[14 + 2] << 8) | data[14 + 3]) },
        { label: 'Time to Live', value: String(data[14 + 8]) },
        { label: 'Protocol', value: protocolName(ipProto) },
        { label: 'Header Checksum', value: `0x${(((data[14 + 10] << 8) | data[14 + 11]) >>> 0).toString(16).padStart(4, '0')}` },
        { label: 'Source', value: ipv4ToString(data, 14 + 12) },
        { label: 'Destination', value: ipv4ToString(data, 14 + 16) },
      ],
    });
    l4Off = 14 + ihl;
  } else if (etherType === ETHERTYPE_IPV6 && data.length >= 54) {
    ipProto = data[14 + 6];
    layers.push({
      name: 'Internet Protocol Version 6',
      fields: [
        { label: 'Version', value: '6' },
        { label: 'Payload Length', value: String((data[14 + 4] << 8) | data[14 + 5]) },
        { label: 'Next Header', value: protocolName(ipProto) },
        { label: 'Hop Limit', value: String(data[14 + 7]) },
        { label: 'Source', value: ipv6ToString(data, 14 + 8) },
        { label: 'Destination', value: ipv6ToString(data, 14 + 24) },
      ],
    });
    l4Off = 14 + 40;
  } else {
    return layers;
  }

  if ((ipProto === 6 || ipProto === 17) && data.length >= l4Off + 4) {
    const srcPort = (data[l4Off] << 8) | data[l4Off + 1];
    const dstPort = (data[l4Off + 2] << 8) | data[l4Off + 3];
    if (ipProto === 6 && data.length >= l4Off + 20) {
      layers.push({
        name: 'Transmission Control Protocol',
        fields: [
          { label: 'Source Port', value: String(srcPort) },
          { label: 'Destination Port', value: String(dstPort) },
          { label: 'Sequence Number', value: String(((data[l4Off + 4] << 24) | (data[l4Off + 5] << 16) | (data[l4Off + 6] << 8) | data[l4Off + 7]) >>> 0) },
          { label: 'Acknowledgment Number', value: String(((data[l4Off + 8] << 24) | (data[l4Off + 9] << 16) | (data[l4Off + 10] << 8) | data[l4Off + 11]) >>> 0) },
          { label: 'Header Length', value: `${(data[l4Off + 12] >> 4) * 4} bytes` },
          { label: 'Flags', value: tcpFlagsToString(data[l4Off + 13]) },
          { label: 'Window Size', value: String((data[l4Off + 14] << 8) | data[l4Off + 15]) },
          { label: 'Checksum', value: `0x${(((data[l4Off + 16] << 8) | data[l4Off + 17]) >>> 0).toString(16).padStart(4, '0')}` },
        ],
      });
    } else if (ipProto === 17 && data.length >= l4Off + 8) {
      layers.push({
        name: 'User Datagram Protocol',
        fields: [
          { label: 'Source Port', value: String(srcPort) },
          { label: 'Destination Port', value: String(dstPort) },
          { label: 'Length', value: String((data[l4Off + 4] << 8) | data[l4Off + 5]) },
          { label: 'Checksum', value: `0x${(((data[l4Off + 6] << 8) | data[l4Off + 7]) >>> 0).toString(16).padStart(4, '0')}` },
        ],
      });
    }
  } else if ((ipProto === 1 || ipProto === 58) && data.length >= l4Off + 4) {
    layers.push({
      name: ipProto === 1 ? 'Internet Control Message Protocol' : 'Internet Control Message Protocol v6',
      fields: [
        { label: 'Type', value: String(data[l4Off]) },
        { label: 'Code', value: String(data[l4Off + 1]) },
        { label: 'Checksum', value: `0x${(((data[l4Off + 2] << 8) | data[l4Off + 3]) >>> 0).toString(16).padStart(4, '0')}` },
      ],
    });
  }

  return layers;
}

// layerClass maps a decodeDetailed() layer name to a CSS class that colors
// it the same hue as its live-view row equivalent (layer-tcp matches
// proto-tcp, etc.) — see the matching CSS comment in styles.css for why the
// class needs to combine with ".layer" there rather than stand alone.
export function layerClass(name: string): string {
  if (name === 'Ethernet II') return 'layer-eth';
  if (name.startsWith('Internet Protocol')) return 'layer-ip';
  if (name.startsWith('Transmission Control')) return 'layer-tcp';
  if (name.startsWith('User Datagram')) return 'layer-udp';
  if (name.startsWith('Internet Control Message')) return 'layer-icmp';
  return '';
}
