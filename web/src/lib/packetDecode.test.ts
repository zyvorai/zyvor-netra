import { describe, it, expect } from 'vitest';
import { decodeL3L4, decodeDetailed, hexDump, layerClass } from './packetDecode';

function ethIPv4TCP(srcIP: [number, number, number, number], dstIP: [number, number, number, number], srcPort: number, dstPort: number, flags: number): Uint8Array {
  const buf = new Uint8Array(14 + 20 + 20);
  buf[12] = 0x08; buf[13] = 0x00; // EtherType IPv4
  buf[14] = 0x45; // version 4, IHL 5
  buf[14 + 9] = 6; // TCP
  buf.set(srcIP, 14 + 12);
  buf.set(dstIP, 14 + 16);
  const tcpOff = 14 + 20;
  buf[tcpOff] = srcPort >> 8; buf[tcpOff + 1] = srcPort & 0xff;
  buf[tcpOff + 2] = dstPort >> 8; buf[tcpOff + 3] = dstPort & 0xff;
  buf[tcpOff + 13] = flags;
  return buf;
}

function ethIPv4UDP(srcIP: [number, number, number, number], dstIP: [number, number, number, number], srcPort: number, dstPort: number): Uint8Array {
  const buf = new Uint8Array(14 + 20 + 8);
  buf[12] = 0x08; buf[13] = 0x00;
  buf[14] = 0x45;
  buf[14 + 9] = 17; // UDP
  buf.set(srcIP, 14 + 12);
  buf.set(dstIP, 14 + 16);
  const udpOff = 14 + 20;
  buf[udpOff] = srcPort >> 8; buf[udpOff + 1] = srcPort & 0xff;
  buf[udpOff + 2] = dstPort >> 8; buf[udpOff + 3] = dstPort & 0xff;
  return buf;
}

describe('decodeL3L4', () => {
  it('decodes an IPv4 TCP SYN', () => {
    const d = decodeL3L4(ethIPv4TCP([10, 0, 0, 5], [10, 0, 0, 9], 51413, 443, 0x02));
    expect(d).not.toBeNull();
    expect(d!.srcIP).toBe('10.0.0.5');
    expect(d!.dstIP).toBe('10.0.0.9');
    expect(d!.srcPort).toBe(51413);
    expect(d!.dstPort).toBe(443);
    expect(d!.tcpFlags).toBe('SYN');
    expect(d!.summary).toContain('10.0.0.5:51413 → 10.0.0.9:443');
  });

  it('decodes combined TCP flags', () => {
    const d = decodeL3L4(ethIPv4TCP([1, 1, 1, 1], [2, 2, 2, 2], 1, 2, 0x12)); // SYN+ACK
    expect(d!.tcpFlags).toBe('SYN,ACK');
  });

  it('decodes an IPv4 UDP packet', () => {
    const d = decodeL3L4(ethIPv4UDP([10, 0, 0, 5], [8, 8, 8, 8], 53000, 53));
    expect(d).not.toBeNull();
    expect(d!.srcPort).toBe(53000);
    expect(d!.dstPort).toBe(53);
    expect(d!.tcpFlags).toBeUndefined();
  });

  it('returns null for a truncated or unknown-ethertype frame', () => {
    expect(decodeL3L4(new Uint8Array(4))).toBeNull();
    const arp = new Uint8Array(14);
    arp[12] = 0x08; arp[13] = 0x06; // ARP
    expect(decodeL3L4(arp)).toBeNull();
  });
});

describe('decodeDetailed', () => {
  it('breaks an IPv4 TCP frame into Ethernet/IP/TCP layers', () => {
    const layers = decodeDetailed(ethIPv4TCP([10, 0, 0, 5], [10, 0, 0, 9], 51413, 443, 0x12));
    const names = layers.map((l) => l.name);
    expect(names).toEqual(['Frame', 'Ethernet II', 'Internet Protocol Version 4', 'Transmission Control Protocol']);
    const ip = layers.find((l) => l.name === 'Internet Protocol Version 4')!;
    expect(ip.fields).toContainEqual({ label: 'Source', value: '10.0.0.5' });
    expect(ip.fields).toContainEqual({ label: 'Destination', value: '10.0.0.9' });
    const tcp = layers.find((l) => l.name === 'Transmission Control Protocol')!;
    expect(tcp.fields).toContainEqual({ label: 'Source Port', value: '51413' });
    expect(tcp.fields).toContainEqual({ label: 'Flags', value: 'SYN,ACK' });
  });

  it('breaks an IPv4 UDP frame into Ethernet/IP/UDP layers', () => {
    const layers = decodeDetailed(ethIPv4UDP([10, 0, 0, 5], [8, 8, 8, 8], 53000, 53));
    expect(layers.map((l) => l.name)).toEqual(['Frame', 'Ethernet II', 'Internet Protocol Version 4', 'User Datagram Protocol']);
    const udp = layers.find((l) => l.name === 'User Datagram Protocol')!;
    expect(udp.fields).toContainEqual({ label: 'Destination Port', value: '53' });
  });

  it('stops at Frame/Ethernet for a truncated or unknown-ethertype frame', () => {
    expect(decodeDetailed(new Uint8Array(4)).map((l) => l.name)).toEqual(['Frame']);
    const arp = new Uint8Array(14);
    arp[12] = 0x08; arp[13] = 0x06;
    expect(decodeDetailed(arp).map((l) => l.name)).toEqual(['Frame', 'Ethernet II']);
  });
});

describe('hexDump', () => {
  it('renders bytes as lowercase space-separated hex, capped at max', () => {
    expect(hexDump(new Uint8Array([0, 255, 16]))).toBe('00 ff 10');
    expect(hexDump(new Uint8Array(10).fill(1), 3).split(' ')).toHaveLength(3);
  });
});

describe('layerClass', () => {
  it('maps known layer names to their color class', () => {
    expect(layerClass('Ethernet II')).toBe('layer-eth');
    expect(layerClass('Internet Protocol Version 4')).toBe('layer-ip');
    expect(layerClass('Internet Protocol Version 6')).toBe('layer-ip');
    expect(layerClass('Transmission Control Protocol')).toBe('layer-tcp');
    expect(layerClass('User Datagram Protocol')).toBe('layer-udp');
    expect(layerClass('Internet Control Message Protocol')).toBe('layer-icmp');
    expect(layerClass('Internet Control Message Protocol v6')).toBe('layer-icmp');
  });

  it('returns empty string for an unrecognized layer name', () => {
    expect(layerClass('Frame')).toBe('');
    expect(layerClass('Workload Attribution')).toBe('');
  });
});
