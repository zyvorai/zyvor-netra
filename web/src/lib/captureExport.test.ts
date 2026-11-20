import { describe, it, expect } from 'vitest';
import { toCSV, bucketRates, type ExportRow } from './captureExport';

describe('toCSV', () => {
  it('renders a header and one row per entry', () => {
    const rows: ExportRow[] = [{ time: '12:00:00', protocol: 'TCP', direction: 'ingress', lengthBytes: 66, capturedBytes: 66, srcIP: '10.0.0.5', srcPort: 443, dstIP: '10.0.0.9', dstPort: 51413, tcpFlags: 'SYN,ACK' }];
    const csv = toCSV(rows);
    const lines = csv.split('\n');
    expect(lines[0]).toBe('time,protocol,direction,lengthBytes,capturedBytes,srcIP,srcPort,dstIP,dstPort,tcpFlags,icmpType,srcWorkload,dstWorkload');
    expect(lines[1]).toBe('12:00:00,TCP,ingress,66,66,10.0.0.5,443,10.0.0.9,51413,"SYN,ACK",,,');
  });

  it('quotes and escapes fields containing commas or quotes', () => {
    const rows: ExportRow[] = [{ time: 't', protocol: 'TCP', direction: 'egress', lengthBytes: 1, capturedBytes: 1, srcWorkload: 'pod ns/name, "weird"' }];
    expect(toCSV(rows).split('\n')[1]).toContain('"pod ns/name, ""weird"""');
  });

  it('renders only the header for an empty input', () => {
    expect(toCSV([]).split('\n')).toHaveLength(1);
  });
});

describe('bucketRates', () => {
  it('buckets frames into 1-second windows ending at the latest frame', () => {
    const frames = [
      { atMs: 1000, bytes: 100 },
      { atMs: 1500, bytes: 50 },
      { atMs: 2000, bytes: 200 },
    ];
    const { packetsPerSec, bytesPerSec } = bucketRates(frames, 2);
    expect(packetsPerSec).toEqual([2, 1]);
    expect(bytesPerSec).toEqual([150, 200]);
  });

  it('returns empty arrays for no frames', () => {
    expect(bucketRates([])).toEqual({ packetsPerSec: [], bytesPerSec: [] });
  });

  it('drops frames older than the window', () => {
    const frames = [{ atMs: 0, bytes: 999 }, { atMs: 5000, bytes: 10 }];
    const { packetsPerSec, bytesPerSec } = bucketRates(frames, 2);
    expect(packetsPerSec).toEqual([0, 1]);
    expect(bytesPerSec).toEqual([0, 10]);
  });
});
