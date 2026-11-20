// Pure helpers for the Capture page's "export decoded view" and
// "live throughput" features — kept separate from packetDecode.ts (protocol
// parsing) and Capture.tsx (React/state) so both are independently testable.

export type ExportRow = {
  time: string;
  protocol: string;
  direction: string;
  lengthBytes: number;
  capturedBytes: number;
  srcIP?: string;
  srcPort?: number;
  dstIP?: string;
  dstPort?: number;
  tcpFlags?: string;
  icmpType?: number;
  srcWorkload?: string;
  dstWorkload?: string;
};

const CSV_COLUMNS: (keyof ExportRow)[] = [
  'time', 'protocol', 'direction', 'lengthBytes', 'capturedBytes',
  'srcIP', 'srcPort', 'dstIP', 'dstPort', 'tcpFlags', 'icmpType', 'srcWorkload', 'dstWorkload',
];

function csvCell(v: unknown): string {
  const s = v === undefined || v === null ? '' : String(v);
  return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
}

export function toCSV(rows: ExportRow[]): string {
  const lines = rows.map((r) => CSV_COLUMNS.map((c) => csvCell(r[c])).join(','));
  return [CSV_COLUMNS.join(','), ...lines].join('\n');
}

// bucketRates groups frames into 1-second buckets ending at the latest
// frame's own observed timestamp (not client receipt time), for a
// packets/sec and bytes/sec Sparkline over the trailing windowSeconds.
export function bucketRates(frames: { atMs: number; bytes: number }[], windowSeconds = 30): { packetsPerSec: number[]; bytesPerSec: number[] } {
  if (frames.length === 0) return { packetsPerSec: [], bytesPerSec: [] };
  const nowSec = Math.floor(frames[frames.length - 1].atMs / 1000);
  const startSec = nowSec - windowSeconds + 1;
  const packets = new Array(windowSeconds).fill(0);
  const bytes = new Array(windowSeconds).fill(0);
  for (const f of frames) {
    const idx = Math.floor(f.atMs / 1000) - startSec;
    if (idx >= 0 && idx < windowSeconds) {
      packets[idx] += 1;
      bytes[idx] += f.bytes;
    }
  }
  return { packetsPerSec: packets, bytesPerSec: bytes };
}
