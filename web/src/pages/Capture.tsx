import { Fragment, useEffect, useMemo, useRef, useState } from 'react';
import { api, wsURL } from '../api';
import CaptureHistory from '../components/CaptureHistory';
import CaptureSummaries from '../components/CaptureSummaries';
import TerminalFrame from '../components/TerminalFrame';
import Sparkline from '../components/Sparkline';
import PagePulse from '../components/kit/PagePulse';
import { bytesRate } from '../components/kit/format';
import { ListEmpty } from '../components/Toolbar';
import { Radio, Waves } from 'lucide-react';
import { useRoute } from '../hooks/useInvestigation';
import { decodeDetailed, decodeL3L4, hexDump, layerClass } from '../lib/packetDecode';
import { buildIPIndex, labelForIP } from '../lib/workloadAttribution';
import { bucketRates, toCSV, type ExportRow } from '../lib/captureExport';
import { loadPresets, savePresets, upsertPreset, removePreset, type CapturePreset } from '../lib/capturePresets';

type KernelFindingAlert = { node: string; signal: string; explanation?: string };

const PROTO_CLASS: Record<number, string> = { 1: 'proto-icmp', 6: 'proto-tcp', 17: 'proto-udp', 58: 'proto-icmpv6' };

type CaptureSpec = {
  node: string;
  backend?: string;
  protocol?: string;
  host?: string;
  port?: number;
  snapLen?: number;
  maxPps?: number;
  requestor?: string;
  startedAt?: string;
  expiresAt?: string;
};
type CaptureStatus = { active?: CaptureSpec[] };
type BulkResult = { node: string; ok: boolean; error?: string };

type Frame = { observedAtUnixNano: bigint; origLen: number; direction: number; family: number; protocol: number; data: Uint8Array<ArrayBuffer> };

const FRAME_HEADER_LEN = 20;
const PROTOCOL_NAMES: Record<number, string> = { 1: 'ICMP', 6: 'TCP', 17: 'UDP', 58: 'ICMPv6' };
const MAX_LIVE_ROWS = 500;

// decodeFrame mirrors internal/capture.DecodeFrame's wire format exactly —
// see that Go file's own doc comment for the byte layout both ends agree
// on (all integers little-endian).
function decodeFrame(buf: ArrayBuffer): Frame {
  const dv = new DataView(buf);
  return {
    observedAtUnixNano: dv.getBigInt64(0, true),
    origLen: dv.getUint32(8, true),
    direction: dv.getUint8(16),
    family: dv.getUint8(17),
    protocol: dv.getUint8(18),
    data: new Uint8Array(buf, FRAME_HEADER_LEN, dv.getUint32(12, true)),
  };
}

// buildPCAP assembles a classic (non-pcapng) libpcap file client-side from
// every frame received this session — mirrors internal/capture's
// WritePCAPHeader/WritePCAPRecord byte-for-byte, so the download opens
// directly in Wireshark with no server-side capture storage or export
// endpoint needed.
function buildPCAP(frames: Frame[]): Blob {
  const parts: BlobPart[] = [];
  const hdr = new DataView(new ArrayBuffer(24));
  hdr.setUint32(0, 0xa1b2c3d4, true);
  hdr.setUint16(4, 2, true);
  hdr.setUint16(6, 4, true);
  hdr.setUint32(16, 9000, true);
  hdr.setUint32(20, 1, true); // LINKTYPE_ETHERNET
  parts.push(hdr.buffer);
  for (const f of frames) {
    const rec = new DataView(new ArrayBuffer(16));
    const nanos = f.observedAtUnixNano;
    rec.setUint32(0, Number(nanos / 1_000_000_000n), true);
    rec.setUint32(4, Number((nanos % 1_000_000_000n) / 1000n), true);
    rec.setUint32(8, f.data.byteLength, true);
    rec.setUint32(12, f.origLen, true);
    parts.push(rec.buffer, f.data);
  }
  return new Blob(parts, { type: 'application/vnd.tcpdump.pcap' });
}

export default function Capture() {
  const [status, setStatus] = useState<CaptureStatus>();
  const [nodes, setNodes] = useState<string[]>([]);
  const [nodeToAdd, setNodeToAdd] = useState('');
  const [selectedNodes, setSelectedNodes] = useState<string[]>([]);
  const [backend, setBackend] = useState('');
  const [protocol, setProtocol] = useState('');
  const [host, setHost] = useState('');
  const [port, setPort] = useState('');
  const [duration, setDuration] = useState('60s');
  const [err, setErr] = useState('');
  const [live, setLive] = useState(false);
  const [watching, setWatching] = useState('');
  const [rows, setRows] = useState<Frame[]>([]);
  const [filterProtocol, setFilterProtocol] = useState('');
  const [filterDirection, setFilterDirection] = useState('');
  const [filterQuery, setFilterQuery] = useState('');
  const [filterWorkload, setFilterWorkload] = useState('');
  const [expanded, setExpanded] = useState<number | null>(null);
  const [ipIndex, setIpIndex] = useState<Map<string, string>>(new Map());
  const [presets, setPresets] = useState<CapturePreset[]>(() => loadPresets());
  const [presetName, setPresetName] = useState('');
  const [presetToLoad, setPresetToLoad] = useState('');
  const [alerts, setAlerts] = useState<KernelFindingAlert[]>([]);
  const [dismissedAlerts, setDismissedAlerts] = useState<Set<string>>(new Set());
  const wsRef = useRef<WebSocket | null>(null);
  const framesRef = useRef<Frame[]>([]);
  const route = useRoute();

  const loadStatus = () => api<CaptureStatus>('/api/v1/capture/status').then(setStatus).catch((e) => setErr(String(e)));
  useEffect(() => {
    loadStatus();
    const t = setInterval(loadStatus, 5000);
    return () => clearInterval(t);
  }, []);
  useEffect(() => {
    api<{ nodes?: { node?: string }[] }>('/api/v1/fleet')
      .then((inv) => setNodes((inv.nodes || []).map((n) => n.node || '').filter(Boolean)))
      .catch(() => {});
  }, []);
  useEffect(() => {
    type Named = { namespace: string; name: string; podIP?: string };
    Promise.all([
      api<{ items?: Named[] }>('/api/v1/pods').then((r) => r.items || []).catch(() => []),
      api<{ items?: Named[] }>('/api/v1/vms').then((r) => r.items || []).catch(() => []),
    ]).then(([pods, vms]) => setIpIndex(buildIPIndex(pods, vms)));
  }, []);
  useEffect(() => () => wsRef.current?.close(), []);
  // A "Capture on this node" link from the Congestion Map (or anywhere
  // else) pre-selects the node via the shared URL scope instead of a
  // page-specific query param, matching how the rest of the app navigates.
  useEffect(() => {
    if (route.scope.node) setSelectedNodes((prev) => (prev.includes(route.scope.node) ? prev : [route.scope.node]));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [route.scope.node]);
  // Reuses the same GET /api/v1/ebpf/kernel-network the Congestion Map
  // already polls — no new backend endpoint — to suggest a capture when a
  // node has a live critical finding, so there's evidence gathered close
  // to the moment of an incident instead of only after the fact.
  useEffect(() => {
    type KernelAlertResponse = { nodes?: { node: string; findings?: { severity: string; signal: string; explanation?: string }[] }[] };
    const load = () =>
      api<KernelAlertResponse>('/api/v1/ebpf/kernel-network?window=5m')
        .then((r) => {
          const found: KernelFindingAlert[] = [];
          for (const n of r.nodes || []) {
            for (const f of n.findings || []) {
              if (f.severity === 'critical') found.push({ node: n.node, signal: f.signal, explanation: f.explanation });
            }
          }
          setAlerts(found);
        })
        .catch(() => {});
    load();
    const t = setInterval(load, 20000);
    return () => clearInterval(t);
  }, []);

  function addNode() {
    if (nodeToAdd && !selectedNodes.includes(nodeToAdd)) setSelectedNodes((prev) => [...prev, nodeToAdd]);
    setNodeToAdd('');
  }
  function removeNode(n: string) {
    setSelectedNodes((prev) => prev.filter((x) => x !== n));
  }

  function watch(target: string) {
    wsRef.current?.close();
    framesRef.current = [];
    setRows([]);
    setErr('');
    setExpanded(null);
    setWatching(target);
    const ws = new WebSocket(wsURL(`/api/v1/vms/${encodeURIComponent(target)}/capture/ws`));
    ws.binaryType = 'arraybuffer';
    ws.onopen = () => setLive(true);
    ws.onmessage = (ev) => {
      const f = decodeFrame(ev.data as ArrayBuffer);
      framesRef.current.push(f);
      setRows((prev) => [...prev.slice(-(MAX_LIVE_ROWS - 1)), f]);
    };
    ws.onerror = () => setErr('WebSocket error');
    ws.onclose = () => setLive(false);
    wsRef.current = ws;
  }

  async function start() {
    if (selectedNodes.length === 0) { setErr('at least one node is required'); return; }
    if (!protocol && !host && !port) { setErr('at least one of protocol, host, or port is required'); return; }
    const body: Record<string, unknown> = {};
    if (backend) body.backend = backend;
    if (protocol) body.protocol = protocol;
    if (host) body.host = host;
    if (port) body.port = Number(port);
    const m = /^(\d+)([smh])$/.exec(duration.trim());
    if (m) body.durationSeconds = Number(m[1]) * { s: 1, m: 60, h: 3600 }[m[2] as 's' | 'm' | 'h'];
    try {
      if (selectedNodes.length === 1) {
        await api(`/api/v1/vms/${encodeURIComponent(selectedNodes[0])}/capture`, { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
        setErr('');
        await loadStatus();
        watch(selectedNodes[0]);
      } else {
        const res = await api<{ results?: BulkResult[] }>('/api/v1/capture/bulk', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ nodes: selectedNodes, ...body }) });
        const results = res.results || [];
        const failed = results.filter((r) => !r.ok);
        setErr(failed.length ? `${failed.length} of ${selectedNodes.length} node(s) failed to start: ${failed.map((f) => `${f.node} (${f.error})`).join('; ')}` : '');
        await loadStatus();
        const firstOK = results.find((r) => r.ok);
        if (firstOK) watch(firstOK.node);
      }
    } catch (e) { setErr(String(e)); }
  }

  async function stop(target: string) {
    try {
      await api(`/api/v1/vms/${encodeURIComponent(target)}/capture`, { method: 'DELETE' });
      await loadStatus();
      if (target === watching) { wsRef.current?.close(); }
    } catch (e) { setErr(String(e)); }
  }

  function download() {
    const blob = buildPCAP(framesRef.current);
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `netra-capture-${watching || 'session'}.pcap`;
    a.click();
    URL.revokeObjectURL(url);
  }

  function repeat(e: { node: string; backend?: string; protocol?: string; host?: string; port?: number }) {
    setSelectedNodes([e.node]);
    setBackend(e.backend || '');
    setProtocol(e.protocol || '');
    setHost(e.host || '');
    setPort(e.port ? String(e.port) : '');
  }

  function saveCurrentAsPreset() {
    const name = presetName.trim();
    if (!name) return;
    const next = upsertPreset(presets, { name, backend, protocol, host, port, duration });
    setPresets(next);
    savePresets(next);
    setPresetName('');
  }
  function applyPreset(name: string) {
    const p = presets.find((x) => x.name === name);
    if (!p) return;
    setBackend(p.backend || '');
    setProtocol(p.protocol || '');
    setHost(p.host || '');
    setPort(p.port || '');
    setDuration(p.duration || '60s');
  }
  function deletePreset(name: string) {
    const next = removePreset(presets, name);
    setPresets(next);
    savePresets(next);
    if (presetToLoad === name) setPresetToLoad('');
  }

  function downloadFile(content: string, filename: string, type: string) {
    const blob = new Blob([content], { type });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    a.click();
    URL.revokeObjectURL(url);
  }
  function exportRows(): ExportRow[] {
    return filteredIdx.map((i) => {
      const f = rows[i];
      const d = decoded[i];
      const w = workloads[i];
      return {
        time: new Date(Number(f.observedAtUnixNano / 1_000_000n)).toISOString(),
        protocol: PROTOCOL_NAMES[f.protocol] || String(f.protocol),
        direction: f.direction === 1 ? 'ingress' : 'egress',
        lengthBytes: f.origLen,
        capturedBytes: f.data.byteLength,
        srcIP: d?.srcIP, srcPort: d?.srcPort, dstIP: d?.dstIP, dstPort: d?.dstPort,
        tcpFlags: d?.tcpFlags, icmpType: d?.icmpType,
        srcWorkload: w?.src, dstWorkload: w?.dst,
      };
    });
  }
  function exportJSON() {
    downloadFile(JSON.stringify(exportRows(), null, 2), `netra-capture-${watching || 'session'}.json`, 'application/json');
  }
  function exportCSV() {
    downloadFile(toCSV(exportRows()), `netra-capture-${watching || 'session'}.csv`, 'text/csv');
  }

  function dismissAlert(node: string, signal: string) {
    setDismissedAlerts((prev) => new Set(prev).add(`${node}:${signal}`));
  }
  function startFromAlert(node: string) {
    setSelectedNodes([node]);
    if (!protocol && !host && !port) setProtocol('tcp');
  }

  const active = status?.active || [];
  const decoded = useMemo(() => rows.map((f) => decodeL3L4(f.data)), [rows]);
  const workloads = useMemo(
    () => decoded.map((d) => ({ src: labelForIP(ipIndex, d?.srcIP), dst: labelForIP(ipIndex, d?.dstIP) })),
    [decoded, ipIndex],
  );
  const filteredIdx = useMemo(() => {
    const q = filterQuery.trim().toLowerCase();
    const wq = filterWorkload.trim().toLowerCase();
    return rows
      .map((_, i) => i)
      .filter((i) => {
        const f = rows[i];
        if (filterProtocol && (PROTOCOL_NAMES[f.protocol] || String(f.protocol)) !== filterProtocol) return false;
        if (filterDirection && String(f.direction) !== filterDirection) return false;
        if (q) {
          const hay = `${decoded[i]?.summary || ''} ${PROTOCOL_NAMES[f.protocol] || ''}`.toLowerCase();
          if (!hay.includes(q)) return false;
        }
        if (wq) {
          const hay = `${workloads[i]?.src || ''} ${workloads[i]?.dst || ''}`.toLowerCase();
          if (!hay.includes(wq)) return false;
        }
        return true;
      });
  }, [rows, decoded, workloads, filterProtocol, filterDirection, filterQuery, filterWorkload]);
  const rates = useMemo(
    () => bucketRates(rows.map((f) => ({ atMs: Number(f.observedAtUnixNano / 1_000_000n), bytes: f.data.byteLength })), 30),
    [rows],
  );
  const visibleAlerts = alerts.filter((a) => !dismissedAlerts.has(`${a.node}:${a.signal}`));

  return (
    <div className="grid">
      <PagePulse
        headline={active.length ? `Capturing on ${active.length} node${active.length === 1 ? '' : 's'}${watching ? ` · watching ${watching}` : ''}.` : 'No capture running.'}
        tone={active.length ? 'warn' : undefined}
        tick={status}
        error={err || undefined}
        figures={[
          { label: 'active sessions', value: status ? active.length : undefined, tone: active.length ? 'warn' : undefined },
          { label: 'packets streamed', value: rows.length },
          { label: 'packets / s', value: rates.packetsPerSec.length ? rates.packetsPerSec[rates.packetsPerSec.length - 1] : live ? 0 : undefined, series: rates.packetsPerSec },
          { label: 'throughput', value: rates.bytesPerSec.length ? rates.bytesPerSec[rates.bytesPerSec.length - 1] : live ? 0 : undefined, format: bytesRate, series: rates.bytesPerSec },
        ]}
      />
      {err && <section className="card span3"><p className="warning">{err}</p></section>}
      {active.length > 0 && (
        <section className="card span3">
          <p className="warning">Capturing full packet bytes on {active.length} node{active.length === 1 ? '' : 's'} — captured traffic may contain sensitive application data (auth headers, tokens, cookies).</p>
        </section>
      )}

      {visibleAlerts.length > 0 && (
        <section className="card span3">
          <p className="eyebrow">SUGGESTED CAPTURE</p>
          <h2 className="card-title">Live critical finding{visibleAlerts.length === 1 ? '' : 's'} on the Congestion Map</h2>
          <div className="list">
            {visibleAlerts.map((a) => (
              <div className="agent wide" key={`${a.node}:${a.signal}`}>
                <b>{a.node}</b>
                <span className="severity-badge critical">critical</span> <span>{a.signal}</span>
                {a.explanation && <small>{a.explanation}</small>}
                <div className="toolbar">
                  <button className="primary" onClick={() => startFromAlert(a.node)}>Start a capture on {a.node}</button>
                  <button className="btn-secondary" onClick={() => dismissAlert(a.node, a.signal)}>Dismiss</button>
                </div>
              </div>
            ))}
          </div>
        </section>
      )}

      <section className="card span3">
        <p className="eyebrow">PACKET CAPTURE</p>
        <h2 className="card-title">Start a capture</h2>
        <p>
          Full packet bytes by default, filtered and time-bounded (max 5 minutes).{' '}
          {backend === 'afpacket'
            ? 'AF_PACKET mode: a pure userspace raw-socket capture, no eBPF object dependency.'
            : 'Standalone, fail-open eBPF observer — never affects the datapath verdict.'}{' '}
          Add more than one node to start a bulk capture across all of them at once.
        </p>
        <div className="toolbar">
          <label>
            Node{' '}
            {nodes.length > 0 ? (
              <select value={nodeToAdd} onChange={(e) => setNodeToAdd(e.target.value)}>
                <option value="">select…</option>
                {nodes.map((n) => <option key={n} value={n}>{n}</option>)}
              </select>
            ) : (
              <input value={nodeToAdd} onChange={(e) => setNodeToAdd(e.target.value)} placeholder="node-1" />
            )}
          </label>
          <button className="btn-secondary" onClick={addNode} disabled={!nodeToAdd}>Add node</button>
          <label>
            Backend{' '}
            <select value={backend} onChange={(e) => setBackend(e.target.value)}>
              <option value="">eBPF (default)</option>
              <option value="afpacket">AF_PACKET</option>
            </select>
          </label>
          <label>
            Protocol{' '}
            <select value={protocol} onChange={(e) => setProtocol(e.target.value)}>
              <option value="">any</option>
              <option value="tcp">tcp</option>
              <option value="udp">udp</option>
              <option value="icmp">icmp</option>
              <option value="icmpv6">icmpv6</option>
            </select>
          </label>
          <label>Host <input value={host} onChange={(e) => setHost(e.target.value)} placeholder="10.0.0.5" /></label>
          <label>Port <input value={port} onChange={(e) => setPort(e.target.value)} placeholder="443" /></label>
          <label>Duration <input value={duration} onChange={(e) => setDuration(e.target.value)} placeholder="60s" /></label>
          <button className="primary" onClick={start}>Start capture{selectedNodes.length > 1 ? ` (${selectedNodes.length} nodes)` : ''}</button>
        </div>
        <div className="chips">
          {selectedNodes.length === 0 && <span>No nodes selected yet.</span>}
          {selectedNodes.map((n) => <button key={n} aria-label={`Remove ${n}`} onClick={() => removeNode(n)}>{n} ×</button>)}
        </div>
        <div className="toolbar">
          <label>Preset name <input value={presetName} onChange={(e) => setPresetName(e.target.value)} placeholder="ssh, dns, …" /></label>
          <button className="btn-secondary" onClick={saveCurrentAsPreset} disabled={!presetName.trim()}>Save current filters as preset</button>
          {presets.length > 0 && (
            <>
              <label>Load preset{' '}
                <select value={presetToLoad} onChange={(e) => { setPresetToLoad(e.target.value); if (e.target.value) applyPreset(e.target.value); }}>
                  <option value="">select…</option>
                  {presets.map((p) => <option key={p.name} value={p.name}>{p.name}</option>)}
                </select>
              </label>
              <button className="btn-secondary" disabled={!presetToLoad} onClick={() => deletePreset(presetToLoad)}>Delete preset</button>
            </>
          )}
        </div>
      </section>

      <section className="card span3">
        <p className="eyebrow">ACTIVE SESSIONS</p>
        <h2 className="card-title">{active.length} active</h2>
        <div className="list">
          {active.length === 0 && <ListEmpty compact icon={Radio} title="No capture sessions running." description="Pick a node and filters above, then start a time-bounded capture." />}
          {active.map((c) => (
            <div className="agent wide" key={c.node}>
              <b>{c.node}</b>
              <span>{c.protocol || 'any'}{c.host ? ` · ${c.host}` : ''}{c.port ? `:${c.port}` : ''}{c.backend === 'afpacket' ? ' · AF_PACKET' : ''}</span>
              <small>started by {c.requestor || 'unknown'}, expires {c.expiresAt ? new Date(c.expiresAt).toLocaleTimeString() : '—'}</small>
              <div className="toolbar">
                <button className={watching === c.node ? 'primary' : 'btn-secondary'} onClick={() => watch(c.node)}>Watch</button>
                <button className="btn-secondary" onClick={() => stop(c.node)}>Stop</button>
              </div>
            </div>
          ))}
        </div>
      </section>

      <section className="card span3">
        <p className="eyebrow">LIVE VIEW</p>
        <h2 className="card-title">{live ? 'Connected' : 'Not connected'}{watching ? ` · ${watching}` : ''} · {filteredIdx.length} of {rows.length} packets shown (last {MAX_LIVE_ROWS})</h2>
        <p>Click Watch on an active session, or start one above, to stream packets here as they're captured. Endpoints matching a known pod or VM IP are labeled automatically — process/PID attribution isn't available (would need a kernel-side capture change, not client-side).</p>
        {active.length > 1 && (
          <div className="toolbar">
            <span>Switch node:</span>
            {active.map((c) => <button key={c.node} className={watching === c.node ? 'primary' : 'btn-secondary'} onClick={() => watch(c.node)}>{c.node}</button>)}
          </div>
        )}
        {rates.packetsPerSec.length >= 2 && (
          <p className="sparkline-row">
            <Sparkline values={rates.packetsPerSec} />
            <small className="stage-cell-gloss">packets/sec, last {rates.packetsPerSec.length}s</small>
            <Sparkline values={rates.bytesPerSec} />
            <small className="stage-cell-gloss">bytes/sec, last {rates.bytesPerSec.length}s</small>
          </p>
        )}
        <div className="toolbar">
          <label>Protocol{' '}
            <select value={filterProtocol} onChange={(e) => setFilterProtocol(e.target.value)}>
              <option value="">any</option>
              {Object.values(PROTOCOL_NAMES).map((p) => <option key={p} value={p}>{p}</option>)}
            </select>
          </label>
          <label>Direction{' '}
            <select value={filterDirection} onChange={(e) => setFilterDirection(e.target.value)}>
              <option value="">any</option>
              <option value="1">ingress</option>
              <option value="0">egress</option>
            </select>
          </label>
          <label>Search <input value={filterQuery} onChange={(e) => setFilterQuery(e.target.value)} placeholder="10.0.0.5:443" /></label>
          <label>Pod / VM <input value={filterWorkload} onChange={(e) => setFilterWorkload(e.target.value)} placeholder="namespace/name" /></label>
          <button className="btn-secondary" disabled={framesRef.current.length === 0} onClick={download}>Download .pcap ({framesRef.current.length} packets)</button>
          <button className="btn-secondary" disabled={filteredIdx.length === 0} onClick={exportJSON}>Export JSON</button>
          <button className="btn-secondary" disabled={filteredIdx.length === 0} onClick={exportCSV}>Export CSV</button>
        </div>
        {rows.length === 0 && <ListEmpty compact icon={Waves} title="No packets yet." description="Click Watch on an active session to stream its packets here." />}
        {rows.length > 0 && filteredIdx.length === 0 && <p className="empty-state">No packets match this filter.</p>}
        {rows.length > 0 && filteredIdx.length > 0 && (
          <TerminalFrame title={`capture · ${watching || 'no session'}`}>
            <div className="flowhead capture">
              <span>TIME</span>
              <span>PROTO</span>
              <span>DIR</span>
              <span>LEN</span>
              <span>ENDPOINTS</span>
            </div>
            {filteredIdx.slice().reverse().map((i) => {
              const f = rows[i];
              const d = decoded[i];
              const w = workloads[i];
              const captured = f.origLen !== f.data.byteLength ? ` (${f.data.byteLength}B captured)` : '';
              const workloadTags = [w?.src, w?.dst].filter(Boolean).join(' / ');
              return (
                <Fragment key={i}>
                  <div className="flowrow capture" onClick={() => setExpanded(expanded === i ? null : i)} role="button" tabIndex={0}>
                    <span>{new Date(Number(f.observedAtUnixNano / 1_000_000n)).toLocaleTimeString()}</span>
                    <span className={PROTO_CLASS[f.protocol] || 'proto-other'}>{PROTOCOL_NAMES[f.protocol] || f.protocol}</span>
                    <span className={f.direction === 1 ? 'dir-ingress' : 'dir-egress'}>{f.direction === 1 ? '← in' : 'out →'}</span>
                    <span>{f.origLen}B{captured}</span>
                    <span>{d ? d.summary : '—'}{workloadTags ? ` · ${workloadTags}` : ''}</span>
                  </div>
                  {expanded === i && (
                    <div className="packetdetail">
                      {(w?.src || w?.dst) && (
                        <div className="layer layer-workload">
                          <b>Workload Attribution</b>
                          {w?.src && <div><span>Source</span><span>{w.src}</span></div>}
                          {w?.dst && <div><span>Destination</span><span>{w.dst}</span></div>}
                        </div>
                      )}
                      {decodeDetailed(f.data).map((layer) => (
                        <div className={`layer ${layerClass(layer.name)}`} key={layer.name}>
                          <b>{layer.name}</b>
                          {layer.fields.map((field) => (
                            <div key={field.label}><span>{field.label}</span><span>{field.value}</span></div>
                          ))}
                        </div>
                      ))}
                      <pre>{hexDump(f.data, 128)}</pre>
                    </div>
                  )}
                </Fragment>
              );
            })}
          </TerminalFrame>
        )}
      </section>

      <CaptureSummaries />
      <CaptureHistory onRepeat={repeat} />
    </div>
  );
}
