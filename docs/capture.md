# Packet Capture

Netra can start a filtered, time-bounded packet capture on one node and stream it live to the dashboard (or `netractl`/MCP), with a client-side `.pcap` download for Wireshark. As of v0.27.7x, an operator chooses which capture **backend** runs the session: eBPF (the default, in-kernel) or AF_PACKET (pure userspace, no BPF object dependency).

## Backends

| | eBPF (default) | AF_PACKET |
|---|---|---|
| Mechanism | `bpf/netra_capture.c` — a standalone, fail-open TCX observer, attached alongside the main datapath | A raw `AF_PACKET`/`SOCK_RAW` socket per interface (`internal/afcapture`), no BPF program at all |
| Filtering | In-kernel, via the `capture_spec` map's own field matching | In-kernel, via a classic-BPF (cBPF) filter assembled at runtime and attached with `SO_ATTACH_FILTER` — a completely different, much older mechanism than netra's eBPF, needing no clang/BPF toolchain |
| Rate limiting | In-kernel (`capture_rate` map, checked *before* a ringbuf reservation) | Userspace (checked *after* the kernel has already delivered a filter-matching packet to the process) |
| Snaplen | In-kernel ringbuf reservation + BPF-side clamp | In-kernel via the cBPF filter's own return-length truncation, plus a defensive second clamp in the read loop |
| Requires | The `netra_capture.o` BPF object loaded and pinned maps under `/sys/fs/bpf` (gated by `NETRA_CAPTURE=auto\|off\|required`) | Nothing beyond what the agent pod already has (`CAP_NET_RAW`, already covered by the DaemonSet's existing `privileged: true`) |
| Direction | `DIR_INGRESS`/`DIR_EGRESS` from the TC hook position | Decoded from the raw socket's `PACKET_OUTGOING` vs everything-else signal (`unix.SockaddrLinklayer.Pkttype`) |

Both backends produce the exact same wire format (`internal/capture.Frame`) streamed to the controller and browser — the live-view, `.pcap` download, and relay code have no idea which backend is running a given session.

## Choosing a backend

- **Default to eBPF.** It's the more mature, higher-fidelity path: in-kernel rate limiting means a busy, loosely-filtered interface never costs a userspace copy for packets over the PPS cap, unlike AF_PACKET where every filter-matching packet has already cost one syscall round-trip and copy before the userspace limiter gets a chance to drop it.
- **Pick AF_PACKET** when the eBPF capture object genuinely can't attach on a node (e.g. `NETRA_CAPTURE=off`, a load failure, an older/incompatible kernel), or as a deliberate lower-dependency choice — it needs no `bpffs` mount and no BPF toolchain in the build image.
- An explicit backend request that the target node can't actually provide (no `CAP_NET_RAW` for AF_PACKET, no BPF object for eBPF) **fails loudly** rather than silently falling back to the other one — see below.

## API / CLI / MCP

```text
PUT /api/v1/vms/{node}/capture
  {"backend": "afpacket", "protocol": "tcp", "host": "10.0.0.5", "durationSeconds": 60}

netractl capture start node-1 --backend afpacket --protocol tcp --host 10.0.0.5
```

`backend` is optional everywhere (CLI, MCP, API) and defaults to `"ebpf"` — every existing caller that predates this field keeps working unchanged. `GET /api/v1/capture/status` and the MCP `netra_capture_status` tool report which backend each active session is using. MCP `netra_capture_start` (mutating, gated by `NETRA_MCP_ALLOW_MUTATIONS`) accepts the same `backend` field.

Like the eBPF path, an AF_PACKET request still requires at least one of `protocol`/`host`/`port` — unfiltered whole-interface captures are refused for both backends identically, since a promiscuous raw socket has the same blast radius as the in-kernel observer (it sees all host-visible traffic on the bound interfaces once promiscuous mode is enabled, which AF_PACKET capture always does — needed because the agent runs `hostNetwork: true` and a raw socket, unlike a TC hook, doesn't see other pods' traffic by default).

## Failure behavior

When a session explicitly requests a backend the node can't provide (an AF_PACKET `CAP_NET_RAW` probe failure, or an eBPF `capture_spec` map that isn't attached), the agent does not silently fall back to the other backend or do nothing — it records the failure and surfaces it the same way a missing fast-path map is already surfaced: folded into `AgentReport.MissingMaps` (e.g. `"afpacket:CAP_NET_RAW"`, `"ebpf:capture_spec map unavailable"`), visible on the node's health data. This reuses the existing node-health channel rather than adding a second one for what's fundamentally the same "requested capability unavailable on this node" category.

## Dashboard (Investigate → Capture)

Everything below is client-side on top of the API/wire format above — none of it requires a backend change to add, since every buffered frame already carries full Ethernet-through-L4 bytes.

- **History.** Ended sessions (metadata only — node, protocol/host/port, backend, start/end time, requestor, stop reason — never packet bytes) are recorded server-side (`GET /api/v1/capture/history`) and persisted the same way the audit log is, so they survive a controller restart. A "Repeat" button on each row pre-fills the start-capture form. Auto-capture rows show an **Auto** badge; when a PCAP was recorded, a **Download** control hits `GET /api/v1/capture/artifacts/{id}`.
- **Live inspection.** The live view is a macOS-terminal-styled feed (dark background, traffic-light title bar) with each row color-coded by protocol (TCP/UDP/ICMP/ICMPv6) and direction, plus a filter/search toolbar (protocol, direction, free text, pod/VM). Clicking a row expands a Wireshark-style layered breakdown (Ethernet II / IPv4 or IPv6 / TCP or UDP or ICMP, each its own color) plus a hex dump — all decoded client-side from bytes already in the browser, no new wire format.
- **Workload attribution.** A captured packet's src/dst IP is matched against `GET /api/v1/pods` and `GET /api/v1/vms` (both already expose `podIP`) to label endpoints `pod ns/name` / `vm ns/name`, filterable via the "Pod / VM" field. This is IP-based only — **there is no process/PID attribution**, since that would require `bpf/netra_capture.c` itself to record cgroup/PID context at capture time, a kernel-side change distinct from anything documented above.
- **Multi-node.** Adding more than one node before starting a capture calls `POST /api/v1/capture/bulk` instead of the single-node `PUT`, starting the same filtered capture on every selected node independently (capture is already a per-node, pull-based agent primitive, so this needs no new coordination) and reporting per-node success/failure.
- **Live throughput, presets, export.** A packets/sec and bytes/sec sparkline is computed from the buffered frames' own timestamps. Named filter presets (`{backend, protocol, host, port, duration}`) persist to the browser's `localStorage`. The currently-filtered decoded rows export to `.json`/`.csv` alongside the existing `.pcap` download.
- **Congestion Map integration.** Each Congestion Map per-node finding has a "Capture on {node}" button that pre-selects that node on this page. Separately, this page polls the same `GET /api/v1/ebpf/kernel-network` endpoint the Congestion Map uses and shows a dismissible "Suggested capture" banner when a node has a live critical finding — evidence gathered close to the moment of an incident, not only after.

## Auto-capture on heavy load / packet drops

GA and on by default (`NETRA_AUTO_CAPTURE=true` / Helm
`alerting.autoCapture.enabled`). Set `enabled: false` to disable.
When enabled, the alert poller automatically starts a **filtered**,
time-bounded capture on critical drop/congestion signals:

| Trigger | Source / kind |
|---------|----------------|
| Congestion Map critical finding | `kerneldiag` / layer |
| Kernel or policy drop-rate spike (critical) | `dropdiag-baseline` / `kernel-drop-spike` or `policy-drop-spike` |
| Softnet drops at critical (≥1000) | `dropdiag` / `softnet-drop` |

| Env / Helm | Default | Notes |
|---|---|---|
| `NETRA_AUTO_CAPTURE` / `alerting.autoCapture.enabled` | on (GA) | set `false` to disable; PCAPs may include cleartext |
| `NETRA_AUTO_CAPTURE_DURATION` / `.duration` | `60s` | max 5m |
| `NETRA_AUTO_CAPTURE_COOLDOWN` / `.cooldown` | `10m` | per-node |
| `NETRA_AUTO_CAPTURE_PROTOCOL` / `.protocol` | `tcp` | fallback filter; policy spikes may enrich host/port from the top `PolicyDropStat` |
| `NETRA_AUTO_CAPTURE_BACKEND` / `.backend` | `ebpf` | or `afpacket` (useful without the node agent / eBPF capture object) |
| `NETRA_AUTO_CAPTURE_MAX_PPS` / `.maxPps` | `1000` | |
| `NETRA_AUTO_CAPTURE_MAX_CONCURRENT` / `.maxConcurrent` | `5` | |
| `NETRA_AUTO_CAPTURE_DIR` / `.dir` | `/var/lib/netra/auto-capture` | PCAP directory (PVC path when persistence is on; emptyDir when not) |
| `NETRA_AUTO_CAPTURE_MAX_ARTIFACTS` / `.maxArtifacts` | `50` | prune oldest |
| `NETRA_AUTO_CAPTURE_MAX_TOTAL_MB` / `.maxTotalMb` | `1024` | |
| `NETRA_AUTO_CAPTURE_MAX_SESSION_MB` / `.maxSessionMb` | `50` | stop writing beyond this |

Requestor is tagged `auto-capture:{source}/{kind}` in the audit log and
capture history (UI shows an **Auto** badge). Auto-capture can run even when
no notify channels are configured — the poller still evaluates findings when
`NETRA_AUTO_CAPTURE=true`.

Frames for auto-capture sessions are written to classic PCAP files under
`NETRA_AUTO_CAPTURE_DIR`, retained with count/size caps, and listed on
`GET /api/v1/capture/history` with `artifactId` / `artifactFrames` /
`artifactBytes`. Download: `GET /api/v1/capture/artifacts/{id}` (UI **Download**
badge). Empty (header-only) PCAPs are discarded on finalize, and the sibling
context file is discarded with them.

The same moment also freezes a drop-incident JSON beside the PCAP
(`{id}.context.json`). It records which node (name, hostname, kernel),
whether CPU or memory was hot on the last agent sample, the top workloads
by CPU and by memory, comm-only host processes (pid, CPU%, RSS — no
argv/cmdline), policy-drop process attribution when the drop was egress
TCP, and the softnet, qdisc, and kernel-drop counters already on that
report. Download: `GET /api/v1/capture/artifacts/{id}/context` (UI
**Context** when `contextAvailable` is set on the history row). This is
not a Red Hat sosreport: no `dmesg`, journal, or package inventory.
Walkthrough: [tutorials/drop-incident-context.md](tutorials/drop-incident-context.md).

A notify event (`source=auto-capture`, `kind=started`) is published when a
session begins (delivered through configured alert channels when present).

### CI / local smoke (iperf3 + veth)

`scripts/ci-auto-capture-veth.sh` (Linux, **root**) proves the path without
the full node agent:

1. Creates a veth pair with the peer in a dedicated netns (same-netns pairs
   are short-circuited by the local stack and never appear on AF_PACKET).
2. Starts `netrad` with `NETRA_AUTO_CAPTURE=true` and
   `NETRA_AUTO_CAPTURE_BACKEND=afpacket`.
3. POSTs a synthetic agent report with `softnetDropped ≥ 1000` (reliable
   trigger; real softnet counters are too flaky under CI load alone). The
   same report carries this host's hostname/kernel and the live `iperf3`
   server's pid and comm from `/proc` (no cmdline).
4. Runs `cmd/netra-ci-feeder` to stream AF_PACKET frames from the veth into
   `/api/v1/agents/capture/stream`, while `iperf3` generates TCP across the
   pair.
5. Asserts a non-empty classic PCAP under the artifact dir, a history
   entry with `artifactId` + `artifactFrames > 0` + `contextAvailable`,
   and `GET /api/v1/capture/artifacts/{id}/context` naming that node and
   the `iperf3` process.

GitHub Actions job: `auto-capture-veth` in `.github/workflows/ci.yml`.

```bash
# On a Linux host with go, iperf3, iproute2, curl, python3:
sudo ./scripts/ci-auto-capture-veth.sh
# Optional: CONTROLLER_PORT=31970 CAPTURE_DURATION=12s sudo -E ./scripts/ci-auto-capture-veth.sh
```

### Lab, 2026-09-18 (`NLDW4-4-16-36`)

Host `NLDW4-4-16-36`. Three back-to-back runs of
`sudo CONTROLLER_PORT=31970 ./scripts/ci-auto-capture-veth.sh`. Each wrote a
PCAP and a sibling context file. History `contextAvailable` was true every
time. The context named node `ci-veth`, hostname `NLDW4-4-16-36`, and the
live `iperf3` pid (no cmdline).

| Run | Frames | PCAP bytes | iperf3 pid | Result |
|---|---|---|---|---|
| 1 | 775 | 152764 | 3225210 | pass |
| 2 | 754 | 151232 | 3227934 | pass |
| 3 | 763 | 151970 | 3230303 | pass |

For manual traffic against a live capture (not CI), see
`scripts/iperf3-traffic-gen.sh`.

Related: always-on JA3/JA4 datapath smoke (`scripts/ci-tlsfp-smoke.sh`,
GitHub job `tlsfp-smoke`) also uses **iperf3** for background TCP while
**openssl** generates ClientHellos — see [`tls-fingerprints.md`](tls-fingerprints.md).

**HA note:** artifact files are local to the leader process unless the
directory sits on shared RWX storage alongside the state file.

## v1 scope notes

- AF_PACKET's cBPF filter mirrors `bpf/netra_capture.c`'s `spec_matches()` filter semantics (family/protocol/host/port, host and port each matched against source *or* destination) but, like the eBPF path's own `parse_headers`, does not walk IPv6 extension headers — a v6 packet with extension headers before its L4 header won't have its port matched. Not a new limitation introduced by AF_PACKET; it matches the existing eBPF behavior exactly.
- AF_PACKET capture spans every interface the agent is configured for (`NETRA_AGENT_INTERFACES`), merged into one stream — not just a single interface.

See `docs/standalone-ebpf.md` for the broader eBPF hook/map reference this feature sits alongside.

## Verification in CI

`scripts/ci-capture-live.sh` (job `capture-live`) runs a real agent and controller on a veth and,
for **both** backends, starts a filtered capture through the API and plays the browser's part
(`cmd/netra-ci-capture-client`: WebSocket in, `.pcap` out). It asserts: every captured frame matches
the filter and traffic to a second port on the same host is not captured; both directions are seen;
the frames parse as Ethernet/IP/TCP; the `.pcap` is a valid classic file holding exactly the streamed
frames and is readable by `tcpdump`; an unfiltered request and an unknown backend are refused (400);
stopping works once and a second stop is 404; the session is in the history with its backend,
requestor, filter and stop reason; a capture with a duration ends on its own (`expired`).
`ci-auto-capture-veth.sh` covers the automatic (alert-triggered) path.
