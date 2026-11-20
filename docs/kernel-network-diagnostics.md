# Kernel network buffer and congestion diagnostics

Netra collects a read-only, per-node snapshot of Linux networking sysctls and
cumulative protocol counters, then correlates them with the existing softnet,
interface, qdisc and eBPF drop evidence.

> See also [`docs/sysctl-audit.md`](sysctl-audit.md) for a separate, flat
> baseline-checked inventory of security/IPv6/TCP-lifecycle/conntrack-timeout/
> ARP-bridge sysctls — this document's findings stay evidence-correlated to
> observed congestion/drops, not a pass/fail hardening checklist.

```text
GET /api/v1/ebpf/kernel-network?window=5m
netractl ebpf kernel-network 5m
# alias
netractl ebpf sysctl
```

Netra does **not** write sysctls. A finding includes the observed value, the
evidence that made the setting relevant, a conservative canary value where a
safe numeric suggestion is possible, the apply command, and a rollback command
that restores the observed value.

The controller retains a bounded two-hour in-memory history and compares two
reports inside the requested window (default `5m`, clamped to `30s..2h`). The
response exposes each counter's `delta` and `perSecond` rate. Until two reports
from the same agent process exist, the node is marked `warming` and cumulative
drop findings are suppressed. Agent restarts and backwards counters are marked
as resets and never converted into unsigned spikes. Conntrack utilization is a
current gauge and remains available while the rate window warms.

## Where congestion and drops occur

| Layer | Primary evidence | Relevant controls | What to investigate first |
| --- | --- | --- | --- |
| NIC/driver ring | `rx_missed_errors`, RX/TX drops/errors, `ethtool -S` | NIC ring/channel/coalescing settings, not sysctls | Link health, IRQ affinity, queue count, CPU/NUMA placement, virtual-device backpressure |
| NAPI/softnet | `/proc/net/softnet_stat` dropped and time-squeeze, `TcpExt.TCPBacklogDrop` | `net.core.netdev_max_backlog`, `net.core.netdev_budget`, `net.core.netdev_budget_usecs`, `net.core.dev_weight` | Per-CPU deltas, softirq CPU, RPS/RFS/XPS, bursts versus sustained overload |
| IP layer | `Ip.InDiscards`, `Ip.OutDiscards`, route, checksum, reassembly and fragmentation counters | Route/MTU/fragment controls; usually not a buffer-first problem | Routes, policy, MTU, conntrack, checksum offload, Netra drop reasons |
| UDP receive | `Udp.RcvbufErrors`, `Udp.InErrors`, `Udp.MemErrors` | Application `SO_RCVBUF`, `net.core.rmem_max/default`, `net.ipv4.udp_rmem_min`, `udp_mem` | Slow reader, socket queue from `ss -u -m -p`, burst rate, cgroup/node memory |
| UDP send | `Udp.SndbufErrors` | Application `SO_SNDBUF`, `net.core.wmem_max/default`, `net.ipv4.udp_wmem_min` | Producer rate, qdisc drops, NIC drain rate, pacing |
| TCP listen/SYN queues | `ListenDrops`, `ListenOverflows`, `TCPReqQFullDrop`, `TCPFastOpenListenOverflow` | Application `listen(backlog)`, `net.core.somaxconn`, `net.ipv4.tcp_max_syn_backlog` | Accept-loop latency, worker saturation, SYN rate, load-balancer behavior |
| TCP socket memory | `TCPMemoryPressures`, `TCPAbortOnMemory`, `TCPWqueueTooBig` | `tcp_rmem`, `tcp_wmem`, `tcp_mem`, `tcp_moderate_rcvbuf`, cgroup memory | Node/cgroup memory, socket count, per-socket queues, leak/runaway connections |
| TCP path/congestion | retransmits, timeouts, lost/retrans out, cwnd pressure, RTT | `tcp_congestion_control`, `tcp_limit_output_bytes`, application pacing | Remote loss, path capacity, MTU, qdisc, receiver window; do not assume host buffer loss |
| Egress qdisc | netlink qdisc drops/overlimits/requeues | qdisc algorithm and queue/shaper parameters; `default_qdisc` only affects newly created qdiscs | `tc -s qdisc show`, shaping/policing, application pacing, bufferbloat |
| Conntrack | insert/drop/full evidence and occupancy | `nf_conntrack_max` plus table sizing/timeouts | Flow churn, leaks, NAT pressure, hash distribution and memory budget |

## Collected sysctls

The allow-list is intentionally bounded and contains no secrets:

- packet processing: `netdev_max_backlog`, `netdev_budget`,
  `netdev_budget_usecs`, `dev_weight`, RPS flow entries and flow-limit size;
- socket ceilings/defaults: `rmem_*`, `wmem_*`, `optmem_max`, `somaxconn`;
- TCP: `tcp_rmem`, `tcp_wmem`, `tcp_mem`, SYN backlog, receive autotuning,
  advertised-window scaling, output/notsent limits and congestion algorithms;
- UDP: minimum receive/send buffers and protocol memory thresholds;
- qdisc, busy-poll, ephemeral-port range and conntrack table ceiling.

Missing settings are omitted because kernel version, build configuration and
network namespace determine which files exist.

## Dashboard (Diagnostics → Congestion Map)

A pictorial, cluster-wide view lays out the layers above as stage cards across ingress/shared/egress columns, colored by the worst finding across the cluster right now. Every one of the four severities — `ok`, `warming`, `warning`, `critical` — gets a full tinted card background (not just a border color), so a healthy cluster's grid reads as a field of green rather than flat gray. Clicking a stage drills into per-node detail, a trend sparkline for the worst-affected node, and a plain-English glossary popover per stage.

Each per-node finding in the drill-down has a "Capture on {node}" button that jumps to the Capture page with that node pre-selected — see `docs/capture.md`'s Congestion Map integration section for the other half of that link (the Capture page also polls this same `GET /api/v1/ebpf/kernel-network` endpoint to suggest a capture on a node with a live critical finding).

With opt-in auto-capture (`NETRA_AUTO_CAPTURE` / Helm `alerting.autoCapture`), a **critical** Congestion Map finding also starts that capture automatically and writes a PCAP under `NETRA_AUTO_CAPTURE_DIR` — see `docs/capture.md` (Auto-capture).

## Prometheus

The default five-minute window exports low-cardinality gauges without node,
interface, qdisc or counter-name labels:

- `netra_kernel_network_findings`, `_critical_findings`, `_warning_findings`
  and `_warming_nodes`;
- `netra_softnet_drop_rate`, `netra_softnet_time_squeeze_rate`;
- `netra_interface_rx_drop_rate`, `netra_interface_tx_drop_rate`,
  `netra_interface_rx_missed_rate`, `netra_qdisc_drop_rate`;
- `netra_udp_receive_buffer_error_rate`,
  `netra_udp_send_buffer_error_rate`;
- `netra_tcp_listen_drop_rate`, `netra_tcp_receive_queue_drop_rate`,
  `netra_tcp_memory_pressure_rate`, `netra_ip_discard_rate`.

These rates are zero while the relevant node window is warming.

## Interpretation rules

1. Agent snapshots are cumulative since boot. The controller endpoint converts
   them to deltas over the requested interval before estimating current
   severity. Raw totals remain visible for investigation.
2. A small sysctl is not, by itself, a defect. Netra creates a recommendation
   only when matching loss/pressure evidence exists.
3. Increasing a buffer helps absorb bursts; it cannot fix a sustained producer
   rate above the consumer, CPU, qdisc or link drain rate.
4. Larger queues trade drops for memory and latency. Watch p95/p99 latency,
   retransmits, memory, drops and throughput during a canary.
5. Persist only a validated value through the host's normal configuration
   management. The response's `sysctl -w` command is deliberately temporary;
   the paired rollback command restores the value Netra observed.

## Suggested rollout

1. Record the API response, selected interval and node uptime.
2. Wait for window warm-up, then reproduce the traffic window.
3. Locate the first layer whose counters increased; downstream counters can be
   symptoms of the same event.
4. Fix CPU, consumer, routing, NIC or qdisc causes before changing buffers.
5. Canary one node and one setting. Keep the rollback command ready.
6. Compare drop deltas, latency, memory and throughput. Revert if the change
   only increases queueing latency or memory.

## Visibility boundaries

The agent must see the host `/proc` and relevant network namespace to diagnose
the host. A container-local snapshot may be valid only for that namespace.
The feature does not read payloads, process command lines, socket contents, or
secrets. It performs no mutation and does not change Netra's observe-first and
lease-bounded enforcement guarantees.
