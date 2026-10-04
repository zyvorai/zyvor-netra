# Per-second metrics platform

Netra collects per-second host, network, workload and application metrics on
every node, streams them to netrad, keeps them in a tiered store, scores them
for anomalies, evaluates health rules against them, and charts them in the
console. It is the Netdata-style "every metric, every second, zero config"
layer, joined to Netra's eBPF evidence: a spike on a chart links straight to
the flows, drop reasons, TCP events and captures behind it.

Related pages: [metric alerts](metric-alerts.md),
[anomaly detection](anomaly-detection.md),
[application collectors](app-collectors.md).

The platform is **observe-only**. Collectors read `/proc`, `/sys`, cgroup files
and the counters the agent already read from its own eBPF maps; they never write
to any of them. Metric alerts only notify. Nothing here touches enforce mode,
rules or policies.

## How it fits together

```
node: collectors ─▶ tier-0 store (1 h, replay buffer) ─▶ anomaly flags
                                 │
                                 └─ gzip JSON stream, POST /api/v1/agents/metrics
netrad: per-node stores (tier 0 1 s, tier 1 1 min, tier 2 1 h)
        ├─ query, WebSocket stream, contexts      GET /api/v1/metrics/*
        ├─ metric alert engine ─▶ notification channels
        ├─ exporters ─▶ Prometheus remote write, OTLP, Graphite
        └─ evidence, AI briefs, fleet roll-up
```

- **Collectors** run once a second in the agent. A collector that fails or is
  slow is reported in `netra.collector_duration`, `netra.collector_events` and `netra.collector_disabled` and never blocks the others.
- **The agent store** keeps one hour of 1-second samples. It is also the replay
  buffer: when netrad is unreachable the sender resumes from its cursor and
  catches up, so a restart or a network blip leaves no gap.
- **netrad** keeps one store per node with three tiers. Rollups keep min, max,
  sum, count and the anomaly count per bucket, so a 30-day chart still shows
  peaks and the anomaly ribbon.

## What is collected

| Collector | Contexts | Source |
|---|---|---|
| `proc.stat` | `system.cpu`, `cpu.cpu`, `system.intr`, `system.ctxt`, `system.forks`, `system.processes`, `system.softirqs` | `/proc/stat`, `/proc/softirqs` |
| `proc.meminfo` | `system.ram`, `mem.available`, `mem.used_percent`, `mem.swap`, `mem.committed`, `mem.kernel`, `mem.hugepages`, `mem.writeback`, `mem.pgfaults`, `mem.oom_kill` | `/proc/meminfo`, `/proc/vmstat` |
| `proc.system` | `system.load`, `system.uptime`, `system.file_nr_used`, `system.file_nr_utilization`, `system.entropy` | `/proc/loadavg`, `/proc/uptime`, `/proc/sys` |
| `proc.pressure` | `system.cpu_some_pressure`, `system.memory_full_pressure`, `system.io_full_pressure` (and the other some/full pairs, plus stall time) | `/proc/pressure` |
| `proc.diskstats` | `disk.io`, `disk.ops`, `disk.qops`, `disk.util`, `disk.await`, `disk.backlog`, `system.io` | `/proc/diskstats` |
| `diskspace` | `disk.space`, `disk.space_utilization`, `disk.inodes`, `disk.inodes_utilization` | `statfs` on host mounts |
| `proc.net.dev` | `net.net`, `net.packets`, `net.errors`, `net.drops`, `net.fifo`, `net.frames`, `net.carrier`, `net.speed`, `net.mtu`, `net.operstate`, `system.net` | `/proc/net/dev`, `/sys/class/net` |
| `proc.net.snmp`, `proc.net.netstat` | `ipv4.packets`, `ipv4.tcppackets`, `ipv4.tcpsock`, `ipv4.tcperrors`, `ipv4.tcp_retrans_segments`, `ipv4.udppackets`, `ipv4.icmp`, `ipv6.*`, `ip.tcp_retransmits`, `ip.tcp_accept_queue`, `ip.tcp_syn_queue`, `ip.tcpsyncookies`, `ip.tcp_backlog_drops`, `ip.tcpconnaborts` | `/proc/net/snmp*`, `/proc/net/netstat` |
| `proc.net.sockstat` | `ipv4.sockstat_tcp_sockets`, `ipv4.sockstat_tcp_mem`, `ipv4.sockstat_udp_*`, `ipv6.sockstat6_*` | `/proc/net/sockstat*` |
| `proc.net.softnet_stat` | `system.softnet_stat` (processed, dropped, squeezed) | `/proc/net/softnet_stat` |
| `netfilter.conntrack` | `netfilter.conntrack_sockets`, `conntrack_max`, `conntrack_utilization`, `conntrack_changes`, `conntrack_errors` | `/proc/sys/net/netfilter`, `/proc/net/stat/nf_conntrack` |
| `cgroups` | `cgroup.cpu`, `cgroup.throttled`, `cgroup.mem_usage`, `cgroup.mem_utilization`, `cgroup.mem`, `cgroup.mem_events`, `cgroup.io`, `cgroup.serviced_ops`, `cgroup.*_pressure` | cgroup v2 files of each pod Netra already tracks (pod cgroup, which includes its containers; per container with `NETRA_METRICS_CGROUP_CONTAINERS=true`) |
| `apps.groups` | `app.cpu_utilization`, `app.mem_usage`, `app.processes`, `app.threads`, `app.disk_io`, `app.page_faults` | `/proc/<pid>/stat` and `io`, grouped by **comm** |
| `ebpf.datapath` | `ebpf.packets`, `ebpf.bandwidth`, `ebpf.iface_*`, `ebpf.kernel_drops`, `ebpf.tcp_events`, `ebpf.shield`, `ebpf.policy_drops`, `ebpf.conntrack_entries` | counters already in the agent report |
| `workload.red` | `workload.red_rate`, `red_bandwidth`, `red_errors`, `red_http`, `red_dns`, `red_duration` | workload-attributed counters in the agent report |
| `apps` | `<kind>.*`, `apps.up` | [application collectors](app-collectors.md) |

The process collector never reads `/proc/<pid>/cmdline` or `environ`; groups are
named by the 15-byte kernel comm. The busiest 40 groups (by CPU and memory) get
their own charts and the rest are summed into `other`; once a group is charted it
stays charted until it exits, so series do not churn.

### Workload RED series

`workload.red_*` turns the same counters behind `GET /api/v1/insights/red` into
per-second series per workload (`namespace`, `workload`, `workload_kind`
labels), so anomaly detection and metric alerts cover every workload with no
configuration. Rate is datapath packets and bandwidth; errors are blocked
packets, TCP retransmissions and RTOs, cleartext HTTP/1 5xx and DNS failures;
duration is TCP smoothed RTT. The busiest 200 workloads by bytes are kept
(`NETRA_METRICS_RED_WORKLOADS_MAX`). The agent builds its report every few
seconds; between reports the last rates are repeated rather than dropping to
zero, and a report that stops changing stops being repeated after 15 seconds.

## Querying

| Endpoint | What |
|---|---|
| `GET /api/v1/metrics/nodes` | streaming nodes, last ingest, series and bytes per node |
| `GET /api/v1/metrics/contexts?nodes=&family=` | every context with its charts, dimensions, labels, units and time range |
| `GET /api/v1/metrics/data?context=...` | one query (below) |
| `GET /api/v1/metrics/stream` | WebSocket: send `{"subscribe":[{id, context, charts, nodes, labels, window, points, groupBy, group, aggregate}]}`; each subscription is pushed once a second |
| `GET /api/v1/metrics/anomalies` | anomaly rate per node, ranked anomalous metrics, correlation for a highlighted range ([anomaly detection](anomaly-detection.md)) |
| `GET /api/v1/metrics/evidence` | flows, drop reasons, captures and co-anomalies behind a metric window (below) |
| `GET /api/v1/metrics/alerts` | active metric alerts, transitions, rules, silences ([metric alerts](metric-alerts.md)) |
| `GET /api/v1/metrics/exporters` | exporter status (below) |
| `GET /api/v1/metrics/summary` | this cluster at a glance |
| `GET /api/v1/metrics/fleet` | this cluster plus every `NETRA_FLEET_PEERS` peer |

`/data` parameters, Netdata-style:

| Parameter | Meaning |
|---|---|
| `context` | required, for example `net.net` |
| `nodes`, `charts`, `dimensions` | comma-separated globs |
| `labels` | `key:value,...` (values may be globs) |
| `after`, `before` | unix seconds, or negative seconds relative to now (default `-600`, `0`) |
| `points` | number of buckets returned |
| `group` | reduction inside a bucket: `avg` (default), `min`, `max`, `sum`, `last`, `p50`, `p90`, `p95`, `p99` (percentiles need tier 0) |
| `group_by` | `dimension` (default), `chart`, `node`, `instance`, `all`, `label:<key>` |
| `aggregate` | how grouped series combine: `sum`, `avg`, `min`, `max` |
| `tier` | force tier 0, 1 or 2; otherwise the finest tier covering the window is used |

Each dimension carries `values` and `anomalyRate` per bucket. NaN (no data) is
`null`.

### Evidence behind a metric

`GET /api/v1/metrics/evidence?context=&node=&labels=&after=&before=` answers
"what was happening on the network when this chart moved". It picks evidence by
the kind of metric:

| Metric looks like | Evidence |
|---|---|
| drops, softnet, shield, policy, interface errors | drop reasons, drop sites, flows ranked by blocked packets, captures |
| TCP, retransmits, `workload.red_errors`, `red_duration`, listen queues | TCP events, kernel network diagnostics, flows ranked by retransmissions, captures |
| DNS | DNS findings, flows |
| HTTP, nginx, apache, haproxy, envoy | workload RED, flows |
| conntrack | datapath summary, flows |
| anything else | flows ranked by bytes, captures |

The answer holds the top 10 flow-history peers in the window (narrowed to a
workload when the chart's `namespace`/`workload` labels are passed), the node's
current kernel drop reasons for drop metrics, capture sessions that overlapped
the window, other metrics that were anomalous at the same time, and links to the
matching Netra endpoints. The console shows it under a chart (Evidence button,
or drag across the chart to pick the range); `netractl metrics evidence CONTEXT`
and MCP `netra_metrics_evidence` return the same.

### CLI and MCP

```bash
netractl metrics nodes
netractl metrics contexts --family net
netractl metrics query net.net --node worker-1 --after -300 --group max
netractl metrics top --node worker-1
netractl metrics anomalies --after -3600
netractl metrics evidence ebpf.kernel_drops --node worker-1 --after -900
netractl metrics fleet
```

MCP read tools: `netra_metrics_contexts`, `netra_metrics_query`,
`netra_metrics_anomalies`, `netra_metrics_evidence`, `netra_metrics_fleet`,
`netra_metrics_alerts`, plus the `netra://metrics/contexts`,
`netra://metrics/anomalies` and `netra://metrics/alerts` resources.

## Console

**Metrics** is generated from `/contexts`: families in a sidebar, one canvas
chart per context (or per instance when a node has a handful), live at one
second over the WebSocket with polling as the fallback, windows from 5 minutes
to 30 days, split by dimension or by node across the fleet. **Metric anomalies**
shows the anomaly-rate timeline per node; drag a range to rank the metrics whose
distribution changed most. **Metric alerts** lists active alerts with Ack and
Silence actions.

## Fleet roll-up

`GET /api/v1/metrics/summary` reports this cluster's nodes, stale nodes, series,
anomaly rate over the last 15 minutes, raised alerts by severity, the top alerts
and the top anomalous dimensions. `GET /api/v1/metrics/fleet` adds the same
summary from every peer in `NETRA_FLEET_PEERS` (see
[fleet clusters](fleet-clusters.md)), fetched in parallel and best-effort; a
peer's own peers are not followed. Totals weight the anomaly rate by node count.

## Exporting

netrad can ship stored metrics elsewhere. Each sink is off until its target is
set.

| Variable | Meaning |
|---|---|
| `NETRA_EXPORT_PROMETHEUS_RW_URL` | Prometheus remote write v1 endpoint (protobuf, snappy) |
| `NETRA_EXPORT_PROMETHEUS_RW_HEADERS` | `K=V,K2=V2`, for example an `Authorization` header |
| `NETRA_EXPORT_OTLP_ENDPOINT` | OTLP/HTTP base URL; gauges are posted to `/v1/metrics` as JSON |
| `NETRA_EXPORT_OTLP_HEADERS` | `K=V,...` |
| `NETRA_EXPORT_GRAPHITE_ADDR` | `host:port` for Graphite plaintext over TCP |
| `NETRA_EXPORT_RESOLUTION` | bucket size, default `10s` (average per bucket) |
| `NETRA_EXPORT_CONTEXTS`, `NETRA_EXPORT_EXCLUDE` | comma-separated context globs |
| `NETRA_EXPORT_PREFIX` | metric name prefix, default none (`netra` in Helm) |

Prometheus names are `<prefix>_<context>` with dots turned into underscores
(`netra_net_net`), labelled `instance` (the node), `chart`, `dimension`,
`family` and the chart's own labels; OTLP sets `k8s.cluster.name`
from `NETRA_CLUSTER_NAME`. Each exporter keeps a cursor per series, sends only
complete buckets, retries on failure, and skips ahead rather than fall more than
15 minutes behind. `GET /api/v1/metrics/exporters` shows the last success, last
error, points sent and lag per sink. Credentials come only from these variables
(in Helm, from `metricsPlatform.export.existingSecret`).

## Configuration

### Agent

| Variable | Default | Meaning |
|---|---|---|
| `NETRA_METRICS_ENABLED` | `true` | collectors and stream on/off |
| `NETRA_METRICS_TIER0_RETENTION` | `1h` | local 1-second history and replay buffer |
| `NETRA_METRICS_MAX_SERIES` | `20000` | series cap on the node |
| `NETRA_METRICS_AGENT_DIR` | empty (memory) | persist the agent store |
| `NETRA_METRICS_PROC`, `NETRA_METRICS_SYS`, `NETRA_METRICS_FS_ROOT` | `/proc`, `/sys`, `/proc/1/root` when visible | host roots |
| `NETRA_METRICS_PROCESS_GROUPS`, `NETRA_METRICS_PROCESS_GROUPS_MAX` | `true`, `40` | process groups |
| `NETRA_METRICS_CGROUP_CONTAINERS` | `false` | chart each container cgroup as well as each pod |
| `NETRA_METRICS_RED_WORKLOADS_MAX` | `200` | workload RED series |
| `NETRA_METRICS_ML`, `NETRA_METRICS_ML_TRAIN_WINDOW`, `NETRA_METRICS_ML_TRAIN_EVERY` | `true`, `1h`, `30m` | anomaly models on the node |
| `NETRA_APPS_CONFIG`, `NETRA_APPS_DISCOVERY`, `NETRA_APPS_EVERY` | `/etc/netra/apps.yaml`, `false`, `5s` | [application collectors](app-collectors.md) |

### netrad

| Variable | Default | Meaning |
|---|---|---|
| `NETRA_METRICS_ENABLED` | `true` | ingest, store and APIs on/off |
| `NETRA_METRICS_DIR` | `<state dir>/metrics` | store directory; `-` keeps everything in memory |
| `NETRA_METRICS_TIER0_RETENTION` | `1h` | 1-second samples (memory) |
| `NETRA_METRICS_TIER1_RETENTION` | `336h` | 1-minute rollups |
| `NETRA_METRICS_TIER2_RETENTION` | `8760h` | 1-hour rollups |
| `NETRA_METRICS_DISK_QUOTA_MB` | `1024` | oldest rollup blocks are dropped first above it |
| `NETRA_METRICS_MAX_SERIES` | `50000` | per node |
| `NETRA_METRICS_MAX_NODES` | `2000` | stores kept |
| `NETRA_METRICS_PARENT_ML` | `false` | score anomalies on netrad for agents running with ML off |

Helm: `metricsPlatform.*` (separate from `metrics.*`, which is netrad's own
Prometheus `/metrics`). Keep `metricsPlatform.diskQuotaMb` below
`persistence.size`; the state file shares the volume.

## Honest limits

- Per-second resolution lives in memory for `tier0Retention` (one hour by
  default); older windows come from 1-minute and 1-hour rollups, where
  percentiles fall back to `max`.
- A series that stops reporting keeps its history but stops growing; the series
  cap rejects new series (counted) rather than evicting old ones.
- Pods in their own network namespace are seen through their cgroup, their
  host-side veth and Netra's eBPF counters, not through their own `/proc/net`.
- Workload RED is network-level (packets, retransmissions, SRTT, cleartext
  HTTP/1 status), not an application request trace; see
  [flow log](flow-log.md) for the same caveats.
- Tests: `./scripts/ci-metrics-unit.sh` (fixtures, no root) and
  `sudo ./scripts/ci-metrics-veth.sh` (real collectors and netrad, iperf3 load on
  a veth, anomaly flagged, alert fired).
