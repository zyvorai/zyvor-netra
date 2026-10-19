# Patterns borrowed from Cloudflare ebpf_exporter and Cilium Tetragon

Netra stays a Cilium-independent network observability + leased emergency containment product. This document records what was taken, adapted, or explicitly skipped so future waves do not re-litigate the boundary. See also [`fluxvm-borrow-backlog.md`](fluxvm-borrow-backlog.md).

**Do not vendor** `github.com/cloudflare/ebpf_exporter` or `github.com/cilium/tetragon`. **Do not** grow a TracingPolicy / arbitrary-kprobe / Sigkill product.

## Taken (v0.22)

| Pattern | Source | Netra surface |
|---|---|---|
| Network histogram metrics | ebpf_exporter tcp-retransmit / connect-style buckets | Agent-side bucketization from `tcp_health` + connect latency → `AgentReport.histograms` → Prometheus `netra_tcp_retransmissions`, `netra_tcp_srtt_us`, `netra_tcp_connect_us` |
| SYN backlog / listen pressure | ebpf_exporter tcp-syn-backlog (counter side) | `/proc/net/netstat` `ListenOverflows` / `ListenDrops` → `netra_tcp_listen_*` |
| Softirq NET_RX presence | ebpf_exporter softirq examples | `/proc/softirqs` NET_RX → `netra_softirq_net_rx` (not entry→exit latency) |
| BPF program attach/run health | ebpf_exporter program_* builtins | `AgentReport.programs` + `netra_ebpf_program_attached` / `run_count_total` / `run_time_seconds_total` |
| Process↔socket ownership hardening | Tetragon TrackSock / exec id | When `NETRA_PROCMETA_ENABLED`: confirm PID via `pid+startTimeJiffies`; clear stale attribution; surface `exe` on TCP health |
| Cap change observe (socket owners) | Tetragon capability-change match | Agent compares CapEff across syncs for procmeta-enriched socket owners → `capChanges` |
| Tetragon coexistence | Tetragon | `netra-doctor` `tetragon` info check (bpffs/runtime paths / process) |

## Adapted later

| Piece | Notes |
|---|---|
| Softirq *latency* histograms | Entry→exit still needs an optional kprobe/tracepoint program. Pressure buckets (NET_RX + softnet + listen depth) ship as `GET /api/v1/ebpf/stack-histograms` |
| SYN backlog depth histogram | Point-in-time listen-queue depth buckets on `GET /api/v1/ebpf/stack-histograms` (inet_diag); time-series sensor still optional |
| OTEL *logs* for audit/anomaly/incident | Shipped as pull-based `GET /api/v1/export/*?format=otlp` (`internal/siem`). Stdlib JSON Logs body only — no OTEL SDK, does not replace the JSON API. See `docs/siem-export.md` |
| OTEL *spans* for block/deny | Shipped as pull-based `GET /api/v1/export/blocks?format=otlp-trace` (`internal/siem`). One zero-parent span per already-captured blocked/dropped `FastPathEvent`; no OTEL SDK, does not replace the JSON API. See `docs/siem-export.md` |
| Exe-hash leased deny | Observe: `internal/exehash`. Enforce: `BlockedExeHashes` → agent-sourced `exehash_pids` (same TOCTOU shape as `capgate_pids`), `POST /api/v1/ebpf/exehash-deny` with `X-Netra-Confirm-Risk: high`, lease-bounded fail-open. See `docs/process-metadata.md` |
| Namespace-change watch | Shipped as `internal/nsdrift` (`GET /api/v1/ebpf/nsdrift`). Same identity/diff/pruning shape as `internal/capdrift`, no new BPF — `procmeta.Meta.NetNS` from `/proc/PID/ns/net`. See `docs/process-metadata.md` |

## Skipped

- Shipping ebpf_exporter or a YAML metric DSL runtime
- Hardware PMU (IPC/LLC), block I/O / FS / Ceph, CFS throttling dashboards
- Full Tetragon TracingPolicy CRD engine, arbitrary kprobe/uprobe/USDT
- Sigkill / Override / enforcement mode
- Cluster-wide file access or generic syscall audit
- Fighting Cilium/Tetragon for exclusive attachment on shared hooks
- Maglev / full LSM MAC (also on FluxVM backlog)

## Verifier / ABI rules

- No silent resize of existing pinned maps (`socket_owner` ABI unchanged; start-time is confirmed in userspace)
- New sensors stay **optional separate programs**, not grown into the slimmed TC path
