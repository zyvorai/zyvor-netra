# Netra standalone eBPF datapath

Netra owns these programs and maps independently of Cilium. It does not read, mutate, pin-over, or depend on Cilium-owned BPF maps.

## Programs

- `cgroup_skb/ingress` and `cgroup_skb/egress`: default CNI-independent packet visibility/control.
- `cgroup/connect4`, `cgroup/connect6`: TCP socket attribution and policy for new connects.
- `cgroup/sendmsg4`, `cgroup/sendmsg6`: UDP socket attribution and policy for sends.
- `tc/ingress`, `tc/egress`: optional TCX interface attachment from the agent.
- `sockops`: TCP lifecycle, RTT, connect latency and transport-pressure telemetry.
- `xdp`: optional early-ingress CIDR/port drop.
- `xdp` (shield variant, `netra_xdp_shield`): optional per-source-class (SYN/UDP/ICMP/other) PPS token-bucket DDoS shield, attached instead of the generic early-deny `xdp` program above when enabled. Independent of the fast-path deny-list and its own mode; see `docs/tcx-and-shield.md`.
- `raw_tracepoint/kfree_skb`: optional node-level kernel skb drop-reason counting on kernels whose tracepoint exposes a reason field.

## Maps

All pin-compatible state is owned below `/sys/fs/bpf/netra`.

**Operator inventory (desired control-plane contents):** use
`netractl ebpf maps` / `GET /api/v1/ebpf/maps` — see [`docs/ebpf-maps.md`](../docs/ebpf-maps.md).
That view lists deny/allow/rate/policy entries the controller pushes; it is
not a substitute for `bpftool map dump` of counter/observability maps.

- `flow_stats`: global exact IPv4/IPv6 tuple counters retained for pin compatibility and TCX/XDP visibility.
- `workload_flow_stats`: exact cgroup-attributed tuple counters used for namespace/pod/workload topology.
- `dest_stats`: legacy v0.x egress destination counter retained for map compatibility.
- `blocked_v4`, `blocked_v6`: exact egress IP denies.
- `allowed_v4`, `allowed_v6`: exact-IP exceptions evaluated before deny/CIDR/port/rate.
- `allowed_cidr_v4`, `allowed_cidr_v6`: directional LPM prefix exceptions, mirror of `blocked_cidr_v4`/`v6` but evaluated before deny/CIDR/port/rate.
- `blocked_ingress_v4`, `blocked_ingress_v6`: exact-IP ingress denies (parity with the existing egress `blocked_v4`/`v6` — exact-IP deny now supports direction).
- `blocked_cidr_v4`, `blocked_cidr_v6`: directional LPM prefix denies.
- `blocked_ports`: directional L4 destination-port denies.
- `allowed_ports`: directional L4 destination-port exceptions, mirror of `blocked_ports` but evaluated before deny/CIDR/port/rate.
- `blocked_uids`: socket UID denies.
- `allowed_uids`: socket UID exceptions, evaluated before UID/comm deny at the socket hook.
- `blocked_comms`: exact Linux process `comm` denies.
- `allowed_comms`: exact Linux process `comm` exceptions, evaluated before UID/comm deny at the socket hook.
- `blocked_dns`: exact normalized DNS qname denies for cleartext UDP/53.
- `rate_v4`, `rate_state_v4`: exact IPv4 destination fixed-window PPS control.
- `rate_v6`, `rate_state_v6`: exact IPv6 destination PPS (parity with `rate_v4`).
- `icmp_type_stats`: observe-only ICMPv4 type histogram.
- `icmp6_type_stats`: observe-only ICMPv6 type histogram (parity with `icmp_type_stats`).
- `icmp_errors`: observe-only, node/interface-scoped LRU histogram of fixed ICMPv4/ICMPv6 error headers (unreachable, time-exceeded, parameter-problem, packet-too-big/MTU) seen at TC ingress/egress. Never attributes to a workload, destination, port, or connection; quoted original packets are not retained.
- `scope_config`: enforcement scope mode (`all` or `selected`).
- `enforced_cgroups`: cgroup IDs currently selected for enforcement.
- `config_map`: observe/enforce mode.
- `events`: sampled flow/DNS/socket/block metadata ring buffer.


## v0.14 drop-diagnostic map

- `kernel_drops`: cumulative node-level `kfree_skb` drop-reason counters. The agent pins this map when available so counters survive agent restart. The raw tracepoint is attached only after userspace confirms the host tracepoint format contains a drop-reason field.

Linux softnet and interface counters are read directly by the agent and are not BPF maps.

## v0.13 path-diagnostic maps

- `tcp_pressure`: current sockops snapshots for cwnd, ssthresh, packets/retrans/loss outstanding, total retransmits, delivered-rate samples, MSS and TCP state.
- `connect_health`: cumulative active TCP connect-establishment latency per cgroup/remote tuple.
- `connect_start`: temporary socket-cookie timestamps used to measure connect latency; this map is intentionally not pinned.

The existing `tcp_health` and `socket_owner` map ABIs are unchanged for upgrade compatibility.

## Workload attribution and scope

The agent scans the host cgroup-v2 hierarchy, maps cgroup inode IDs to Kubernetes pod UID/container IDs, and joins those IDs to controller-supplied pod metadata. The privileged agent remains tokenless; only the controller has read-only Pod metadata RBAC.

`scope_config=all` preserves node-wide v0.7 enforcement. With `scope_config=selected`, cgroup packet/socket hooks enforce only when the current cgroup ID is present in `enforced_cgroups`. TCX/XDP traffic has no reliable workload cgroup at those hooks, so those programs remain observe-only in selected mode. This is a deliberate fail-open boundary.

## Event privacy boundary

The ring buffer contains selected header/process/workload metadata only. Netra does not copy arbitrary application payload bytes into userspace. DNS qname parsing is a narrow exception that extracts only the query name from ordinary UDP/53 requests.

## Enforcement boundary

All custom deny behavior is inactive in observe mode. Controller leases and the node failsafe control `config_map`; the agent forces observe on startup and if it cannot refresh desired state within the configured failsafe interval.

v0.8 limitations: no IPv6 extension-header walk, no TCP DNS parser, no DoH/DoT inspection, process-`comm` rules affect new connect/sendmsg operations only, pod owner attribution uses the immediate controller OwnerReference, and the PPS limiter is emergency containment rather than QoS/shaping.

## v0.10 metadata maps

- `tls_sni_stats`: exact counters keyed by cgroup ID + parsed TLS ClientHello SNI.
- `http_host_stats`: exact counters keyed by cgroup ID + cleartext HTTP/1 Host + method.
- `http_status_stats`: cleartext HTTP/1 status code when the status line starts the skb. No HTTP/2, HTTP/3, or reassembly.
- `connect_attempts`: cgroup socket-attempt counters keyed by family/protocol/remote IP/remote port.
- `blocked_sni`: exact normalized TLS SNI emergency deny entries.
- `tls_hello_events` / `tls_hello_rate` (additive, **standalone**
  `bpf/netra_tlsfp.c`): rate-limited ClientHello samples via
  `bpf_skb_load_bytes` + per-CPU scratch for userspace JA3/JA4. Own
  verifier budget — attaches even when `netra_l7_*` is rejected (kernels
  before 5.17 lack `bpf_loop`). See
  `docs/tls-fingerprints.md`. CI: `scripts/ci-tlsfp-smoke.sh`.

TLS and HTTP parsing is metadata-only and best-effort on a single skb. Netra does not reassemble TCP streams or export payload bytes. SNI-specific enforcement applies only when an ordinary ClientHello hostname is fully parsed; fragmented ClientHello, ECH and QUIC traffic fail open for the SNI rule.

## v0.18+ XDP Shield maps

- `shield_cfg`: generation-published mode/thresholds/burst config for the shield.
- `shield_protected4`, `shield_protected6`: exact-IP allow-list of destinations the shield applies to when `protectAll` is off (v6 added 0.27.16, mirrors `shield_protected4`'s key/value shape).
- `shield_sources`: per-source-class token-bucket state (LRU).
- `shield_stats`, `shield_class_stats`: aggregate and per-class (syn/udp/icmp/other) allowed/dropped/audited counters.
- `shield_source_hits`: per-source "would-be-denied" hit counts for diagnostics.

See `docs/tcx-and-shield.md` for the full config shape, attach requirements, and per-class/per-source diagnostics.
