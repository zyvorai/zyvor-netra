# Netra Path Diagnostics

Netra v0.13 adds Cilium-independent TCP path diagnostics using the existing root-cgroup `sockops` attachment plus two new pinned maps. No resize or ABI change is made to the existing v0.12 `tcp_health` or `socket_owner` maps.

## Signals

`tcp_pressure` tracks the latest kernel transport state for each TCP tuple: `snd_cwnd`, `snd_ssthresh`, `packets_out`, `retrans_out`, `total_retrans`, `lost_out`, `sacked_out`, delivered-rate samples, MSS and TCP state. `connect_health` measures active TCP connect establishment latency from the cgroup `connect4/connect6` hook to the `BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB` callback.

The controller exposes these through `GET /api/v1/ebpf/path`, `netractl ebpf path`, the **Path Diagnostics** dashboard and low-cardinality Prometheus gauges.

## Interpretation

These are TCP transport signals from the Linux kernel. `lost_out` means segments TCP currently considers lost; `retrans_out` means retransmitted segments are outstanding. They are not a generic packet-drop reason feed and do not identify a switch, router, qdisc, NIC or firewall as the cause. `packets_out / snd_cwnd` is shown as congestion-window pressure, not as a socket send-queue byte count.

Connect latency is measured only for active TCP connections where Netra observed the cgroup connect hook and later saw the corresponding active-established sockops callback. Passive accepts are not included.

## Upgrade compatibility

v0.13 adds three new maps under `/sys/fs/bpf/netra`:

- `connect_start` — temporary socket-cookie start timestamps;
- `connect_health` — cumulative active-connect timing;
- `tcp_pressure` — current TCP transport-pressure snapshots.

Existing pinned map ABIs remain unchanged. On first upgrade the new maps are created and pinned automatically.

## Safety and privacy

Path diagnostics are observe-only. They do not change congestion control, socket options or enforcement behavior. No application payload is collected by this feature.
