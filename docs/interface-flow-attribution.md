# Netra Interface Flow Attribution

Netra's TC/TCX-attached hooks already see `skb->ifindex` on every packet, but the `flow_stats`/`workload_flow_stats` maps behind Netra's existing flow counters carry no interface identity — a multi-NIC node's allow/block counters could not be attributed to a specific interface, unlike the kernel-level drop diagnostics in `docs/drop-diagnostics.md`, which already break down by interface name. This feature adds one new pinned map, `iface_flow_stats`, that keys the same flow counters by interface as well. No resize or ABI change is made to `flow_key`, `flow_stats`, or `workload_flow_stats`.

## Scope: TC/TCX hooks only

`iface_flow_stats` is populated **only** from `handle_v4`/`handle_v6`'s `HOOK_TC` branch — that is, `tc/egress`, `tc/ingress`, and TCX. It is deliberately **not** populated from:

- **`cgroup_skb` hooks** — at that point in the stack, `skb->ifindex` is not a trustworthy "which NIC" signal (the same class of reasoning `docs/ipv6-diagnostics.md` uses in reverse: cgroup hooks have workload identity but not reliable interface identity; TC hooks have the opposite).
- **The early-deny XDP program** (`netra_xdp_ingress`) — it only ever calls the equivalent of `update_flow` on its blocked path, never on allow, so including it here would produce an interface counter that is silently blocked-only and inconsistent with TC's allowed+blocked coverage.

This means `iface_flow_stats` never carries a cgroup ID — interface attribution stays node-level, for the same underlying reason IPv6 extension-header diagnostics stay node-level: no single hook has both dimensions available at once with equal trust.

## API and CLI

```text
GET /api/v1/ebpf/interfaces?limit=10
netractl ebpf interfaces
```

Also available as the `netra_ebpf_interfaces` MCP tool (`docs/mcp-integration.md`). The response is per-node, per-interface: total packets/bytes/blocked, plus the top-N destinations for that interface. Interface names are resolved agent-side from the host's own network interface list, not pushed into BPF from userspace.

## Upgrade compatibility

This feature adds exactly one new map under `/sys/fs/bpf/netra`: `iface_flow_stats`, keyed by `{ifindex, flow_key}` and reusing the existing `flow_value` type verbatim — the same "wrap, don't resize" pattern `workload_flow_key` already established for `flow_key`. Existing pinned map ABIs are unchanged.

## Cost and cardinality

Worst-case cardinality is `(number of TC-attached interfaces) × (existing flow_stats cardinality)`, so `iface_flow_stats`'s `max_entries` is matched to `flow_stats`'s own size (131072) as a starting point — watch for LRU eviction on nodes with many TC-attached interfaces and high flow cardinality, the same way you would for `flow_stats` itself. This also adds one extra map lookup-or-create per packet on `HOOK_TC`, Netra's highest-volume path; if you run a very high packet-rate node, verify this doesn't measurably change throughput before relying on the feature at scale.

## Safety and privacy

Purely observational — no enforcement behavior changes, and no data beyond what `flow_stats` already tracks (5-tuple, packet/byte/blocked counts) is collected, just attributed to an additional dimension.
