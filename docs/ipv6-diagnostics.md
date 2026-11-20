# Netra IPv6 Diagnostics

Netra's IPv6 extension-header walker (`bpf/netra_ipv6.h`, see `docs/ipv6-extension-headers.md`) computes extension-header counts and fragmentation state for every IPv6 packet purely to decide whether L4 parsing is safe. This feature adds one new pinned map, `ipv6_ext_stats`, that counts those outcomes instead of discarding them, and a controller-side diagnostics surface over the result. No resize or ABI change is made to any existing pinned map.

## Signals

`ipv6_ext_stats` is keyed by `(direction, hook)` and counts, per key: total IPv6 packets observed, packets that carried at least one extension header, the cumulative extension-header count, fragmented packets, non-first fragments, more-fragments-set packets, and packets where the walk exceeded its bounded limit (`chain_truncated`).

The controller exposes this through `GET /api/v1/ebpf/ipv6`, `netractl ebpf ipv6`, and the `netra_ebpf_ipv6` MCP tool, with two anomaly kinds:

- `high-fragmentation-rate` — the fragmented/total-packets ratio for a node is at or above 5% (warning) or 20% (critical), gated on a minimum sample of 1000 packets so a freshly restarted agent's still-warming counters don't trigger a false positive.
- `ext-chain-frequently-truncated` — a node has accumulated 100+ packets whose extension-header chain exceeded the walker's bounded limit (`NETRA_IPV6_MAX_EXT = 6`), meaning L4/L7 parsing was suppressed for them.

## Interpretation

This is a **node-level** signal, not per-workload: the walker runs at three call sites (`handle_v6`'s `HOOK_TC` branch, its `HOOK_CGROUP` branch, and `netra_xdp_ingress`), and only one of the three has reliable cgroup identity available. Rather than attribute the signal inconsistently depending on which hook happened to see a given packet, `ipv6_ext_stats` stays uniformly node-level — the same reasoning `docs/drop-diagnostics.md` already applies to kernel `kfree_skb` drop reasons.

A high fragmentation rate is not inherently a problem — some environments legitimately see IPv6 fragmentation from MTU mismatches or specific application behavior — but a sustained high rate or a rising `chain_truncated` count is worth investigating, since traffic in that state has address/CIDR-level visibility and enforcement only; the walker deliberately does not parse L4 ports or L7 metadata for it (see `docs/ipv6-extension-headers.md` for why this bound exists).

## Upgrade compatibility

This feature adds exactly one new map under `/sys/fs/bpf/netra`: `ipv6_ext_stats`. Existing pinned map ABIs (including `netra_ipv6_walk`'s own consumers) remain unchanged. On first upgrade the new map is created and pinned automatically.

## Safety and privacy

Purely observational — no enforcement behavior changes, and no packet payload beyond header fields the walker already inspects is collected.
