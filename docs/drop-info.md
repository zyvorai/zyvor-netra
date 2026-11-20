# Kernel drop attribution

Which connections the kernel is dropping packets for, **why**, and **which kernel
function dropped them**, from the `skb:kfree_skb` tracepoint.

`bpf/netra_tc.c` already counts kernel drop reasons (the raw `kfree_skb` tracepoint), but
a count with no packet in it cannot say *whose* packets are being dropped or by what
code. This adds, per dropped packet:

| Field | Example | Source |
|---|---|---|
| tuple (family, proto, src/dst, ports) | `tcp 10.0.0.5:41722 → 10.0.0.9:443` | the skb's IP and L4 headers |
| reason | `NETFILTER_DROP`, `NO_SOCKET`, `TCP_INVALID_SEQUENCE` | the tracepoint, named from **this kernel's own table** |
| location | `nft_do_chain [nf_tables]`, `__udp4_lib_rcv` | the tracepoint's code address, resolved through `/proc/kallsyms` |

The existing reason counters are untouched; this is an additional, separate sensor.

## Reading it

```
GET /api/v1/ebpf/drop-info?top=20&node=worker-1&reason=NETFILTER_DROP     # viewer role
```

Returns totals, drops per reason, the top (reason, kernel function) sites, the top dropped
flows tagged with their node, and per node whether the sensor runs. A node that tried and
could not load reports **why** (`unavailable`, e.g. "kernel BTF not available"); a node
that is off, or runs an older agent, is listed without a reason. Stale agents are excluded.
`reason` filters flows and sites; totals and the per-reason breakdown stay whole.

`/metrics` (aggregate only):

| Series | Meaning |
|---|---|
| `netra_drop_info_nodes_reporting` / `_not_reporting` | agents with / without the sensor |
| `netra_drop_info_drops` | packets dropped, summed since each agent attached |
| `netra_drop_info_drops_without_tuple` | drops with no readable IP header |
| `netra_drop_info_read_errors` | non-zero ⇒ the counts undercount |
| `netra_drop_info_reason_drops{reason}` | per reason; at most 30 series, the rest folded into `other` |

These are gauges of per-node running totals, not Prometheus counters: an agent restart
resets its contribution. Tuples and kernel functions are never labels; they are in the API.

## Enabling

On by default in `auto` mode; a node that cannot run it is reported, not failed.

| Variable (agent) | Default | Meaning |
|---|---|---|
| `NETRA_DROP_INFO` | `auto` | `auto` degrade and report why · `off` skip · `required` fail agent startup |
| `NETRA_BPF_DROPINFO_OBJECT` | `/opt/netra/bpf/netra_dropinfo.o` | compiled object |

Helm: `agent.dropInfo`. The image ships the object; from source, `make bpf`.

## How it works, and what it needs

The tracepoint record carries the skb *pointer*, `location`, the ethertype and the
`reason`. Reading the packet needs `sk_buff`'s `head` and `network_header` offsets, which
differ between kernels, so those three reads are **CO-RE relocated against
`/sys/kernel/btf/vmlinux`** at load time. This is the only Netra sensor that needs BTF; the
core datapath and the other objects do not, so a kernel without BTF loses only this
feature. The tracepoint record's own layout (skbaddr, location, protocol, reason) is read
from the kernel's format file, exactly as for `docs/tcp-events.md`, and reason names come
from that file's `print fmt` (the numbering changes between kernels).

Requirements: kernel BTF, tracefs readable by the agent (the chart mounts the host's
`/sys/kernel/tracing`; see `docs/tcp-events.md`), and `CAP_SYSLOG` for real symbol names.
Without the last, locations show as raw hex addresses.

**A tuple is trusted only when the ethertype and the IP version agree.** A packet dropped
before its network header was set, or a non-IP frame, is counted as a drop with **no
tuple** rather than given a made-up one (`drops_without_tuple`).

Aggregation is in the kernel: an LRU table of 16 384 (tuple, reason) entries and one of
2 048 (reason, location) entries, plus per-CPU counters. A drop storm costs a few map
updates per packet, not a ring buffer's worth of events.

## Limits

- **Only drops.** `kfree_skb` fires for dropped packets, not for `consume_skb` (normal
  completion), so this is not a traffic counter.
- **`NOT_SPECIFIED` is common.** Many kernel paths drop without a specific reason; the
  location is then the useful part.
- **Ports are zero** for non-first IP fragments, for IPv6 packets with extension headers
  (the next header is then not TCP/UDP), and for protocols other than TCP and UDP.
- **The tuple is the packet as the kernel held it when it dropped it**, so for traffic
  that has been decapsulated or NAT'd that is the address in the header at that point.
- **Eviction.** A very busy node evicts the coldest tuples from the flow table (16 384
  entries); `drops` and the tuple/no-tuple totals are separate per-CPU counters and are not
  lowered by it. The per-reason breakdown is summed from the (reason, location) table, which
  would lose a site only after 2 048 distinct pairs, far more than a kernel has. An event
  that cannot get a slot at all is counted in `mapFull`.
- **Top-N in reports:** 50 flows and 30 sites per node. Building them reads the flow table in
  batches of 1024 entries (per-entry iteration on kernels without batch lookup for the map
  type) and ranks the rows before formatting, so only the reported 50 are resolved and
  formatted. A drop location the resolver has not seen re-reads `/proc/kallsyms` (~150 ms on a
  busy node); the parsed table is kept for 30 s so sites that trickle in after a read do not
  pay that again. Measured with 12 000 flows in the table: about 10 ms per snapshot on a
  12-core node at load average 20 (150–250 ms before batching and the kept table), 16 ms on a
  4-vCPU VM. On a real node with the table nearly full (15 600
  entries) and the sensors running, tracing 40 s of the agent's `bpf()` calls showed this sensor
  and the TCP-event sensor together made about 7% of them; the rest are the agent's older flow
  maps. `TestDropInfoSnapshotCostWithAFullFlowTable` bounds the cost in CI.
- **Cost.** The program runs on every dropped packet. Measured with the kernel's own BPF
  run-time accounting, generating real drops (UDP to a closed port on loopback):
  **about 100 ns per drop** on a 4-vCPU aarch64 VM (Linux 6.8), and **about 540 ns** on a
  shared GitHub Actions runner (Linux 6.17, x86_64), which is the more conservative figure. On a
  loop that does nothing but generate drops, the worst case, it added 150 to 700 ns to a
  send-and-drop, 9 to 14%. At 100 000 drops per second that is roughly 1 to 5% of one core.
  Normal traffic is not affected: the program runs only for dropped packets. Caveats: loopback,
  not a NIC under load; the accounting itself adds a little; and a host that drops millions of
  packets per second (a DDoS) will pay proportionally, so use `NETRA_DROP_INFO=off` there.
  `TestDropInfoCostPerDrop` re-measures this on every CI run and fails on an order-of-magnitude
  regression (over 50 µs per drop).

## Verification

- `./scripts/ci-ebpf-tests.sh` (CI job `ebpf`) compiles the object with clang and runs
  `bpf/integration` `TestDropInfo*` against the runner's real kernel and verifier:
  the program loads and its `sk_buff` reads relocate; a UDP datagram to a closed port is
  attributed to the right tuple with reason `NO_SOCKET` and an exact count, and the dropping
  function is resolved to `__udp4_lib_rcv`; an `nft` drop of a TCP SYN is attributed to
  the connection with `NETFILTER_DROP` and `nft_do_chain`; IPv6; a non-IP frame is counted
  with no tuple even when its payload looks like an IPv4 header (mutation-checked: guessing
  the family from the bytes fabricates a tuple and that test fails); a kernel without BTF
  and a record layout it cannot read safely are refused with the reason. The BTF tests skip
  on a runner kernel that has none.
- `./scripts/ci-kernel-sensors-unit.sh` (CI job `go`) runs those unit tests with `-race` and a
  minimum test count; `./scripts/ci-agent-image.sh` (CI job `agent-image`) checks
  `netra_dropinfo.o` shipped in the agent image; the `ebpf` job also runs a mutation guard.
- Layout, reason-name and kallsyms parsing are unit-tested against a real Linux 6.8 format
  file and kallsyms shapes; aggregation, staleness and metric bounds in `internal/api`.

Run on Ubuntu 24.04 (Linux 6.8, aarch64, clang 18) and on the GitHub Actions runner (Linux
6.17, x86_64): all of the `TestDropInfo*` cases pass on both, so the CO-RE relocation works
across those kernels and both architectures. Not yet run in a Kubernetes pod or on a live
cluster node, so whether `/proc/kallsyms` shows real addresses to the agent container there
is unconfirmed.

**Reason numbers are not portable, which is why names come from the kernel.** `NETFILTER_DROP`
is 8 on 6.8 and 12 on 6.17; `TCP_RESET` is 35 and 45; `UNHANDLED_PROTO` is 56 and 74; the table
grew from 94 to 124 entries. A table baked into Netra would have mislabelled every drop on one
of them. `internal/tpformat` tests both real tables against each other's numbering.
