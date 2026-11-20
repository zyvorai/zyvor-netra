# TCP listen-queue pressure

Which listener is close to refusing connections, how full every accept queue has been,
and how many half-open connections are waiting on each. Read from the kernel's
`inet_diag` sock_diag interface: **no BPF, no BTF, no root**, on any kernel.

The kernel already counts *that* a listen queue overflowed (`TcpExt.ListenOverflows`,
`ListenDrops`, surfaced by `netra doctor` and `netra_tcp_listen_*`). It does not say
**which listener**, or how close the others are. For a `LISTEN` socket `inet_diag` reports
the current accept-queue length and the configured `listen()` backlog, which is exactly
what `ss -ltn` shows as `Recv-Q` / `Send-Q`.

## Reading it

```
GET /api/v1/listen-queues?top=20&node=worker-1        # viewer role
```

| Field | Meaning |
|---|---|
| `listeners` / `full` / `saturated` | current counts across reporting nodes. **Full**: refusing connections right now. **Saturated**: at or above 80% of capacity (includes full). |
| `synRecv` | half-open connections (SYN received, final ACK not yet) across all listeners, right now |
| `buckets` | cumulative fill histogram: (listener, sample) pairs per bin `empty, le_25, le_50, le_75, lt_100, full` |
| `top[]` | listeners that are, or have been, under pressure, deepest first: `queue`, `max` (the backlog), `synRecv`, and `peak` / `peakPct` (deepest seen at a sample since that listener appeared) |
| `nodes[]` | every fresh agent, and whether it is sampling; a node that is not reports why |

`/metrics` (aggregate only; ports and addresses are never labels):

| Series | Meaning |
|---|---|
| `netra_listen_queue_nodes_reporting` / `_not_reporting` | agents sampling / not |
| `netra_listen_queue_listeners` / `_full_listeners` / `_saturated_listeners` | current values, summed |
| `netra_listen_queue_syn_recv` | half-open connections right now |
| `netra_listen_queue_fill_samples{bucket}` | the histogram; six fixed bins, always all present |

Values are absent, not zero, when no node is sampling. The histogram is a gauge of a
running total per agent; an agent restart resets its part.

Helm `agent.listenQueues` / env `NETRA_LISTEN_QUEUES=auto|off` (default `auto`). There is
no `required` mode: nothing is loaded, and a failed read is reported as `unavailable`.

## What "full" means

The kernel refuses new connections when `queue > backlog` (`sk_acceptq_is_full`), so a
listener with backlog *N* really holds *N+1* connections. Fill percentage is therefore
`queue / (backlog + 1)`, and 100% is exactly "full". On a real 6.8 kernel a backlog-1
listener that never calls `accept()` completed two connections, showed `queue 2 / max 1`,
and `ListenOverflows` rose for the rest.

## Limits

- **Sampling, not events.** The agent reads the sockets once per report (a few seconds).
  A burst that fills and drains between two samples is not seen; the kernel's overflow
  counters still count it. `peak` is the deepest *sampled* depth.
- **The kernel's dump is not atomic.** `inet_diag` walks the listener hash while other
  processes create and close listeners; under extreme churn a listener that stays in place can
  be skipped by one dump (seen once in 14 rounds while four goroutines opened and closed
  listeners as fast as they could). The next report has it again. `TestDumpIsCorrectWhileOtherListenersChurn`
  asserts a stable listener is never missing persistently (an immediate re-dump finds it) and
  that misses stay rare.
- **Listeners only.** This does not attribute an individual dropped SYN to a listener; the
  drop attribution sensor (`docs/drop-info.md`) shows the tuple and the kernel function
  (`tcp_conn_request`) for drops that carry a tuple.
- **Half-open counts** are attributed to the listener bound to the connection's exact local
  address and port, else the wildcard listener on that port. SYN cookies mean a flood may
  not appear as half-open sockets at all.
- **Host network namespace only.** The agent runs with `hostNetwork`, so these are the host's
  listeners; a listener inside another pod network namespace is not seen.
- Cost: one netlink dump of listening sockets (and one of `SYN_RECV`) per family per report;
  a host has tens of listeners.

## Verification

- `./scripts/ci-listenq-unit.sh` (CI job `go`): the fill arithmetic, buckets and peaks; the
  **real kernel's** inet_diag through loopback listeners (a backlog-1 listener that never
  accepts is seen as full with the exact queue and backlog; `accept()` drains it; IPv6; a
  cross-check that every port `/proc/net/tcp` lists as listening is in the dump); the agent's
  modes and conversion; the controller's aggregation, endpoint and metric bounds; each step
  asserts a minimum test count. It needs no privilege.
- `./scripts/ci-ebpf-tests.sh` (CI job `ebpf`, root + `nft`): half-open connections. Dropping
  the handshake's final ACK leaves three connections in `SYN_RECV`, and all three are
  attributed to their listener with an empty accept queue.
- Mutation-checked: `queue >= backlog` for "full", never recording peaks, and not attributing
  half-open sockets each fail a test.

Run on Ubuntu 24.04 (Linux 6.8, aarch64). Not yet run in a pod or on a live node.
