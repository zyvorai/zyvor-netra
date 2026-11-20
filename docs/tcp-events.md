# TCP event tracepoints

Per-connection **retransmit and RST attribution**, and the **full TCP state-transition
matrix**, from four passive kernel tracepoints. It fills two gaps left by the sockops
program in `bpf/netra_tc.c`: sockops reports retransmits only as a per-connection count
at close (no 5-tuple of the connection that is losing packets *now*), and it counts only
the `TCP_CLOSE` transition.

| Tracepoint | Counted as |
|---|---|
| `tcp:tcp_retransmit_skb` | a segment of that tuple was retransmitted |
| `tcp:tcp_send_reset` | this host sent a RST on that tuple |
| `tcp:tcp_receive_reset` | this host received a RST on that tuple |
| `sock:inet_sock_set_state` | a TCP socket moved `from` → `to` (matrix, no tuple) |

The programs only count. They never change a packet or a socket, and a failure to read a
record is counted, not fatal.

## Why the agent reads `format` files

This is not hypothetical: the record for `tcp_send_reset` **changed shape between the two
kernels this was run on.** On Linux 6.8 it carries `sport`/`dport`/`family`/`saddr`/`daddr`.
On 6.17 (a GitHub Actions runner) those are gone, replaced by two 28-byte
`struct sockaddr_in6`-sized blobs. The agent handles both: it recognises the blob shape only
when `saddr` is exactly 28 bytes and there is no `sport`, reads the family, the big-endian
port and the address out of each blob, and refuses (with the reason) anything it cannot
place. The other three tracepoints kept the classic record on both kernels.

A classic tracepoint hands a BPF program a raw record whose layout is fixed by the kernel
that built it. It differs between versions and even between sibling tracepoints of one
kernel: on Linux 6.8 the source port is at offset 28 in `tcp_send_reset` but offset 16 in
`tcp_receive_reset`. Without BTF/CO-RE a hard-coded struct would silently read the wrong
bytes on some kernel and report plausible-looking nonsense.

So before loading, the agent reads each tracepoint's own
`/sys/kernel/tracing/events/<group>/<event>/format` (falling back to
`/sys/kernel/debug/tracing`), checks that the fields it needs exist with the expected
sizes, and writes the offsets into the program's read-only data (`internal/tpformat`,
`internal/tcpevents`). A tracepoint whose layout cannot be established is **left out and
reported with the reason** instead of attached blind. The rest still run.

This keeps the core object BTF-free, like the other optional objects.

## Enabling

On by default in `auto` mode: if the object or the kernel support is missing the agent logs
a warning and carries on without it.

| Variable (agent) | Default | Meaning |
|---|---|---|
| `NETRA_TCP_EVENTS` | `auto` | `auto` degrade quietly · `off` skip · `required` fail agent startup |
| `NETRA_BPF_TCPEVENTS_OBJECT` | `/opt/netra/bpf/netra_tcpevents.o` | compiled object |

Helm: `agent.tcpEvents` (`auto`/`off`/`required`) and `agent.hostTracefs` (see below).

The image ships the object. From source: `make bpf`.

## Reading it

```
GET /api/v1/ebpf/tcp-events?top=20&node=worker-1     # viewer role
```

Returns the totals summed across fresh agents, the transition matrix, the top flows by
activity, and per node which sensors run and which were skipped (with the reason each was
skipped). A node with no sensors is listed under `nodesNotReporting`; it carries a reason
only when its agent sent one, so an older agent, or one started with `NETRA_TCP_EVENTS=off`,
appears without. A stale agent is excluded rather than counted at its last value.

`/metrics`:

| Series | Meaning |
|---|---|
| `netra_tcp_events_nodes_reporting` / `_not_reporting` | agents with / without the sensors |
| `netra_tcp_events_retransmits`, `_rst_sent`, `_rst_received` | summed counts since each agent attached |
| `netra_tcp_events_read_errors` | records the kernel program could not read; non-zero ⇒ the counts undercount |
| `netra_tcp_state_transitions{from,to}` | matrix cells; at most 144 series |

These are gauges of a per-node running total, not Prometheus counters: an agent restart
resets its contribution, so `rate()` over them is not meaningful across a restart. Use
`delta`/`increase` only over windows without restarts.
Labels are bounded (state names); no addresses reach `/metrics`. Addresses appear only in the
API's flow list.

## Behaviour to know

- **`tcp_send_reset` does not fire for RSTs the kernel sends for a port with no socket**
  (a dial to a closed port). Those are visible as `tcp_receive_reset` on the dialling side.
  `rst_sent` therefore counts resets sent *by a socket* (abortive close, `SO_LINGER 0`,
  resets from a live socket), not every RST on the wire.
- **Tuples are the socket's own view** (local address first), as the tracepoint reports
  them; nothing is translated for NAT or a proxy.
- **Flow table is an LRU of 16 384 tuples.** A very busy node evicts the coldest tuple.
  Totals live in a separate per-CPU counter, so eviction does not lower them. An event whose
  tuple cannot be inserted at all is not counted, and shows up in `mapFull` in the totals.
- **Only the top 50 flows per node** travel in each agent report.
- **`inet_sock_set_state` also fires for DCCP/SCTP/MPTCP**; where the kernel reports the
  protocol the program keeps TCP only.
- **Needs tracefs, which a container does not have by default.** A pod's own `/sys` is a bare
  sysfs: `/sys/kernel/tracing` is an empty directory and `/sys/kernel/debug` is empty. Read
  from the host side on a live k3s node (Ubuntu 6.8), the agent's mount namespace had no
  tracefs at all, so no tracepoint layout could be read. The chart therefore mounts the
  host's `/sys/kernel/tracing` read-only into the agent (`agent.hostTracefs`, default true;
  `deploy/agent.yaml` does the same). Without it the sensors report "not reporting" with the
  read error rather than guessing. Set `agent.hostTracefs=false` only on a node image that has
  no `/sys/kernel/tracing` directory, where the volume would stop the pod from starting.
- **The `kfree_skb` drop-reason sensor needs the same file** and was silently unavailable in
  the DaemonSet for the same reason ("kernel drop reason tracepoint unavailable; using stack
  counters only"). The tracefs mount fixes that too, so on an upgraded node that sensor starts
  attaching where it previously did not.

## Verification

- `./scripts/ci-ebpf-tests.sh` (CI job `ebpf`, needs root, `nft`) compiles the object with
  clang and runs `bpf/integration` `TestTCPEvents*` against the runner's real kernel and
  verifier: all four sensors load and attach; state transitions are counted; received RSTs
  and abortive closes are attributed to the right tuple in the right direction; retransmits
  are attributed to a tuple made lossy with an `nft` drop rule; IPv6 tuples; a missing field
  is counted rather than misread; a missing tracepoint drops only its own sensor.
- Parser and layout logic (`internal/tpformat`, `internal/tcpevents`) are unit-tested against
  format files captured from a real Linux 6.8 kernel, including the sibling-layout difference.
- Aggregation, staleness and metrics: `internal/api/tcp_events_test.go`.
- `./scripts/ci-kernel-sensors-unit.sh` (CI job `go`) is the unit + `-race` gate for all of the
  above, with a minimum test count per step. `./scripts/ci-agent-image.sh` (CI job
  `agent-image`) builds the agent image and checks `netra_tcpevents.o` shipped in it.

Kernel-level behaviour was run on Ubuntu 24.04 (Linux 6.8, aarch64, clang 18) and on the
GitHub Actions runner (Linux 6.17, x86_64). The layout parser is also unit-tested against the
real format files captured from both kernels (`internal/tpformat/testdata`). The `ebpf` job
prints the runner's kernel and format files, so a runner image update that changes a layout
shows up as a labelled failure with the new layout next to it.
