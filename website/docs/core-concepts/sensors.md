---
sidebar_position: 2
---

# Optional kernel sensors

Beyond the core cgroup datapath, the agent can run extra sensors. **Each one is its own
eBPF object** (or a plain netlink query), so a bug or a verifier rejection in one can never
affect another, or a packet's verdict. Every sensor uses the same three modes, set with an
environment variable on the agent (a Helm value in the chart):

| Mode | Meaning |
|---|---|
| `auto` | run if the node can; if it cannot, the agent keeps going and **reports why** |
| `off` | do not load it |
| `required` | fail agent startup if it cannot run |

A node that cannot run a sensor shows the reason in the API and the dashboard (for example
"kernel BTF not available") instead of silently reporting zeros.

| Sensor | What it tells you | Default | Needs | API |
|---|---|---|---|---|
| **Drop attribution** | Which connection's packets the kernel dropped, why, and which kernel function dropped them | `auto` | kernel BTF, tracefs | `GET /api/v1/ebpf/drop-info` |
| **TCP events** | Retransmits, resets and state changes per flow, with the tuple | `auto` | tracefs (no BTF) | `GET /api/v1/ebpf/tcp-events` |
| **Listen queues** | Accept-queue depth and overflow per listening socket | `auto` | `inet_diag` (no BPF) | `GET /api/v1/listen-queues` |
| **BPF attachments** | Which BPF programs the kernel says are attached to each interface (XDP, TCX, classic tc), and when a Netra hook the agent believes it has is gone | `auto` | agent privileges (no new BPF) | `GET /api/v1/ebpf/attachments` |
| **Netlink changes** | Which link, address, route or neighbor changed on a node, and when; overflow is counted, not hidden | `auto` | host netns (no BPF) | `GET /api/v1/netlink` |
| **Sampled L7** | Redis commands, SQL verbs, Kafka APIs, HTTP/1 and HTTP/2 status, gRPC methods and errors | **off** | cgroup skb | `GET /api/v1/l7/sampled` |
| **TLS plaintext** | The same for HTTPS, read where the application hands bytes to OpenSSL | **off** | libssl uprobes, host PID view | `GET /api/v1/l7/tls` |

Two things are worth knowing about all of them.

**Layouts and names come from the running kernel.** Tracepoint record layouts and drop-reason
names are read from the kernel's own `format` files at load time. The numbering of drop reasons
changes between kernel versions (`NETFILTER_DROP` is 8 on 6.8 and 12 on 6.17), so a table baked
into the agent would mislabel every drop on one of them.

**Reads are cheap and bounded.** The agent reads big BPF maps in batches and keeps only the top
N in memory, so a node with hundreds of thousands of flows costs a few dozen syscalls per read
instead of hundreds of thousands. Each report says how long each map read took and whether it was
batched (`GET /api/v1/agents`).

## Drop attribution, TCP events and listen queues

These three answer "why is this node slow or losing traffic?" without touching packets.

- **Drop attribution** attaches to the kernel's `kfree_skb` tracepoint and reads the packet's
  headers with kernel type information, so it works across kernel builds. A packet dropped before
  its network header was set is counted as a drop with **no tuple** rather than given a made-up one.
  Locations resolve to real kernel function names (`nft_do_chain`, `__udp4_lib_rcv`) when the
  agent may read `/proc/kallsyms`.
- **TCP events** name the flows behind retransmits and resets, which the older counters could not.
  Some kernels expose a different record layout (a socket address instead of ports); the agent
  selects it from the kernel's format file and counts, never misreads, an event it cannot decode.
- **Listen queues** show which service's accept queue is filling. The kernel's dump is not atomic,
  so under extreme listener churn one dump can skip a stable listener; the next report has it.

## Sampled application protocols

The sampled L7 sensor copies the first bytes of packets on ports you configure into a ring
buffer, and the **agent** parses them. It is rate-limited per flow, and the kernel counts what was
eligible, emitted, rate-limited and lost, so counts can be scaled to honest estimates
(`scaleFactor = eligible / emitted`).

- A request is seen twice, leaving its client and arriving at its server, so counts carry a role:
  `issued` (this node's workloads) or `served` (this node's services). Adding the two double-counts.
- **What can appear in the output is allowlisted by construction**: an operation name, a coarse
  outcome, or a validated pattern (a Redis command, a SQL verb, an SQLSTATE class, a Kafka API name,
  an HTTP method and status). Keys, table names, SQL text, paths, query strings and bodies never
  leave the agent, and tests plant secrets in requests and assert they appear nowhere.
- It is **off by default** (`agent.l7Sample` in Helm).

## TLS plaintext sampling

This one is different in kind, so it is opt-in, off by default, and narrower on purpose.

- It attaches uprobes to `SSL_write` and `SSL_read` in the OpenSSL libraries your processes load,
  and parses the first bytes of the plaintext **inside the agent**. The plaintext is never exported.
  Only the same allowlisted counts as above (HTTPS method, status and a validated, bounded host name) leave the agent.
- **Limit what it can see.** `agent.tlsUprobesComms` restricts it to named processes
  (`nginx,envoy`), enforced **in the kernel before any byte is copied**. With no allowlist it
  observes every process that uses libssl.
- Enabling it gives the agent a host-PID view (`hostPID: true`) so it can find each process's
  libssl; the chart requests that only when TLS sampling or process metadata is on.
- It sees OpenSSL only: Go's `crypto/tls`, BoringSSL statically linked into a binary, and
  applications that do their own TLS are out of scope.
- Cost, measured on real runners: about 1 µs of program time per probe hit.

Read the full pages in the repository for the details: `docs/drop-info.md`, `docs/tcp-events.md`,
`docs/listen-queues.md`, `docs/l7-sampling.md`, `docs/tls-plaintext.md` and
`docs/agent-map-reads.md`.
