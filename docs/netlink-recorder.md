# Netlink change recorder

Netra records the Linux host network control plane beside its eBPF data plane:
which link, address, route or neighbor changed, on which node, and when. It
answers "what changed on the network right before it broke" without anyone
running `ip monitor` on the right node at the right time.

The recorder is **read-only**. It never adds or deletes a link, address, route,
rule, neighbour or qdisc, never touches a Cilium-owned object, loads no eBPF
program, and needs no privilege beyond the agent's existing host network
namespace.

## What it records

| Kind | Changes | Fields |
|---|---|---|
| `link` | create, delete, carrier / operational state, MTU, master | interface, type (`veth`, `bridge`, ...), MTU, state, flags, master ifindex |
| `address` | IPv4 and IPv6 add / remove | interface, address with prefix, family |
| `route` | add, replace, withdraw, in **every** routing table | destination (`default` for the default route), gateway, source, interface, table, priority |
| `neighbor` | ARP / NDP entry appears, disappears, or fails | address, MAC, interface, NUD state |
| `overrun` | the recorder itself lost kernel messages or a subscription | which subscription, and why |

Every event carries a per-agent `epoch` and a `sequence`, so `(epoch, sequence)`
is a stable identity, and an interface name even where the kernel message held
only an ifindex (the recorder keeps an ifindex-to-name cache, which also works
for a link that was just deleted).

Once every 30 seconds, and immediately after any loss, the agent takes a **full
snapshot** of links, addresses, routes and neighbors. It heals whatever the event
stream missed, and it is what `netractl netlink state` shows.

## What it deliberately does not record

- **Neighbor state churn.** The kernel emits a message for every
  reachable / stale / delay / probe transition. Recording them would push the
  changes that matter out of the ring. Only a neighbor's first appearance, its
  removal, and a move into `failed` or `incomplete` are recorded; the rest is
  counted in `suppressed`.
- Packet payloads, process command lines, application data, Kubernetes Secrets.
  These are routing-table and link metadata that Linux exposes over RTNL.

## Honest limits

- **Host network namespace only.** The agent runs `hostNetwork`, so it sees the
  node's namespace. It does not see a pod's own namespace (the pod side of a
  veth, or routes inside a pod). The host-side veth, its `/32` route and its
  address are visible.
- **Bounded, and it says so.** Three counters separate "quiet" from "lost":
  - `dropped`: events overwritten in the agent's ring (`agent.netlinkEventBuffer`).
  - `missed`: the subset overwritten *before the agent could deliver them*, a
    real gap in the timeline.
  - `overruns`: kernel receive-buffer overflows (`ENOBUFS`). Changes between the
    overflow and the re-established subscription are lost; the snapshot resync
    restores current state, not the missing events.
- **A dead subscription is reopened.** The netlink library ends a subscription on
  the first receive error, `ENOBUFS` included, and never reopens it. The recorder
  supervises each of the four subscriptions: it records an `overrun` event, asks
  for a snapshot resync, and resubscribes. A kernel buffer overflow reopens
  after a fixed short delay (the socket worked; the reader was slow), so a
  sustained storm never blinds the recorder for longer than that; a failing start
  or any other loss backs off, capped at 30 s. `resubscribes` counts these. Receive buffers are 1 MiB per subscription, not the ~208 KiB
  default.
- **History lives in controller memory.** The controller keeps the last 2000
  events per node and, like every agent report, does not persist them. A
  controller restart clears the history; the agents' next reports rebuild the
  current state. `historySince` on each node is the earliest event the controller
  holds, so a change before it is a blind spot, not a quiet period. An agent
  restart starts a new `epoch`; older history stays, and nothing is deduplicated
  across epochs.
- **Delivery is at-least-once, exactly-once in the store.** The agent advances
  its cursor only after the controller accepted the report, so a failed POST
  resends the same events; the controller drops a resent event by
  `(epoch, cursor)`.
- **The snapshot is capped** at 2000 links, 4000 addresses, 4000 routes and 4000
  neighbors per node (sorted, first N). `counts` is the true size and
  `truncated` says how much was cut.
- **Not a cause.** An event says something changed, not that the change caused an
  outage. Nothing here correlates a change with drops or retransmits yet, and it
  raises no alerts on its own; see "Not in this release".

## Who made the change

A multicast notification says that something changed, not who asked. `bpf/netra_rtnl.c`
is an `fentry` on `rtnetlink_rcv_msg`, which runs synchronously in the task that
called `sendmsg()` on its netlink socket, so at that point the current task is the
requester. For each request that **modifies** state it records the process's `comm`
(its 16-byte name), pid, cgroup id, the `RTM_*` type and the interface index the
request names (a fixed field of address and neighbor requests; `RTA_OIF` for a route).
A link request may instead name its device only by name (`ip link set dev X` sends index 0
and `IFLA_IFNAME`), so for those it reads the name too, and the message flags, to tell a
create from an operation on an existing link. For a route it also reads the destination (`RTA_DST` and the prefix length),
because two processes can add routes on one interface in the same instant and only the
destination tells them apart. Read-only requests (`RTM_GET*`, dumps) are dropped in the
kernel before anything is reserved. It captures **no argv and no environment**, and
nothing of a message beyond the interface (index or name) and a route's destination,
which are the same values the recorder already publishes about the change; it only observes.

The agent joins each recorded change to the request behind it by message type,
interface and time (a request is looked for in the 750 ms before the notification
reached the agent, and 100 ms after). Every event then carries:

- `origin: "process"` and an `actor` (`comm`, `pid`, `cgroupId`, and `namespace`,
  `pod`, `workload` when the requester is in a pod), or
- `origin: "kernel"`: nobody requested it (carrier loss, kernel timers, router
  advertisements), or
- neither, when the sensor could not tell.

The join is strict about what it claims:

- **`confidence: "probable"`** means exactly one requester issued a matching request.
  Several at that moment are **`ambiguous`**: no process is named, and up to three
  names are listed as `alternatives`. It is a join, not proof.
- **Interface matters.** A request for one interface does not explain a change on
  another, so a veth's carrier loss is not credited to the `ip link set <peer> down`
  that happened at the same instant. A link request that names its device only by name
  (which is how modern `ip link set dev X` works) explains only that device. A create is
  the exception: it also creates a peer whose name is not in the request, so it matches
  any. A request that names a device by an *alternative* name would not match the
  device's primary name and would be read as nobody's (kernel), which is a known limit.
- **iproute2's probe is ignored.** Every `ip link` command first sends a bare
  `RTM_NEWLINK` (no index, no name, no attributes) to ask whether the kernel supports it.
  It changes nothing, so a link request with no target and no attributes explains
  nothing; otherwise whoever ran `ip link` would be credited with every link change
  around it. A link request that has attributes but names no device the sensor reads is
  *uncertain*: it names nobody and, unlike a real absence, does not let the event be
  called the kernel's.
- **So does the route's destination.** Two processes adding routes on one interface in
  the same instant are told apart by prefix (`10.90.0.0/24` is one process's,
  `10.91.0.0/24` the other's). Two requests for the very same prefix cannot be, and are
  reported as ambiguous. A multipath route names no single interface and matches any.
- **`origin: "kernel"` is only claimed when nothing weakens it:** the sensor was already
  running before the change, the kernel has not dropped requests around then (the
  ring buffer is 256 KiB; `actor.dropped` counts overflows), and the ring of recent
  requests still reaches back far enough to have held a match. Otherwise the event is
  left unattributed rather than called the kernel's.
- **Nothing is claimed when the sensor is off.** `actor` on each node's report says
  `available`, or `unavailable` with the reason (it needs kernel BTF and `fentry`;
  x86_64 5.5+, arm64 6.0+).

Findings use it: `the IPv4 default route (via 10.0.0.1 on eth0) was removed from the
main table by calico-node (pid 42, pod kube-system/calico-node-x) and none remains`,
or `host link(s) went down: eth1 (down) by the kernel (no process requested it)`, which
tells an administrator's `ip link set down` from a pulled cable. A finding built from
events with different requesters is not summarised as one, and a message without
attribution names nobody.

Events are attributed on the copies a report carries and held back about 300 ms so the
request record has arrived; the ring stays raw, so a resent event is attributed again.

```yaml
agent:
  rtnlActor: auto   # auto | off
```

`NETRA_RTNL_ACTOR=auto|off` (and `NETRA_BPF_RTNL_OBJECT`, default
`/opt/netra/bpf/netra_rtnl.o`). It needs the recorder to be on.

**Network namespaces.** Interface indexes are per namespace, and the hook runs for every
namespace's requests (a pod's CNI setup included), so a pod's request for its `ifindex 3`
could otherwise be credited with an unrelated host change on the host's `ifindex 3`. The
kernel program reads the requester's namespace (the socket's, as `rtnetlink_rcv_msg`
itself uses it), the agent tells it the one namespace it records changes in (its own:
the host's, since the agent runs `hostNetwork`), and requests from any other namespace
are dropped in the kernel before anything is reserved. That also keeps a busy node's pod
churn out of the ring buffer. The joiner refuses to match across namespaces as a second
guard.

## Findings: what is wrong now

The recorder also derives a small set of findings from what it recorded
(`internal/netlinkdiag`). They are **level-triggered**: a finding is reported only
while the latest snapshot still shows the problem, so it clears itself when the
network recovers, and a change is never a finding just because it happened.

| Kind | Severity | When |
|---|---|---|
| `netlink-default-route-removed` | critical (IPv4), warning (IPv6) | The main-table default route was removed and none remains. A replace or a re-add clears it. |
| `netlink-gateway-unreachable` | critical | The default gateway's neighbor entry is `FAILED`: it is not answering ARP/NDP. |
| `netlink-neighbor-failed` | warning for 3 or more, else info | Other neighbors in `FAILED`. One is routine in Kubernetes (a pod died); several at once is a pattern. |
| `netlink-link-down` | critical if it carried the default route, else warning | A **host uplink** went down (`down`, `lower-layer-down`, `not-present`) and is still down. |
| `netlink-link-deleted` | warning | A host uplink was deleted and has not come back. |
| `netlink-mtu-changed` | warning | A host uplink's MTU at the end of the window differs from before it. A change and a change back is no change. |
| `netlink-overrun` | warning for `ENOBUFS`, else info | The recorder lost changes, so a quiet timeline in that period is not evidence that nothing happened. |

Deliberate choices, each one a noise decision:

- **Host uplinks only** (`device`, `bond`, `team`, `vlan`). Pod veths appear and
  disappear with every pod; bridges such as libvirt's `virbr0` toggle carrier as
  guests start and stop; tunnel endpoints are not uplinks. Alerting on those would
  be alerting on normal operation.
- **`INCOMPLETE` is not a failure.** It is ARP in flight, the state of every new
  peer. Only `FAILED`, where the kernel gave up, counts.
- **Confirmed before reported.** A fresh neighbor or link change waits up to 45 s
  for a snapshot (taken every 30 s) to confirm it. A removed default route is
  never made to wait: it is reported on the event unless a snapshot taken
  afterwards shows a default route again.
- **Subject is the node**, never an interface or address (interfaces churn per
  pod, and the alert de-duplication key is built from the subject). Messages
  carry interface names and IPs, never MAC addresses; the evidence, which does,
  stays in the authenticated API.
- Window: 15 minutes by default (`window=1m..24h`). A finding says what changed,
  never why.

Findings flow through `internal/health`, so they reach the **alert poller**
(source `health`, so existing channels and min-severity filters apply), the
**incident** clustering, the **AI brief** and the **SIEM export** with no extra
wiring. They do not move the health score, which is counter-driven. Two netlink
findings on one node, or one plus another node-level anomaly such as ICMP
unreachables, also produce a `correlated-degradation` finding.

```http
GET /api/v1/netlink/findings
GET /api/v1/netlink/findings?window=1h&node=worker-3
```

```bash
netractl netlink findings
netractl netlink findings --node worker-3 --window 1h
```

The response has `findings`, plus `evaluated` and `skipped`: skipped nodes are
stale, have the recorder off, or could not start it, so "no findings" cannot be
mistaken for "nothing was looked at". `/metrics` gains
`netra_netlink_findings{severity="critical|warning|info"}`.

## Configuration

```yaml
agent:
  netlink: auto            # auto | off
  netlinkEventBuffer: 4096 # agent-side ring size
```

Equivalent environment variables: `NETRA_NETLINK=auto|off` and
`NETRA_NETLINK_EVENT_BUFFER=4096`. There is no `required` mode: it needs no BPF,
and a fault is reported in the API (`unavailable`, `error`) instead of stopping
the agent. With `off`, the node's `reporting` is `false` and the metrics count it
as not reporting.

## API

```http
GET /api/v1/netlink                                   # recorder health + recent events
GET /api/v1/netlink?node=worker-3&since=30m
GET /api/v1/netlink?kind=route&since=2026-09-21T10:00:00Z&limit=1000
GET /api/v1/netlink?view=state                        # per-node full snapshot, no events
GET /api/v1/netlink?view=all
```

- `view`: `events` (default), `state`, `all`.
- `kind`: `link`, `address`, `route`, `neighbor`, `overrun`. An unknown value is a
  400, not an empty result.
- `since`: a duration (`30m`) or an RFC 3339 time; default one hour.
- `limit`: 1 to 5000, default 500; the newest N are returned.

`nodes` holds each node's recorder health: `reporting`, `stale`, `unavailable`,
`error`, `epoch`, the counters above, `counts`, `generation`, `resyncedAt`,
`historySince`, and (with `view=state|all`) the `snapshot`. `events` is one
time-ordered timeline across nodes. The endpoint is a GET and there is no route
that changes network state.

## CLI

```bash
netractl netlink state
netractl netlink state --node worker-3
netractl netlink events --since 30m
netractl netlink events --kind route --node worker-3 --limit 200
```

## Metrics

Cluster sums over fresh, reporting nodes. As with every agent-derived cumulative
count in Netra they are gauges (a counter would fall when an agent restarts or a
node goes stale). The only label is `kind`, a fixed five-value set; interface
names, addresses and MACs stay in the JSON API.

```text
netra_netlink_nodes_reporting / netra_netlink_nodes_not_reporting
netra_netlink_events{kind="link|address|route|neighbor|overrun"}
netra_netlink_dropped_events   netra_netlink_missed_events
netra_netlink_overruns         netra_netlink_resubscribes
netra_netlink_suppressed_neighbor_events
netra_netlink_links / _addresses / _routes / _neighbors
```

## Safety and privacy

- Read-only; there is no mutation API, MCP tool, or CLI verb.
- No packet payload, argv/cmdline, application data or Secret content.
- Neighbor entries contain MAC addresses and link names can embed container ids.
  Treat the API output like flow tuples: sensitive operational telemetry.
- Bounded at the agent (ring, report size, snapshot caps) and at the controller
  (2000 events per node), so route churn cannot create unbounded memory or
  report growth.

## Validation

- `scripts/ci-netlink-unit.sh` (CI job `go`): the ring and delivery cursor, the
  resubscribe supervisor, neighbor suppression, snapshot generation, caps and
  refresh, the controller's epoch-aware dedupe and snapshot carry-forward, the
  API filters and views, the metric bounds, and the `netractl` command, with the
  race detector and arm64 / non-Linux builds. The findings are covered by tests of
  every detector and its false-positive case, the health integration, and the
  alert poller (a recorded change becomes one notification, is de-duplicated, and
  stops when the route returns).
- `scripts/ci-netlink-veth.sh` (CI job `netlink-veth-smoke`, needs Linux root):
  runs the real recorder against a real kernel inside a throwaway network
  namespace. It creates a veth, changes its address, route (via a gateway),
  permanent neighbor, MTU and carrier and asserts each event and the snapshot,
  then forces an `ENOBUFS` overflow with a route storm and asserts the overrun is
  counted and recorded, the subscription is re-established, and a route added
  afterwards is seen. The tests are
  `internal/netlinkwatch/kernel_linux_test.go`; they skip unless
  `NETRA_NETLINK_KERNEL_TESTS=1`, which only that script sets.

```bash
./scripts/ci-netlink-unit.sh
sudo ./scripts/ci-netlink-veth.sh     # Linux root
```

## Not built yet

Not implied by anything above: correlation with drops and retransmits,
attributing an interface to a pod, an MCP tool and a web page.
