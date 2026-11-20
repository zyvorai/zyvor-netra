# Node Resources

A per-node "top"-like CPU/memory/load-average snapshot, plus per-workload
cgroup v2 CPU/memory usage attributed to Kubernetes pods/containers
rather than raw host PIDs. Distinct from
[Sysctl Audit](sysctl-audit.md) (current network-hardening *settings*,
not usage) and [Kernel Network Diagnostics](kernel-network-diagnostics.md)
(Congestion Map's network-stack *pressure* — softirq/qdisc/conntrack),
this reports raw CPU/memory/load pressure, host-level and per-workload.

```text
GET /api/v1/node-resources?limit=20
netractl node-resources
```

Netra never throttles, evicts, or otherwise acts on this data — every
number is for operator review only.

## Sources

Host-level (`internal/sysres.Sample`): `/proc/stat`'s `cpu ` jiffies
line, `/proc/loadavg`, `/proc/meminfo` (`MemTotal`/`MemFree`/
`MemAvailable`/`Cached`), `/proc/uptime`, `/proc/cpuinfo` (core count).

Per-workload (`internal/sysres.SampleWorkload`): `cpu.stat`'s
`usage_usec`, `memory.current`, and `memory.max`, read directly under
each workload's already-known `CgroupPath` (the same identity
`WorkloadIdentity`/`ProcessMeta` already use — no new attribution join,
no full host PID scan).

## Why CPU% needs agent-side state

Every other value here is a genuinely current reading, but CPU usage is
a *rate*: `/proc/stat` and `cpu.stat` only expose cumulative counters
since boot/cgroup-creation, so turning that into a percentage needs two
samples and the time elapsed between them. `internal/sysres.Build` — the
function behind this endpoint — is a pure, stateless function computed
fresh from the latest agent snapshot on every request, the same as
`internal/sysctlaudit.Build`, and has no "previous request" to diff
against.

The agent solves this itself: `internal/agent.Agent` keeps its own
previous-tick host sample and a `cgroup ID → last usage_usec` map (the
same "keep a previous-tick map on the `Agent` struct" idiom already used
for capability/network-namespace/exe-hash-change watching), computes
`CPUPercent` as a delta against its own prior 3s report tick, and sends
only the already-computed percentage in `AgentReport.NodeResources` —
the controller and this endpoint never see raw jiffies or `usage_usec`
counters.

## Response shape

`GET /api/v1/node-resources` returns a `NodeResourcesResponse`
(`internal/models/sysres.go`):

```json
{
  "generatedAt": "2026-09-17T06:15:48Z",
  "summary": {
    "nodes": 3, "totalCpuCores": 24, "avgCpuPercent": 34.2,
    "totalMemoryBytes": 51539607552, "usedMemoryBytes": 21474836480,
    "highestCpuNode": "node-2", "highestMemoryNode": "node-1"
  },
  "nodes": [
    {
      "node": "node-1", "stale": false, "ageSeconds": 2,
      "host": {
        "loadAvg1": 1.25, "loadAvg5": 0.98, "loadAvg15": 0.85,
        "cpuCores": 8, "cpuPercent": 37.5,
        "memoryTotalBytes": 17179869184, "memoryUsedBytes": 8589934592,
        "memoryAvailableBytes": 8589934592, "memoryCachedBytes": 2147483648,
        "uptimeSeconds": 86400
      },
      "workloads": [
        { "namespace": "prod", "pod": "api-7d9f", "workloadKind": "Deployment", "workloadName": "api",
          "cpuPercent": 62.3, "memoryUsedBytes": 268435456, "memoryLimitBytes": 536870912 }
      ]
    }
  ],
  "topWorkloadsByCpu": [
    { "namespace": "prod", "pod": "api-7d9f", "workloadKind": "Deployment", "workloadName": "api", "node": "node-1", "cpuPercent": 62.3, "memoryUsedBytes": 268435456, "memoryLimitBytes": 536870912 }
  ],
  "limitations": ["..."]
}
```

`summary` is the cluster-wide aggregate across fresh (non-stale) nodes
only — see **Semantics and limitations** below. `nodes` lists every
agent, stale or not, each with its own `host` snapshot and `workloads`
list. `topWorkloadsByCpu` is every fresh node's workloads pooled
together, sorted by `cpuPercent` descending, and capped at `limit`.

### Query parameters

```text
GET /api/v1/node-resources?limit=20
```

`limit` (default 20, max 200) caps `topWorkloadsByCpu` only — it does
not cap `nodes[].workloads`, which always carries that node's full
workload list.

## Scope and attribution

Workload rows cover **cgroup v2-attributed workloads only** — Kubernetes
pods/containers (and anything else `internal/cgroupmeta` recognizes as a
Kubernetes-looking cgroup). This is not a full `ps`/`top` process
listing: literal per-PID rows (raw host processes, not attributed to any
workload) are an explicit non-goal of this feature, not an oversight —
see **Limits** below.

A single pod typically produces **multiple rows**: one for the pod-level
cgroup slice (`ContainerID` empty) and one per container's own cgroup
scope underneath it (`ContainerID` set). This mirrors the underlying
cgroup v2 hierarchy directly rather than pre-aggregating per pod, so a
multi-container pod's per-container split is visible rather than
collapsed into one number.

## Semantics and limitations

- **Stale nodes stay listed, but excluded from aggregates.** Unlike
  Sysctl Audit (which skips a stale agent entirely — a settings audit
  has nothing to say about a node it can't currently see), this follows
  `GET /api/v1/fleet`'s (`internal/fleet`) convention: every node still
  appears in `nodes` with a `stale` flag, since this is an inventory
  view. But a stale
  node's frozen last-known CPU%/memory is excluded from `summary`'s
  cluster averages and from `topWorkloadsByCpu`, so a disconnected node
  can never skew a live ranking.
- **`cpuPercent` is 0 on an agent's first report after (re)start** —
  there is no prior sample yet to diff against. It climbs to a real
  value on the second report, ~3 seconds later.
- **Host `cpuPercent` is not per-core normalized.** It can exceed 100 on
  a multi-core node under full load (the same convention `top`/`htop`
  themselves use in "solo" mode, not per-core-normalized mode).
- **No per-process (`ps`/`top`-style) rows.** Only cgroup-v2-attributed
  workloads are reported. A process outside any tracked cgroup (rare on
  a Kubernetes node, but possible for host-level daemons) is invisible
  here. A bounded comm-only host process top (pid, CPU%, RSS — no
  argv/cmdline) is frozen only inside a drop-incident context file, not
  on this endpoint. Kernel stacks for the hottest comms are
  `GET /api/v1/insights/profiles`, also not this endpoint. See [Capture](capture.md),
  [flow history](flow-log.md), and the
  [drop-context tutorial](tutorials/drop-incident-context.md).
- **In-memory only.** A `netrad` restart or HA failover, and an agent
  restart, both reset all delta-tracking state to zero — the next
  report after either event starts back at `cpuPercent: 0` for
  everything affected.
- **No trend/history.** This is a current-snapshot view; there is no
  `/sparkline`-style companion endpoint for CPU/memory over time in this
  pass.

## API and CLI

```text
GET /api/v1/node-resources?limit=20
netractl node-resources
```

MCP tool: `netra_node_resources` (read-only).

The dashboard exposes this under **Diagnostics → Node Resources**
(cluster-pulse card, per-node table, top-workloads-by-CPU table). A
compact CPU%/memory%/load summary is also appended to each node's row on
the **Fleet** page.
