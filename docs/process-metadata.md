# Process metadata (`internal/procmeta`)

Optional, off-by-default `/proc`-derived process metadata, enriching the PIDs the eBPF datapath already attributes to TCP connections (`socket_owner`, `tcp_health`).

## Why this exists

The eBPF datapath already resolves PID/UID/comm for new TCP connects and UDP sends (`bpf_get_current_pid_tgid`, `bpf_get_current_comm`), and `TCPHealthStat.PID` carries that PID through to the controller. But a bare PID/UID/comm doesn't say much about *what* a process is — whether it holds `CAP_NET_ADMIN`, runs under a seccomp filter, is a Kubernetes container process or a bare-metal host process, or is actually the QEMU process behind a KubeVirt VM. `internal/procmeta` answers those questions by reading `/proc/PID` on the node where the connection was observed.

## Why this is agent-side, not controller-side

The controller (`netrad`) aggregates `AgentReport` from potentially many remote nodes over HTTP and has no relationship to any specific node's process tree — its own `/proc/PID` refers to a process in the controller's own pod, not the workload the PID actually names. Only the per-node agent (`cmd/netra-agent`, `internal/agent`), which already sees that PID via eBPF on that exact node, can correctly resolve its `/proc` entry. `internal/procmeta` is deliberately Linux-only and is only ever called from `internal/agent` (`procmeta_linux.go`; a no-op stub in `procmeta_other.go` keeps the agent buildable on non-Linux development machines).

## What's collected — and what isn't

Collected: comm, PPID, effective UID, `NoNewPrivs`, seccomp mode, LSM label, executable path, network-relevant effective capabilities (`CAP_NET_ADMIN`, `CAP_NET_RAW`, `CAP_BPF`, etc.), container-local PID, a kernel-thread/host/container/VM heuristic classification, and cgroup-derived pod UID / container ID / QoS class.

**Not collected: argv/cmdline content.** Command-line arguments can carry secrets (`--token=...`, connection strings), and no other feature in this datapath collects payload or argument content — Netra's existing process-identity surface elsewhere is deliberately limited to Linux `comm` (15 visible bytes). `internal/procmeta` reads `/proc/PID/cmdline` only to help classify kernel threads (no exe symlink and empty argv), and never retains its content.

## PID reuse

The kernel reuses PIDs once they're freed. Every `procmeta.Meta` carries an `Identity{PID, StartTime}` (start time in jiffies since boot, from `/proc/PID/stat`), and the internal cache keys on that pair, not on PID alone, so a reused PID can never return a stale entry for the wrong process.

## Enabling it

Off by default. Enabling requires two things, both gated by the same flag:

```bash
helm upgrade --install netra ./helm/netra --reuse-values \
  --set agent.procMetaEnabled=true
```

This sets `NETRA_PROCMETA_ENABLED=true` on the agent **and** adds `hostPID: true` to the agent DaemonSet — a real expansion of what the already-privileged agent can see (every host process's `/proc`, not just what eBPF hooks already surface), not just a config toggle. Read this whole document before enabling it in a cluster with untrusted or sensitive workloads.

## What gets attributed, and how

Once enabled, the agent collects the unique nonzero PIDs seen in the current `TCPHealth` snapshot each sync cycle, resolves each through a bounded, TTL'd cache (`procmeta.Cache`, 30s TTL / 8192 entries by default), and reports the results in `AgentReport.ProcessMeta`, keyed by `pid` + `startTimeJiffies`. A PID that has already exited by the time it's resolved gets an entry with only `attributionError` set, rather than being dropped — so a caller can still see that enrichment was attempted.

When enrichment succeeds, the agent also writes `startTimeJiffies` and `exe` onto matching `TCPHealth` rows. When enrichment fails for a PID that eBPF attributed, that row's PID/comm are cleared and `ownershipStale` is set so UI and Drop Detective do not treat a recycled PID as the socket owner. CapEff changes for those live owners are reported as observe-only `capChanges` events, network-namespace changes (see below) as `namespaceChanges` events, and executable-content changes as `exeHashChanges` events.

## Capability-drift alerting (`internal/capdrift`)

`capChanges` events existed for a while with no consumer — `internal/capdrift.Build` is what turns them into the same anomaly shape (`severity`/`kind`/`subject`/`message`) every other health signal in this project uses, so they plug into `internal/alert.Poller` (a fourth `capdrift` source alongside `health`/`pathdiag`/`dropdiag`) and the Health page the same way.

- Each `CapChangeEvent` is attributed to a workload via the same `CgroupID` its source PID's `TCPHealth` row already carries this cycle — `watchCapChanges` needs no second lookup mechanism for this, since by construction every PID it considers owns a Netra-tracked TCP socket.
- Gaining `CAP_NET_ADMIN` or `CAP_NET_RAW` (the same narrow, fixed vocabulary `docs/capability-gated-deny.md`'s enforcement feature uses, not the full 64-bit capability space) is `warning`; losing either is `info`; any other capability-bit change still produces a finding (`capdrift-other`), just without naming the specific bit.
- **A real blind spot, surfaced rather than hidden**: the diff state (`prevCaps`) `watchCapChanges` compares against is in-memory and resets on every agent restart, so a capability change that happened before the restart, or while the agent was down, produces no event. `capdrift.Build` emits a distinct `capdrift-coverage-gap` finding whenever an agent's own `AgentStartedAt` is recent (within 2 minutes of the current report), naming the affected node, so a quiet capability-drift feed after a rollout reads as "coverage gap, check separately" rather than "confirmed no drift."

`GET /api/v1/ebpf/capdrift`, `netractl ebpf capdrift`, and the `netra_ebpf_capdrift` MCP tool all return the same `{anomalies, events}` shape; the Health page's CAPABILITY DRIFT card renders the anomalies. Like everything else in this file, it does nothing without `NETRA_PROCMETA_ENABLED=true`.

## Namespace-change watch (`internal/nsdrift`)

`docs/exporter-tetragon-borrow-backlog.md` deferred this behind capability-drift shipping first ("Cap watch ships first; ns change can follow the same socket-owner scope") — it now does, following the identical identity/diff/pruning shape.

`procmeta.Meta.NetNS` is the inode number parsed from `/proc/PID/ns/net`'s symlink target (`net:[INODE]`), the kernel's own stable identifier for a network namespace. `watchNamespaceChanges` compares it per process identity (`pid`+`startTimeJiffies`) across sync cycles, exactly mirroring `watchCapChanges`: same 64-event cap, same in-memory pruning of identities no longer present, same restart blind spot.

- Unlike capability drift, there is no benign direction here — a live process changing network namespaces after start (a `setns(2)` call) is always `warning` (`nsdrift-netns-changed`), whether from a container-escape attempt or a debugging tool attaching across namespaces. Netra does not distinguish the two; it only reports that it happened.
- Same coverage-gap honesty as capdrift: `internal/nsdrift.Build` emits `nsdrift-coverage-gap` (`info`) when an agent restarted within the last 2 minutes, since the in-memory `prevNetNS` diff state resets on restart.

`GET /api/v1/ebpf/nsdrift`, `netractl ebpf nsdrift`, and the `netra_ebpf_nsdrift` MCP tool return the same `{anomalies, events}` shape as capdrift. The **Diagnostics → Process Integrity** board shows cap / netns / exe-hash findings together (Health still embeds the nsdrift/exehash widgets). Same `NETRA_PROCMETA_ENABLED=true` gate as everything else in this file.

## Exe-hash change watch (`internal/exehash`) — observe-only half of exe-hash leased deny

`docs/exporter-tetragon-borrow-backlog.md` staged this feature explicitly: "Observe `exe` first; optional fail-open lease map later." This ships the observe half; there is no lease map, deny list, or enforcement anywhere in this codebase yet.

`procmeta.Meta.ExeHash` is the SHA-256 (hex) of the executable backing a process, read from the magic `/proc/PID/exe` symlink **itself**, not the string target `os.Readlink` returns — the kernel resolves that symlink to the live backing inode even after the on-disk file at that path was replaced or unlinked (a package upgrade doing exactly that while an old process instance keeps running is the common benign case this design avoids false-flagging). `watchExeHashChanges` diffs it per process identity (`pid`+`startTimeJiffies`) across sync cycles, mirroring `watchCapChanges`/`watchNamespaceChanges` exactly: same 64-event cap, same stale-identity pruning, same in-memory reset-on-restart caveat.

- Because of how `ExeHash` is read, a genuine change means the process's own backing inode content changed while it was running — a narrower, rarer signal than capability or namespace drift, not a false alarm from routine package upgrades.
- Always `warning` (`exehash-changed`), plus `exehash-coverage-gap` (`info`) on recent agent restart, same coverage-gap honesty as capdrift/nsdrift.
- Hashing is capped at 64MiB per executable (`internal/procmeta.maxExeHashBytes`) to bound a single pathological case; oversized or unreadable executables report an empty hash rather than a partial/misleading one.

`GET /api/v1/ebpf/exehash`, `netractl ebpf exehash`, and the `netra_ebpf_exehash` MCP tool return the same `{anomalies, events}` shape. Shown on **Diagnostics → Process Integrity** with the other drift boards. Same `NETRA_PROCMETA_ENABLED=true` gate.

## Limits

- Linux only. On any other OS the agent's `readProcessMeta` is a no-op regardless of the flag.
- A process may exit between the eBPF hook observing it and the agent's next sync tick resolving `/proc/PID` — this is reported as `attributionError`, not silently dropped.
- The kernel-thread/VM classification (`processKind`) is a heuristic based on executable path and comm, not an authoritative kernel signal.
- Resolving a `PodUID`/`ContainerID`/`QoSClass` to a Kubernetes Pod name, namespace, owner, or labels is not done here — that join already happens elsewhere in this codebase (cgroup-based workload attribution) and is out of scope for this package.
