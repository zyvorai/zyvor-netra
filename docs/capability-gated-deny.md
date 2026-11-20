# Capability-gated socket deny

Denies new `connect()`/`sendmsg()` attempts for any process with a
specific Linux capability currently effective — `CAP_NET_RAW` (raw
sockets, packet crafting) or `CAP_NET_ADMIN` (interface/routing/firewall
control) today, a small fixed vocabulary rather than an arbitrary
capability name.

## Architecture: agent-sourced, not a kernel credential read

The design choice here was made explicitly, not by default. Reading
`task_struct->real_cred->cap_effective` directly from `cgroup/connect4`/
`cgroup/connect6` was considered and rejected: it would require an
unstable CO-RE struct-offset read into unexported kernel internals — a new
class of fragility this project has avoided everywhere else in
`bpf/netra_tc.c` (confirmed nothing like it exists anywhere in that file
before this feature), and it would tie enforcement to kernel-version-
specific struct layouts the BTF/CO-RE relocation mechanism can't fully
insulate against for internal (non-UAPI) structs.

Instead, this reuses `internal/procmeta`'s existing `/proc/PID/status`
`CapEff` parser (already used for the read-only process-metadata feature
and the `CapChangeEvent` watcher). The agent periodically scans every PID
on the node (gated by the same `NETRA_PROCMETA_ENABLED` flag every other
`/proc`-derived feature uses — this is a real expansion of what the agent
reads from the host, same disclosure standard) and writes only the PIDs
whose effective capabilities currently intersect the configured deny set
into a new BPF map, `capgate_pids`, as a plain presence flag — the same
shape as the existing `blocked_uids`/`blocked_comms` maps, checked
alongside them in `socket4`/`socket6`.

## The TOCTOU caveat — read this before relying on it

**This is not a live enforcement guarantee.** A process's effective
capabilities can change (via `setcap`, capability drop, or a new process
inheriting a different set) in the window between the agent's last `/proc`
scan and the `socket()` call `socket4`/`socket6` actually checks
`capgate_pids` against. A process that gained the denied capability
*after* the last scan will not be caught until the next sync; a process
that already had `capgate_pids` set but has since dropped the capability
will still be denied until the next scan clears it. This is the same
honesty standard as this project's other best-effort signals — the ICMP
interface-name lookup, the QUIC-observed heuristic — documented rather
than silently assumed away.

`NETRA_PROCMETA_ENABLED` must be set for the scan to run at all; with it
unset, `deniedCapabilities` entries are configured but have no effect
(`capgate_pids` stays empty every sync).

## Usage

```bash
netractl ebpf capability add CAP_NET_RAW
netractl ebpf capability del CAP_NET_RAW
```

Or the Firewall page's CAPABILITY card, or the
`netra_ebpf_capability_add`/`_delete` MCP tools. Same allow-exception
precedence as UID/comm deny: an explicit `allowed_uids`/`allowed_comms`
entry for that process is checked first and skips this deny alongside the
existing UID/comm checks — a process you've explicitly allow-listed still
gets through even if it holds a denied capability.

## Evidence boundaries

- Checked on both `cgroup/connect4`/`connect6` (TCP) and
  `cgroup/sendmsg4`/`sendmsg6` (UDP) — capability gating applies to any new
  socket operation, unlike SYN-drop mode (TCP-only) or the connection-rate
  cap (TCP-only).
- `capgate_pids` holds at most 8192 entries (`BPF_MAP_TYPE_HASH`), sized to
  cover a busy node's process count; a scan that would exceed it silently
  drops the excess (a `bpf_map_update_elem` failure on the agent side is
  surfaced as a sync error, not silently swallowed).
- `deniedCapabilities` itself is bounded by the known-name vocabulary
  (2 values today), not a BPF map size — validated server-side against
  `models.CapabilityBit`, not accepted as an arbitrary string.

## Validation

`internal/store`'s `TestDeniedCapabilityCRUD`; `internal/api`'s
`TestEBPFCapabilityRoundTrip`/`TestEBPFCapabilityRejectsUnknownName`;
`internal/agent`'s platform-split tests (`capgate_linux_test.go` for the
real map-missing path, `capgate_other_test.go` for the non-Linux stub's
no-op contract — `internal/procmeta` is Linux-only, so `applyCapabilityGate`
is one of the few functions in this agent with a real behavioral split,
not just a build-tag formality). CI compiles the full BPF object. Before
production rollout, load the object on a supported Linux kernel with
`NETRA_PROCMETA_ENABLED=true`, deny `CAP_NET_RAW`, and confirm a process
holding it (e.g. `ping`, which needs raw sockets) is denied a new
connection within one sync interval, and that an unrelated unprivileged
process is unaffected — compilation and host tests alone do not establish
kernel verifier acceptance.
