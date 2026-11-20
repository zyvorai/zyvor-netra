# BPF attachment inventory and hook drift

Netra attaches its programs to interfaces once, at agent start: TCX (`bpf_link`,
kernel 6.6+) for the ingress/egress, edge and capture hooks, and XDP when
configured. The interface list is resolved at that moment and never again.

That leaves a blind spot nothing used to report. If a NIC or bond is deleted and
recreated under the same name, a `bpf_link` dies with its device, and Netra's hook
is gone; the agent's own hook list still says it is attached. The same happens if
a privileged process detaches a program or replaces the XDP program. The traffic on
that interface is then simply no longer observed, and every dashboard still looks
healthy.

This sensor asks the kernel what is attached, read-only, and compares it with what
the agent believes it attached.

## What it reads

| Attach point | How | Notes |
|---|---|---|
| XDP | The interface's netlink attributes (`IFLA_XDP`) | program id and mode: native, generic, offload |
| TCX ingress / egress | `bpf(BPF_PROG_QUERY)` | programs in **execution order**; needs kernel 6.6+ |
| Classic tc (`cls_bpf`) | Netlink filter list on the `clsact` ingress/egress parents | the mechanism Cilium uses on older kernels |

For each program it keeps only the id, the name the kernel already exposes and
an owner class. The kernel reports a name either in full or truncated to 15
characters (`netra_edge_ingress` or `netra_edge_ingr`), depending on the kernel and
on whether it has BTF function info for the program; both are accepted as the same
program. The owner classes are `netra` (`netra_*`), `cilium` (`cil_*`) or
`other`. It never reads bytecode, never reads or touches a map, and **never
attaches, detaches or replaces anything**. Cilium's programs are listed and left
alone, so the Cilium coexistence rules are unchanged.

Only interfaces with at least one program are listed, capped at 200 with `total`
and `truncated` saying how many there were. The kernel is read every 30 s; the
list is sent to the controller only when it changed (or every 5 minutes, so a
restarted controller recovers) and as a small summary otherwise.

## Findings

| Kind | Severity | When |
|---|---|---|
| `bpf-netra-hook-missing` | warning | A hook in the agent's own list (`tcx-ingress:eth0`, `edge-tcx-egress:eth0`, `capture-tcx-*`, `xdp:eth0`) has no matching Netra program in the kernel's inventory. |
| `bpf-xdp-replaced` | warning | The interface has an XDP program, but it is not Netra's. |
| `bpf-no-interface-coverage` | info | The agent has no interface hooks at all (`agent.interfaces` unset): only cgroup-level visibility. A configuration to state plainly, not a fault. |
| `bpf-inventory-unavailable` | info | The inventory is more than 3 minutes old, so drift cannot be judged right now. |

Like the netlink findings they are level-triggered (they clear when the kernel
shows the hook again), their subject is the node, and they flow through
`internal/health`, so they reach the alert poller, incidents, the AI brief and the
SIEM export with no extra wiring.

The check never guesses. It **does not report** a hook as missing when:

- the kernel cannot list TCX at all (before 6.6): absence proves nothing there;
- the query for that very interface failed (`failed` names it): unknown is not
  detached;
- the interface list was capped (`truncated`), so it may just be past the cap;
- the agent sent only a summary and the controller does not yet hold the matching
  list (the hash must match).

## Configuration

```yaml
agent:
  bpfAttach: auto   # auto | off
```

`NETRA_BPF_ATTACH=auto|off`. No new privilege is needed beyond what the agent
already holds. With `off`, the node counts as not reporting.

## API, CLI, metrics

```http
GET /api/v1/ebpf/attachments
GET /api/v1/ebpf/attachments?node=worker-3
```

```bash
netractl ebpf attachments
netractl ebpf attachments --node worker-3
```

`nodes` shows, side by side, what the agent believes (`hooks`,
`configuredInterfaces`) and what the kernel reports (`attached`), plus
`tcxSupported`, `total`, `truncated` and `failed`. `findings` lists the drift, and
`evaluated` / `skipped` count the nodes that could and could not be checked, so "no
findings" cannot be mistaken for "nothing was looked at".

`/metrics`: `netra_bpf_attach_nodes_reporting` / `_not_reporting`,
`netra_bpf_attach_interfaces`, and `netra_bpf_attach_findings{severity}` (a fixed
three-value label; interface and program names stay in the JSON).

## Limits

- **It sees, it does not repair.** A lost hook is reported, not re-attached; the
  fix today is an agent restart. Self-healing would be a behaviour change to
  Netra's own attachments and is deliberately not part of this.
- **Which interfaces are configured is not judged.** A new NIC that Netra was never
  told about is not a finding: an operator may have chosen the interfaces on
  purpose.
- **Program names only.** A program named `netra_*` by someone else would be
  classified as Netra's. The owner class is a label, not an authentication.
- **The kernel's answer, not a guarantee.** The inventory is a snapshot up to 30 s
  old.

## Validation

- `scripts/ci-bpfattach-unit.sh` (CI job `go`): the collector against a fake
  kernel, the drift diagnostic for every drift case and every false alarm above,
  the summary protocol, the controller carry-forward, the API and the metric
  bounds, with the race detector and arm64 / non-Linux builds.
- `scripts/ci-ebpf-tests.sh` (CI job `ebpf`, real kernel, root): attaches Netra's
  real `netra_ingress`, `netra_egress` and `netra_xdp_ingress` to a scratch veth
  next to another program, plus a classic `cls_bpf` filter on the peer, and
  requires the real collector to report each with the right owner and the kernel's
  execution order. It then detaches a hook, and deletes and recreates the
  interface, and requires the diagnostic to say so. It must pass and not skip.
