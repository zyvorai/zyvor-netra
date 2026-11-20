# Node isolation

An allow-only egress filter for one node, in **shadow** (count what it would
block) or **enforce** (drop it), independent of the cluster-wide fast-path
mode. It answers one question: *is this new outbound flow inside the node's
allow-list?*

The rest of the firewall cannot express that. `allowed_*` maps in
`bpf/netra_tc.c` are only exceptions to deny rules, default-deny exists only
per Kubernetes workload (NetPol v2), the global `config_map` is a single
observe/enforce flag, and observe mode does not count would-be-denied traffic.

## How it works

- **Kernel:** `bpf/netra_nodeiso.c`, a standalone TCX egress program attached
  at the **head** of the chain on every agent interface (TCX stops at the first
  definite verdict, and `netra_egress` returns `TC_ACT_OK`). It returns
  `TCX_NEXT` unless enforce rejects the packet (`TC_ACT_SHOT`).
- **Policy:** up to 64 rules of CIDR + protocol (`tcp`, `udp`, any) +
  destination port range. A port range only matches TCP and UDP.
- **Atomic replacement:** rules and exemptions are keyed by a generation; the
  agent writes the new generation, publishes the config last, then deletes the
  old one. A packet sees the whole old set or the whole new one.
- **Counters:** per-CPU allowed / would-block / blocked / exempt packets and
  bytes, plus an LRU of destinations outside the allow-list (top 20 reported).

### What is evaluated

| Traffic | Treatment |
|---|---|
| TCP SYN without ACK (new outbound connection) | evaluated |
| TCP SYN-ACK and later segments | always pass (replies to inbound connections, flows established before the policy) |
| UDP and other IP protocols | evaluated, unless the local source port is exempt |
| ICMP, ICMPv6 (neighbor discovery, PMTU), DHCP, DHCPv6, non-first fragments | always pass |

Because only new outbound TCP connections are judged, an operator's SSH
session (and any inbound service) survives enforce. `exemptLocalPorts`
defaults to `[22]` for UDP/TCP replies from local services; send an explicit
list to change it.

The agent always appends TCP rules for every address of its controller URL,
so enforce can never cut the agent off from the controller (and with it the
lease renewals and the delete that end isolation).

## Safety

- **Enforce has a lease** (default 15 m, 1 m–1 h). When it lapses, the
  controller demotes the policy to shadow (audited
  `ebpf.node-isolation.lease-expired`) and the agent demotes locally without
  waiting for the controller.
- **Controller stale:** after `NETRA_FAILSAFE_AFTER` without a successful
  sync, the agent runs the policy in shadow (`demoted: "controller stale"`).
- **Restart:** shadow policies survive a controller restart; enforce never
  does (audited `ebpf.node-isolation.restart-fail-open`).
- **Apply failure:** the agent falls back to shadow rather than leave a half
  replaced policy enforcing.
- **Fail-open kernel:** no policy, generation 0, a parse failure or a missing
  map entry all pass.
- `PUT` needs the **admin** role; `DELETE` (the safe direction) needs operator.

## API

```text
GET    /api/v1/ebpf/node-isolation                 viewer
PUT    /api/v1/ebpf/node-isolation/{node}?lease=15m admin
DELETE /api/v1/ebpf/node-isolation/{node}          operator
```

`PUT` body (unknown fields are rejected):

```json
{
  "policyId": "duvora-isolate-42",
  "mode": "shadow",
  "rules": [
    {"cidr": "10.0.0.0/8"},
    {"cidr": "0.0.0.0/0", "protocol": "udp", "portFrom": 53, "portTo": 53},
    {"cidr": "192.0.2.0/24", "protocol": "tcp", "portFrom": 443}
  ],
  "exemptLocalPorts": [22]
}
```

`GET` returns `{"items": [...]}`: the stored spec plus what the node's agent
reports — `effectiveMode` and `appliedRevision` (what is in the kernel now),
`demoted`, `agentStale`, `unavailable`, `attached`, `allowedPackets`,
`wouldBlockPackets`/`wouldBlockBytes`, `blockedPackets`/`blockedBytes`,
`exemptPackets` and `top` (destinations outside the allow-list). Counters are
cumulative since the program loaded; consumers diff consecutive reads.

The agent receives its own node's policy as `nodeIsolation` in
`GET /api/v1/ebpf/config?node=` and reports `nodeIsolation` in its report.

## Agent

`NETRA_NODE_ISOLATION=auto|off|required` (Helm `agent.nodeIsolation`),
object `NETRA_BPF_NODEISO_OBJECT` (default `/opt/netra/bpf/netra_nodeiso.o`).
Loading changes nothing until a policy is set. Needs TCX (Linux 6.6+).

It attaches at TCX egress on `NETRA_NODE_ISOLATION_INTERFACES` (Helm
`agent.nodeIsolationInterfaces`, comma-separated) when set, otherwise on the
agent's interfaces, otherwise on the interfaces of the IPv4 and IPv6 default
routes. The last case covers nodes where the agent runs in cgroup mode beside
a CNI such as Cilium and has no TC interfaces of its own.

## Provenance

Ported from FluxVM (see [`fluxvm-borrow-backlog.md`](fluxvm-borrow-backlog.md)):
the tuple rule shape and branch-free prefix compare of
`fluxvm_pod_policy.bpf.h`, including the global per-rule match function that
keeps the scan under the Linux 7.x verifier's 1,000,000-instruction limit
(the inlined scan was rejected; the global-function version verifies in about
6,000); the generation swap of `fluxvm_xdp_shield.bpf.c`; and the DHCP / NDP
passthrough of `fluxvm_tc.bpf.c`. FluxVM's per-pod keying, ingress
direction, audit flag and clsact fallback were not ported.

## Tests

- `internal/nodeiso` (ABI sizes against the C structs, rule encoding,
  generation wrap), `internal/store` (lease expiry, restart fail-open),
  `internal/api` (validation, round trip, config injection, RBAC).
- `bpf/integration/nodeiso_test.go` loads the real object and runs crafted
  frames through it with `BPF_PROG_TEST_RUN`: FluxVM's partial-byte prefix
  cases (/12, /45, /0, /32, both families), shadow never dropping, the
  always-pass classes, and an atomic generation swap.
- `bpf/integration/nodeiso_veth_test.go` attaches it to a scratch veth whose
  peer is in its own namespace, sends real UDP, and checks shadow counts and
  enforce drops.
- Both run in the `ebpf` CI job through `scripts/ci-ebpf-tests.sh`; they pass
  on Linux 7.0.
