# Standalone eBPF datapath — v0.10

Netra can operate on Linux/Kubernetes nodes without Cilium, Hubble, or knowledge of the installed CNI. The default attachment point is the root cgroup v2 hierarchy, so descendant workload traffic is covered independently of virtual-interface naming.

## Attachment strategy

1. **cgroup skb ingress/egress** — primary packet path. Supplies IPv4/IPv6 counters, direction, L4 tuple metadata, TCP flags, DNS qname visibility and packet-path enforcement.
2. **cgroup socket address hooks** — process identity path. Supplies PID, UID, cgroup ID and `comm` for new TCP connects and UDP sendmsg operations and can reject by UID/process/IP/CIDR/port.
3. **TCX** — optional interface layer. Configure `NETRA_INTERFACES=eth0,cni0` or `auto`; it is not needed for baseline standalone coverage.
4. **XDP** — optional early ingress layer. Configure `NETRA_XDP_INTERFACES` explicitly. XDP is restricted to controls that can be decided at that hook and should be validated per NIC/driver.

## Workload attribution and selected enforcement

Netra v0.10 includes cgroup-to-Pod attribution without giving the privileged agent Kubernetes credentials. The controller reads Pod metadata; the agent scans host cgroup v2, derives cgroup IDs from inode identity, joins pod/container path components to that inventory, and enriches cgroup events/counters locally.

`scopeMode=all` preserves node-wide enforcement. `scopeMode=selected` populates an `enforced_cgroups` BPF map from namespace/pod/immediate-owner/label/cgroup-ID selectors. In selected mode, un-attributed cgroups fail open, and optional TCX/XDP remain observe-only because those hooks cannot provide the workload cgroup identity used by this policy gate. See `docs/workload-scoping.md`.

The controller fetches each node's Pod inventory fresh on every agent sync (`GET /api/v1/ebpf/config?node=<node>`) rather than caching it client-side, so a transient Kubernetes API error doesn't leave a stale inventory in the agent. The controller itself keeps a last-known-good copy per node and serves that on a fetch error, instead of an empty inventory — see `docs/behavior-insights.md`'s dependency-graph troubleshooting section for the failure mode this avoids.

## Enforcement rules

Rules are staged in controller state and synchronized to every agent. Observe mode keeps maps populated but returns allow verdicts. Enforce mode is always leased.

To inspect the staged inventory (deny/allow/rate/policy entries with human
labels) without dumping kernel maps:

```bash
netractl ebpf maps
netractl ebpf maps --json   # GET /api/v1/ebpf/maps
```

See [`ebpf-maps.md`](ebpf-maps.md). For counts only: `netractl ebpf census`.
For pin/program health per node: `netractl ebpf coverage`.

| Control | IPv4 | IPv6 | ingress | egress | process-aware |
|---|---:|---:|---:|---:|---:|
| exact IP | ✅ | ✅ | ✅ | ✅ | socket hook can apply egress |
| CIDR LPM | ✅ | ✅ | ✅ | ✅ | socket hook can apply egress |
| TCP/UDP/ANY port | ✅ | ✅ | ✅ | ✅ | ✅ egress |
| UID | n/a | n/a | — | new sockets | ✅ |
| process `comm` | n/a | n/a | — | new sockets | ✅ |
| exact DNS qname | protocol-level | protocol-level | — | UDP/53 | packet hook |
| exact TLS SNI | TLS metadata | TLS metadata | — | parsed ClientHello | cgroup packet hook |
| destination PPS | ✅ exact IPv4 | ✅ exact IPv6 | — | ✅ | — |
| exact IP allow-exception | ✅ | ✅ | ✅ | ✅ | wins over flat deny/rate |
| CIDR LPM allow-exception | ✅ | ✅ | ✅ | ✅ | wins over flat deny/rate |
| TCP/UDP/ANY port allow-exception | ✅ | ✅ | ✅ | ✅ | wins over flat deny/CIDR/port/rate |
| UID allow-exception | n/a | n/a | — | new sockets | wins over UID/comm deny |
| process `comm` allow-exception | n/a | n/a | — | new sockets | wins over UID/comm deny |

## DNS visibility

The BPF parser reads only enough of a normal UDP/53 DNS question to reconstruct a bounded qname. It rejects compression pointers in the question-name parser and lowercases ASCII before lookup. It intentionally does not claim visibility into encrypted DNS, TCP DNS, or arbitrary payloads. v0.10 separately adds metadata-only, best-effort parsing of TLS ClientHello SNI and cleartext HTTP/1 method + Host when those fields are fully present in one egress skb; there is no TCP reassembly, TLS decryption, ECH/QUIC parsing, or request-body export.

## TLS and HTTP metadata

The cgroup egress parser can record an ordinary TLS ClientHello SNI and cleartext HTTP/1 method + `Host` from a single skb. These observations feed `tls_sni_stats` and `http_host_stats`. Exact SNI deny is lease-bound and fails open whenever the SNI cannot be parsed. See `docs/l7-metadata.md`.

`connect_attempts` is updated from cgroup TCP connect and UDP sendmsg hooks and is used for workload fan-out and estimated connection-failure diagnostics.

## Process identity

Linux `bpf_get_current_pid_tgid`, `bpf_get_current_uid_gid`, `bpf_get_current_cgroup_id` and `bpf_get_current_comm` are used in socket-address hooks. `comm` is a short kernel task name, not a cryptographic workload identity. Use UID/process blocking as emergency containment rather than as a durable authorization model.

## Fail-open behavior

Netra's custom enforcement is designed to fail open:

- agent startup writes observe mode before fetching controller state;
- a lease has an explicit expiry;
- each node independently stops enforcing when its lease expires;
- inability to refresh desired state for `NETRA_FAILSAFE_AFTER` forces observe;
- controller restart and HA leadership transition reopen durable state in observe mode.

The configured deny/rate rule set can remain persisted while enforcement is disabled, allowing deliberate reactivation after review.

## Kernel/runtime notes

Use modern kernels and test the actual BPF verifier on every supported kernel family. Ring buffers imply a practical Linux 5.8+ baseline. TCX is treated as a Linux 6.6+ feature baseline by this repository. XDP behavior depends on driver/generic support. bpffs must be mounted at `/sys/fs/bpf`, and the agent is privileged because it loads programs and accesses host cgroup/bpffs state.

## Enforcement verification in CI

`scripts/ci-enforce-veth.sh` (job `enforce-veth`; also on arm64 and on a 6.8 kernel in the nightly kernel legs)
runs the real agent on a veth into a namespace with HTTP servers on both sides and proves, with traffic:
a deny rule never blocks in observe mode; in enforce mode exact-IP, CIDR and port rules drop exactly what they
name (a second port on the same host keeps working), for IPv4 and IPv6; an allow rule overrides a deny rule;
**an egress rule guards connections this host starts and an ingress rule guards connections the peer starts**
(replies to a connection this host started are exempt through connection tracking, so an ingress rule never
cuts your own outbound traffic); the drop is recorded in the block export; a lease expires on its own with the
rule still listed; and the agent fails open to observe when the controller dies (`NETRA_FAILSAFE_AFTER`).
