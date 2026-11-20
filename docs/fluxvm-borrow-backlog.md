# FluxVM patterns deferred for later Netra waves

These FluxVM eBPF surfaces are intentionally **not** ported yet. Track them here so future work does not re-discover the boundary.

Related: patterns from Cloudflare ebpf_exporter and Cilium Tetragon are tracked in [`exporter-tetragon-borrow-backlog.md`](exporter-tetragon-borrow-backlog.md).

## Edge TCP intelligence (`fluxvm_tcp_intel.bpf.c`) — shipped

Ported as `bpf/netra_edge_intel.c`, a standalone observe-only TCX program — see `docs/edge-tcp-intel.md` for the full design, the sockops-non-duplication rationale, and the still-outstanding live-kernel verification (a wholly new BPF program, the least-precedented addition in this codebase to date).

## Pod policy engine + XDP shield generation swap — shipped as node isolation

Ported as `bpf/netra_nodeiso.c`, a standalone TCX egress program: the tuple rules and branch-free prefix compare of `fluxvm_pod_policy.bpf.h` (with its global per-rule match function, needed on the Linux 7.x verifier), the generation-keyed atomic policy swap of `fluxvm_xdp_shield.bpf.c`, and the DHCP/NDP passthrough of `fluxvm_tc.bpf.c`. Keyed per node instead of per pod, egress only, and with a lease-bounded enforce mode — see `docs/node-isolation.md`. The `BPF_PROG_TEST_RUN` verdict cases come from `scripts/test-pod-policy-verdict.py`.

## cgroup LSM MAC (`fluxvm_guard.bpf.c`, `fluxvm_guest_lsm.bpf.c`)

Exec/WX/device/write restrictions keyed by cgroup. Valuable if Netra expands beyond network containment into runtime lockdown. Out of scope while Netra remains a network observability/emergency product.

## `cgroup/connect` VIP rewrite (`fluxvm_service_connect.bpf.c`)

Host/pod VIP redirection sharing Service Fabric maps. Only reconsider if Netra explicitly adds a thin Service VIP feature; must fail open to the existing path and must not become Maglev/NAT/DSR.

## Explicitly skipped

QEMU device/egress locks, KVM flight recorder, memprof, topology steering, sched_ext, AF_XDP bridge, Service Fabric Maglev/QUIC LB.
