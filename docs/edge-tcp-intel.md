# Edge TCP intelligence (`bpf/netra_edge_intel.c`)

Optional, passive, fail-open TCX observer that reports TCP handshake
latency, RTT, and retransmit/RST/FIN counters from the network *edge* —
distinct from, and not a duplicate of, the socket-observed TCP data
`TCPHealth`/`TCPPressure`/`TCPSignals` already report from sockops. Ported
from FluxVM's `fluxvm_tcp_intel.bpf.c` design (see
`docs/fluxvm-borrow-backlog.md`), with its VM-tenant-specific config/event
plumbing dropped in favor of Netra's normal per-node aggregation-and-report
convention.

## Why this is not redundant with sockops

`BPF_SOCK_OPS_RTT_CB`/`track_tcp_signal` in `bpf/netra_tc.c` only fire for
a socket **this host is itself an endpoint of**, and only after NAT
resolution — the kernel's socket layer has already rewritten addresses by
the time sockops sees a packet. Edge TCP intel sits on the TC/TCX
ingress/egress hooks instead, the same attach point `netra_ingress`/
`netra_egress` use, and can see SYN/SYN-ACK/ACK timing for forwarded or
NAT'd flows where the local box is a router, not an endpoint — traffic the
socket layer never attaches to at all. Handshake latency is exact (real
SYN→SYN-ACK/ACK timestamps); RTT and retransmit signals are packet-level
estimates, not the guest TCP stack's own `srtt` — labeled as such rather
than presented as equivalent to the sockops numbers.

## Why a separate BPF object, not a branch in `netra_tc.c`

Per `docs/fluxvm-borrow-backlog.md` and `docs/exporter-tetragon-borrow-backlog.md`:
new sensors stay optional separate programs, not grown into the already
verifier-tight CT/policy program. `netra_edge_intel.c` is its own
compilation unit (`bpf/netra_edge_intel.c` → `netra_edge_intel.o`),
attached as a **second, independent** TCX program on the same interfaces
`netra_ingress`/`netra_egress` already use — TCX supports chaining
multiple programs per attach point (unlike classic TC's single-program
model). It always returns `TC_ACT_UNSPEC` (no verdict opinion), so it can
never override `netra_ingress`/`netra_egress`'s decision.

**Attach order matters, and is not cosmetic.** TCX's `bpf_mprog` chain
short-circuits on any verdict other than `TCX_NEXT` (numerically the same
value as `TC_ACT_UNSPEC`, `-1`) — a program that returns a definite
verdict (`TC_ACT_OK`, `TC_ACT_SHOT`, …) ends the chain right there for
that packet. `netra_ingress`/`netra_egress` return `TC_ACT_OK` for every
allowed packet, which is nearly all traffic in observe mode. Confirmed
live: with edge intel tail-attached (the default TCX attach position),
`bpftool net show` correctly listed both `netra_edge_ingress`/`_egress`
as attached, but `edge_tcp_counts`/`edge_tcp_hist` stayed empty under real
generated traffic — the program was attached but never actually ran,
because `netra_ingress`/`netra_egress` (attached earlier in the chain)
had already returned a terminal verdict for every packet. Fixed by
attaching with `Anchor: link.Head()` (`internal/agent/agent.go`'s
`attachEdgeIntel`) so edge intel always runs *first*, before any other
program on the hook has rendered a verdict — its own always-`TC_ACT_UNSPEC`
return then never blocks anything downstream, and it never misses a
packet regardless of what any other program (Netra's own or Cilium's)
decides afterward.

## Enabling it

Controlled by `NETRA_EDGE_INTEL=auto|off|required` on the agent, mirroring
`NETRA_TCX`/`NETRA_L7`'s existing attach-with-fallback convention exactly:

- `auto` (default): attempt to load `netra_edge_intel.o` and attach it.
  A missing object file, a verifier rejection, or an attach failure on
  some interface all degrade to "no edge intel on that
  node/interface" with a warning log — never a fatal agent-startup error.
  This is a newer, optional feature, not a load-bearing one.
- `off`: skipped entirely, object never even loaded.
- `required`: any failure (missing object, load failure, attach failure)
  is a fatal agent-startup error — for an operator who has explicitly
  opted in and wants to know immediately if it stops working.

## Data reported

Each agent aggregates its local `edge_tcp_hist` (log2-of-microseconds
histogram, 25 buckets, handshake and RTT kinds) and `edge_tcp_counts`
(syn/established/retransmit/rst/fin/flow-table-miss) maps into
`AgentReport.EdgeIntel` (`models.EdgeIntelSummary`) every sync cycle. The
controller sums these across all non-stale nodes into
`GET /api/v1/ebpf/path`'s `edgeIntel` field (see `internal/pathdiag`), the
same aggregation shape `TCPPressure`/`ConnectLatency` already use. The Path
page's "EDGE TCP INTEL" card renders a count/avg/max summary of the
histograms plus the raw counters — not a bucket-by-bucket histogram
render, since the raw log2 buckets aren't meaningful to a reader without
the bucket-boundary math already done for them.

`EdgeIntel` is `nil` on a node where the feature never attached (`off`, or
an `auto`-mode failure) — distinct from an attached-but-quiet node, which
reports a non-nil summary with zero-valued fields. `mergeEdgeIntel` treats
`nil` as "this node contributes nothing," not an error.

## Flow table

`edge_tcp_flows` (`LRU_HASH`, 16384 entries, keyed by
family+local+remote+ports) tracks per-flow handshake/RTT/sequence state so
retransmits and RTT samples can be attributed correctly — the same design
FluxVM's flow table uses. It is not itself reported to the controller
(only the aggregated histograms/counters are); a flow-table miss under LRU
eviction pressure increments the `flowMiss` counter rather than silently
dropping the sample.

## Validation

Maps compile-checked in CI (`clang -target bpfel ... -c bpf/netra_edge_intel.c`,
same as `netra_tc.c`) and built into the agent image via `Dockerfile.agent`
as a second object (`/opt/netra/bpf/netra_edge_intel.o`). This is the
newest and least-precedented BPF addition in this codebase — a wholly new
program on the hot ingress/egress path for all traffic, ported from a
different codebase's toolchain lineage, not merely a small extension of an
already-proven map type (contrast `docs/syn-drop.md`'s CIDR extension,
which reuses an already-live LPM_TRIE type). Real-kernel verification —
confirming both TCX programs actually attach and coexist with
`netra_ingress`/`netra_egress` (`bpftool net show`), the maps populate
under real traffic (`bpftool map dump`), and existing enforcement behavior
is unaffected — is tracked the same way every other eBPF feature in this
project has required it: live-cluster testing beyond `go test`/CI compile
checks, not assumed from design review alone.
