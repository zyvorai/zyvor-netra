---
sidebar_position: 1
---

# Architecture

Netra has two workloads: a controller (`netrad`) that serves the API/UI and holds desired configuration, and a node agent (`netra-agent`) that owns the eBPF programs and maps on each Linux node.

```text
                  Browser / netractl / netra-mcp
                               |
                               v
                    +---------------------+
                    |       netrad        |
                    |  API + UI + state   |
                    +----------+----------+
                               |
                 desired config | node reports
                               v
       +------------------------------------------------+
       |          netra-agent on every Linux node        |
       |                                                  |
       |  cgroup skb + socket hooks       optional TCX    |
       |          |                         optional XDP  |
       |          +------ Netra maps/ring buffer -------+ |
       |                 /sys/fs/bpf/netra                |
       +------------------------------------------------+

         optional                         optional
  +-------------------+             +-------------------+
  | Kubernetes Cilium |             |    Hubble Relay    |
  | NetworkPolicy API |             | Observer.GetFlows  |
  +-------------------+             +-------------------+
```

The agent owns its own programs and maps below `/sys/fs/bpf/netra` and attaches to Linux cgroup v2 for CNI-independent workload coverage — it does not touch `cilium_host`, Cilium's own maps, or assume any particular CNI is present. Cilium and Hubble are read as optional data sources, never a dependency.

Operators inspect **desired** map contents (deny/allow/rate/policy) with
`netractl ebpf maps` / `GET /api/v1/ebpf/maps` — see the repo doc
[ebpf-maps.md](https://github.com/zyvorai/zyvor-netra/blob/main/docs/ebpf-maps.md).
That is the control-plane inventory agents reconcile; it is not a raw
kernel `bpftool` dump.

Netra’s place next to PacketWolf (suite counterparts, not a wired pipeline) is documented in [Suite placement (PacketWolf)](./packetwolf.md).

## Repository layout

```text
cmd/netrad/             controller/API/UI server
cmd/netractl/           operator CLI
cmd/netra-agent/        standalone privileged node agent
cmd/netra-doctor/       read-only host readiness preflight
cmd/netra-mcp/          MCP server: controller API as stdio tools + prompts + resources for AI agents
cmd/netra-ci-*/         CI helpers: capture client (the browser's side of a capture), AF_PACKET feeder, fake OIDC provider
internal/agent/         BPF loading, hook attachment and reporting
internal/doctor/        host readiness checks used by netra-doctor
internal/observability/ standalone eBPF summaries and workload topology
internal/health/        TCP/DNS/connect health scoring and anomaly signals
internal/alert/         anomaly poller, notify fan-out, opt-in auto-capture
internal/capture/       frame encode + auto-capture PCAP artifact store
internal/ai/            heuristic briefs + optional OpenAI-compatible rewrite
internal/tcpevents/     TCP retransmit / reset / state-change tracepoints
internal/dropinfo/      per-connection kernel drop attribution (needs BTF)
internal/listenq/       accept-queue depth per listener through inet_diag
internal/l7sample/      sampled protocol observation (Redis, SQL, Kafka, HTTP/2, gRPC)
internal/sslprobe/      opt-in TLS plaintext sampling through OpenSSL uprobes
internal/mapscan/       cheap batched scans of BPF hash maps
internal/mtls/          optional agent-to-controller mutual TLS
internal/oidcauth/      OIDC login and roles
internal/otlppush/, internal/lokipush/   OTLP and Loki push sinks
bpf/netra_tc.c          the core eBPF datapath
bpf/netra_*.c           optional sensors, each its own object (capture, tlsfp, edge_intel, tcpevents, dropinfo, l7sample, ssl)
scripts/ci-*.sh         one script per CI job; see How Netra is tested
```

## Hook model

| Hook | Default | Purpose |
|---|---:|---|
| `cgroup_skb/ingress` | ✅ | CNI-independent descendant workload ingress observation/control |
| `cgroup_skb/egress` | ✅ | CNI-independent descendant workload egress observation/control |
| `cgroup/connect4`, `connect6` | ✅ | new TCP socket process/UID context and deny |
| `cgroup/sendmsg4`, `sendmsg6` | ✅ | UDP send process/UID context and deny |
| `sockops` | ✅ | TCP connection lifecycle, RTT, retransmit/RTO and connection counters |
| raw `kfree_skb` tracepoint | optional | node-level kernel skb drop-reason counters when the host exposes a reason field |
| `kfree_skb` tracepoint (BTF) | optional, `auto` | per-connection drop attribution: tuple, reason, dropping function |
| TCP tracepoints | optional, `auto` | retransmit, reset and state-change events with the flow tuple |
| `cgroup_skb` sampler | optional, off | first bytes of packets on configured ports, parsed in the agent into protocol operation counts |
| OpenSSL uprobes | optional, off | TLS plaintext sampling for HTTPS, limited to allowlisted processes |
| TCX ingress/egress | optional | interface-level visibility/control on selected interfaces |
| XDP ingress | optional | earliest ingress CIDR/port drop on selected interfaces |

The default agent runs **cgroup-only**, plus the `auto` sensors that need nothing you have not already granted. TCX and XDP are opt-in, attached only to interfaces you explicitly list. See [Optional kernel sensors](./sensors) for what each optional sensor needs and what it can and cannot see.

:::caution Scope warning
`scopeMode=all` attaches enforcement broadly to descendant root-cgroup traffic and can affect Kubernetes workloads plus host/system services. Use `scopeMode=selected` to enforce only resolved workload cgroups after previewing the matching Pods — traffic whose workload identity can't be resolved fails open in selected mode, and TCX/XDP remain observe-only there.
:::

## Observe-first, and the enforcement lease

Every custom enforcement rule in Netra — deny lists, the DDoS shield, NetPol allow/default-deny — is gated by a time-limited lease, not a permanent switch. The datapath returns to **observe** automatically when:

- the lease expires,
- the agent can't refresh state from the controller,
- the controller restarts, or
- HA leadership changes.

A leader transition or controller restart never resurrects an old enforcement lease. This is the single property every other safety guarantee in the product builds on: enforcement is something you deliberately, temporarily opt into for an incident, not a standing configuration that can silently persist past its intended window. See [Security](../security) for the full threat model.
