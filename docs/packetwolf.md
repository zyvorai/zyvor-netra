# Netra + PacketWolf: how they work together

## Verdict

They are **suite counterparts, not a wired pipeline**. PacketWolf is Zyvor’s Cilium-first commercial flagship; Netra is the standalone observe + leased emergency-control layer. Neither product is a dependency or API consumer of the other (Netra’s K3s/Hubble bootstrap helpers intentionally mirror PacketWolf scripts — packaging lineage only).

Official framing ([zyvor.dev/docs/netra](https://zyvor.dev/docs/netra), [Introducing Netra](https://zyvor.dev/blog/introducing-netra)):

> PacketWolf = Cilium-dependent full platform (15 intelligence modules). Netra = cgroup-v2 alone; Cilium/Hubble opt-in.

## Roles

| | **Netra** | **PacketWolf** |
|---|---|---|
| License / place | Zyvor Production License v1.0 | Suite flagship |
| CNI assumption | Any CNI / none | Cilium required |
| Datapath | Own maps under `/sys/fs/bpf/netra` (never touches Cilium maps); inspect desired contents with `netractl ebpf maps` | Hubble + Cilium maps + custom eBPF |
| Core job | Observe + Path/Drop/Congestion diagnostics + leased emergency deny | Observe + AutoPolicy + healer + root-cause + containment |
| Policy posture | Review-only drafts; enforce is time-leased and fails open | Learns and operates Cilium policy at platform depth |
| Surfaces | Web UI, `netractl`, `netra-mcp`, ChatOps | Web UI, TUI, `netpred`, CRDs/operator |

## How they fit in a fleet

```text
  Cilium is CNI of record ──────► PacketWolf (flagship)
  No Cilium / unsettled CNI ────► Netra (standalone)

  Optional overlay on a Cilium cluster:
    PacketWolf ── day-2 intelligence / AutoPolicy / platform containment
    Netra ─────── CNI-independent diagnostics + short-lease emergency deny
    Both may read Hubble Relay independently
```

**Pick Netra** when you need CNI-independent visibility and a fail-open emergency network kill-switch — including non-Cilium clusters — or a lighter containment layer next to an existing policy engine.

**Pick PacketWolf** when Cilium is already the CNI and you want the full intelligence / AutoPolicy / healer / operator stack.

**Run both on a Cilium cluster** only with clear ownership:

- PacketWolf owns day-2 network intelligence, AutoPolicy, and platform containment.
- Netra owns CNI-independent diagnostics (Path, Drop, Congestion Map, capture) and **short-lease** emergency denies that must not fight PacketWolf/Cilium policy long-term.
- Shared optional plane: both can read **Hubble Relay** independently; neither replaces the other’s control plane.
- Hard rule ([AGENTS.md](../AGENTS.md)): never pin over Cilium-owned BPF maps — co-presence is safe at the map layer if operators do not dual-enforce the same traffic.

## Data / control planes (no cross-product bus today)

```text
  Node traffic
       │
       ├──► Cilium eBPF ──► Hubble Relay ──► packetwolf-api (and optionally netrad)
       │
       └──► /sys/fs/bpf/netra ──► netra-agent ──► netrad ──► UI / MCP / SIEM
```

- Netra northbound: REST/SSE, SIEM pull (`/api/v1/export/*`), webhooks, MCP — see [siem-export.md](siem-export.md), [mcp-integration.md](mcp-integration.md).
- PacketWolf northbound: REST/WS `/api/v1/*`, partner trust, flow export, OTLP out.
- There is **no** Netra↔PacketWolf API sync, embed rail, or shared CRD today.

## Practical co-existence rules

1. **Different default markets** — Netra for mixed/non-Cilium clusters and as the easy entry point; PacketWolf for Cilium-standardized fleets.
2. **Same cluster is allowed but not required** — Netra’s maps are isolated; enable Hubble/CNP only if you want enrichment, not as PacketWolf’s datapath.
3. **Do not dual-own long-lived deny** — PacketWolf containment / Cilium NetworkPolicy for durable posture; Netra leases for incident kill-switch that auto-reverts.
4. **Export sideways, not into each other** — both can feed SIEM/Prometheus/webhooks independently if a third plane (Axiom, Forge, SOC) needs a unified view.
5. **Ops DNA is shared** — `scripts/lib/ensure-cilium-k3s.sh` and `ensure-hubble-relay.sh` mirror PacketWolf bootstrap patterns; that is packaging lineage, not runtime coupling.

## What “working together” is *not* (today)

- Not a parent/child product (Netra is not a PacketWolf agent).
- Not a shared eBPF loader or map namespace.
- Not a partner-API consumer of the other.
- Not a required install pair.

## Future integration (not built)

Natural join points if product work is prioritized later: PacketWolf partner trust consuming Netra SIEM/health; Netra MCP feeding Forge/Hermes; Axiom console deep-links to both; a single “network” rail that routes Cilium clusters → PacketWolf and others → Netra.

Operator guidance for east-west ownership: `GET /api/v1/insights/microseg` (`docs/microseg.md`).

## See also

- [competitive-quantum.md](competitive-quantum.md) — perimeter NGFW → Netra fit gaps (internal)
- [competitive-sse.md](competitive-sse.md) — cloud SSE / Zero Trust → Netra fit gaps (internal)
- [standalone-ebpf.md](standalone-ebpf.md) — Netra hook/map model
- [website architecture](../website/docs/core-concepts/architecture.md) — controller + agent layout
- [zyvor.dev/packetwolf](https://zyvor.dev/packetwolf) — PacketWolf product page
