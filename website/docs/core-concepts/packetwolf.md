---
sidebar_position: 5
---

# Suite placement (PacketWolf)

Netra and **PacketWolf** are Zyvor suite counterparts covering the same eBPF territory from opposite directions — not a wired pipeline.

| | **Netra** | **PacketWolf** |
|---|---|---|
| License | Zyvor Production License v1.0 | Suite flagship |
| CNI | Any / none (cgroup v2) | Cilium required |
| Datapath | `/sys/fs/bpf/netra` only | Hubble + Cilium maps + custom eBPF |
| Enforce | Time-leased, fails open to observe | Platform containment + AutoPolicy |
| Reach for | Non-Cilium fleets, lighter emergency kill-switch, Path/Drop/Congestion diagnostics | Cilium-standardized fleets needing full intelligence / operator tooling |

**On a Cilium cluster:** PacketWolf owns day-2 network intelligence; Netra may run alongside for CNI-independent diagnostics and short-lease emergency denies. Both may read Hubble Relay independently. Netra never pins over Cilium-owned BPF maps.

There is no Netra↔PacketWolf API sync, shared CRD, or required install pair today. SIEM/Prometheus/webhooks export sideways into a third plane if you need a unified view.

Full co-existence rules: repository [`docs/packetwolf.md`](https://github.com/zyvorai/zyvor-netra/blob/main/docs/packetwolf.md).

**Next:** [Architecture](./architecture.md) · [Security](../security.md) · [zyvor.dev/packetwolf](https://zyvor.dev/packetwolf)
