# Netra buyers guide

Customer-facing overview of what Netra is, what the recent observe-surface
program adds, how it works, and how to evaluate it. Pairs with the executive
deck and brochure in this folder.

| Asset | Use |
|---|---|
| [Product Perspective](./Zyvor-Netra-Product-Perspective.pdf) (PPTX too) | Short exec briefing |
| [Product Brochure](./Zyvor-Netra-Product-Brochure.pdf) (DOCX too) | Capability depth + suite placement |
| This guide | Evaluation narrative + P0–P5 feature map |
| Technical catalog | [`../p0-p5-surfaces.md`](../p0-p5-surfaces.md) |

Web downloads: https://zyvorai.github.io/netra/resources

---

## One-sentence pitch

**Netra** is standalone eBPF network observability and **leased** emergency
containment for Linux/Kubernetes: observe-first, CNI-independent, with
optional Cilium/Hubble enrichment — never a cloud SWG, ZTNA broker, or
decrypt proxy.

## Who should buy

| Buyer | Why Netra |
|---|---|
| Platform / SRE | Path, Drop, Congestion Map, and stack-deep loss when CNI verdicts look fine |
| SecOps / detection | Metadata threat boards (intel, JA3, DoH/DoT, shadow SaaS, exfil fan-out) without payload harvest |
| Network / CNI owners | Visibility that survives CNI change or mix; maps isolated under `/sys/fs/bpf/netra` |
| MSSP / partner ops | Multi-cluster + tenant risk rollups (read-only) |
| Risk / compliance | CIS-inspired network-hardening packs from live sysctl evidence (review-only) |

## Who should not buy Netra *instead of*

| Need | Better fit |
|---|---|
| Durable Cilium microseg / AutoPolicy depth | **PacketWolf** (suite mate) |
| Remote-user ZTNA / client agents / cloud PoP SWG | Cloud SSE vendors |
| Full HTTPS inspection, DLP, CASB content | SWG / CASB products |
| Signature IPS / malware sandbox | NGFW / IPS appliances |

Netra **complements** those classes with node-level metadata observe and
time-bounded kill-switches that **fail open**.

---

## What shipped in the P0–P5 program

Buyers evaluating perimeter NGFW or cloud SSE often ask: *“Can you see
encrypted traffic, unsanctioned SaaS, GenAI destinations, and multi-cluster
risk — without decrypt?”* Netra answers with observe-only surfaces.

### Encrypted traffic (no decrypt)

- **Always-on JA3/JA4** from a dedicated eBPF ClientHello sampler (plus capture)
- **DoT / DoH** visibility (port 853 + known DoH hosts via SNI/Host/DNS)
- **JA3 risk** and **ECH / missing-SNI** blindness boards

### Fit maps (SSE/ZT-adjacent, metadata only)

- **Shadow SaaS** vs operator allow-list (`NETRA_SANCTIONED_HOSTS`)
- **Workload digital experience** scorecard (latency / retrans / DNS fail)
- **Destination risk** ranking (intel + categories + exposure + volume)
- **Policy packs** and **identity drafts** — review-only Cilium sketches

### Threat & ops

- Live **threat-intel** feed → hits → optional **leased** apply
- **AI / MCP SaaS** destination catalog + optional leased SNI deny
- **Exfil fan-out** heuristics (not DLP), **lateral playbooks**, category deny drafts
- **Prevention coverage** report (`coverageScore`)
- Opt-in **auto-mitigate** for volumetric SYN/UDP (lease-gated)

### Fleet

- Multi-cluster aggregator + **tenant risk** scores for partner/MSSP views

### Console

All of the above are wired into the Netra dashboard **Surfaces** page
(Diagnostics + Security), with summaries on **L7**, **Fleet**, and **Report**.

Full technical map: [`../p0-p5-surfaces.md`](../p0-p5-surfaces.md).

---

## How Netra works (buyer-level)

```text
Workloads (pods / VMs / host)
        ↓
eBPF hooks (cgroup skb · connect · sockops · optional TCX/XDP)
        ↓
Netra maps under /sys/fs/bpf/netra  (agent-owned; never Cilium maps)
Inspect desired contents:  netractl ebpf maps   (docs/ebpf-maps.md)
        ↓
netra-agent → reports, capture stream, lease sync
        ↓
netrad (API · UI · HA) → operators (dashboard, CLI, MCP, ChatOps, SIEM)
```

**Observe** — flows, DNS/SNI/HTTP Host, JA3/JA4 samples, topology, TCP health.  
**Diagnose** — Path, Drop, Congestion Map, Explain, filtered capture + auto-PCAP.  
**Contain** — emergency deny / rate / Shield behind an observe→enforce **lease** that auto-reverts.

### Safety model buyers care about

1. Observe-first — enforce is never the silent default  
2. Plan-token + explicit risk confirm for policy apply  
3. Fail open — lease expiry, agent loss, restart, HA handoff → observe  
4. No payloads / argv / Secrets in reports or AI context  
5. Map isolation from Cilium  

---

## Competitive framing (honest)

| Theme | Cloud SSE / ZT class | Perimeter NGFW class | Netra |
|---|---|---|---|
| Job | Inline cloud broker + decrypt | Prevention-first DPI | Host eBPF observe + leased emergency |
| Encrypted intel | SSL inspect | SSL inspect | JA3/JA4 + DoH/DoT + ECH board |
| SaaS control | CASB content | App-ID DPI | Shadow SaaS + categories (metadata) |
| Exfil | DLP payloads | DLP / sandbox | Fan-out / volume heuristics |
| Microseg | Workload ZT | Zone policy | Drafts + PacketWolf for durable |
| Remote users | ZTNA | VPN / SD-WAN | Out of scope |

Internal strategy docs: SSE and NGFW comparisons avoid brand names
([`../competitive-sse.md`](../competitive-sse.md), [`../competitive-quantum.md`](../competitive-quantum.md)).
Peer eBPF observability gaps, which do name those products:
[`../competitive-observability.md`](../competitive-observability.md).

---

## Evaluation checklist

1. Run `netra-doctor` — cgroup v2, bpffs, BTF baselines.  
2. Deploy Helm observe-only — Overview, Path, Drop, Congestion Map.  
3. Open **Surfaces** — confirm JA3 (after TLS traffic), encrypted DNS, shadow SaaS (set `NETRA_SANCTIONED_HOSTS`).  
4. Load a small intel feed — see hits; do **not** apply until a lease drill.  
5. Exercise capture (and optionally auto-capture) on a non-prod signal.  
6. Pilot a **leased** deny with blast-radius preview; confirm auto-revert.  
7. If Cilium is present, decide enrichment vs PacketWolf ownership explicitly.  
8. Wire alerting / SIEM; keep AI/MCP read-only until trusted.

## Suite placement

| | **Netra** | **PacketWolf** |
|---|---|---|
| Default market | Mixed / non-Cilium; easy entry point | Cilium-standardized fleets |
| Core job | Observe + diagnostics + leased emergency | Observe + AutoPolicy + healer depth |
| Policy | Review-only drafts; enforce time-leased | Durable Cilium policy |

Same cluster is allowed; do not dual-own long-lived deny. Details:
[`../packetwolf.md`](../packetwolf.md).

## Talk to us

- Sales: sales@zyvor.dev  
- Product site: https://zyvor.dev/netra  
- Docs / downloads: https://zyvorai.github.io/netra/resources  

© 2026 Zyvor · Zyvor Production License v1.0
