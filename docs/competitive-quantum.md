# Perimeter NGFW → Netra feature gaps

Internal product strategy. Compares Netra to a typical perimeter / hybrid
**NGFW** class of product (threat prevention, SD-WAN/SASE, HTTPS inspection,
GenAI/MCP destination security, volumetric DDoS, IoT/OT gateways).

Netra should **not** become an NGFW. Gaps below are filtered to what fits
Netra’s mandate (observe-first eBPF + leased emergency deny) and what
[PacketWolf](packetwolf.md) may own instead.

## Positioning

| | **Perimeter NGFW (class)** | **Netra (today)** |
|---|---|---|
| Job | Perimeter / hybrid firewall + threat prevention + SD-WAN/SASE | **CNI-independent** eBPF observe + stack diagnostics + **leased** emergency deny |
| Datapath | Appliance / virtual / cloud gateway, L1–7 DPI | Host cgroup/TCX/XDP maps under `/sys/fs/bpf/netra` (inventory: `netractl ebpf maps`) |
| Default posture | Block threats (prevention-first) | Observe-first; enforce time-bounded and fails open |
| Payload | HTTPS inspection / malware / sandbox | Explicitly **no** payloads, argv, Secrets |
| Suite mate | Vendor console / MSSP portal | PacketWolf = Cilium-first platform depth |

## NGFW pillars → Netra status

| NGFW theme | Netra today | Gap for Netra? |
|---|---|---|
| NGFW / IPS / zero-day / malware / sandbox | No signature IPS; scan/DNS detectors are metadata heuristics | **Adjacent only** — signature IPS/sandbox = non-goal |
| Threat intelligence feeds | Live feed ingest + observe hits + optional leased apply (`docs/threat-intel.md`) | **Shipped (P0)** — still metadata + lease-gated |
| Unified hybrid mesh policy | Single cluster controller + HA | **Yes (lite)** — multi-cluster / fleet view; not branch appliances |
| SD-WAN / SASE / VPN / remote users | None | **No** — out of scope |
| DDoS / volumetric | XDP Shield + SYN-flood detect + optional auto SYN-drop (`docs/auto-mitigate.md`) | **Partial → P0 shipped** — strengthen further as needed |
| App control (10k+ apps) | HTTP Host / SNI / DNS name only | **Partial** — richer labels without decrypt |
| HTTPS inspection / TLS 1.3 decrypt | SNI-only ClientHello | **No decrypt**; **Yes** — TLS fingerprint (JA3/JA4), DoT/DoH |
| GenAI + MCP traffic security | Wire observe of known LLM/MCP SaaS destinations (`docs/ai-destinations.md`) | **Shipped (P0)** — observe + optional leased deny |
| Agentic policy orchestration | Read-only AI + gated MCP mutations | **Partial** — intent→draft; do not auto-enforce |
| IoT / OT / SCADA | Host/container focus | **Low** unless OT Linux appears |
| Central console / MSSP | Dashboard + SIEM + ChatOps | **Partial** — compliance packs, not managed SOC |
| Hyperscale appliance cluster | Controller HA + agent DaemonSet | Different problem; OK for K8s |

## Prioritized backlog

### P0 — Table stakes that fit Netra (implemented)

1. **Live threat-intel pipeline** — ingest list → match live flows → alert/hits + optional leased deny. See [`threat-intel.md`](threat-intel.md).
2. **AI / MCP / LLM SaaS traffic awareness** — SNI/Host catalog match; optional leased deny. See [`ai-destinations.md`](ai-destinations.md).
3. **Stronger volumetric mitigation** — SYN-flood findings → optional leased SYN-drop + notify. See [`auto-mitigate.md`](auto-mitigate.md).

### P1 — Differentiation without becoming an NGFW (implemented)

4. **TLS fingerprinting (JA3/JA4) + DoH/DoT visibility** — always-on datapath (`bpf/netra_tlsfp.c`) + capture-stream JA3/JA4; DoT port 853 + DoH host catalog. See [`tls-fingerprints.md`](tls-fingerprints.md).
5. **Fleet / multi-cluster Netra** — `GET /api/v1/fleet/clusters` + `NETRA_FLEET_PEERS`. See [`fleet-clusters.md`](fleet-clusters.md).
6. **Identity-aware Zero Trust suggestions** — review-only drafts. See [`zero-trust.md`](zero-trust.md).
7. **Threat-prevention-style effectiveness reporting** — coverage snapshot. See [`prevention-report.md`](prevention-report.md).

### P2 — Nice-to-have / suite-owned (implemented)

8. **App/category catalog** — heuristic CDN/SaaS labels. See [`app-categories.md`](app-categories.md).
9. **Compliance packs** — CIS-inspired network hardening from sysctl-audit. See [`compliance.md`](compliance.md).
10. **East-west microseg guidance** — PacketWolf on Cilium; Netra lease drafts otherwise. See [`microseg.md`](microseg.md).

### P5 — Residual metadata fit (implemented)

See [`p5-surfaces.md`](p5-surfaces.md) and [`competitive-sse.md`](competitive-sse.md)
(JA3 risk, DNS/C2 intel, ECH blindness, exfil heuristics, lateral playbooks,
category deny drafts, tenant risk scores).

## Explicit non-goals

- Hardware / hyperscale appliances
- SD-WAN, SASE, client VPN, remote-user agents
- Full HTTPS/TLS interception, malware sandbox, AV unpacking
- Signature IPS / IDS replacing CNI policy engines
- OT/SCADA protocol deep inspection appliances
- Prevention-first default (breaks observe-first + fail-open lease model)

## See also

- [p0-p5-surfaces.md](p0-p5-surfaces.md) — full feature catalog + UX wiring
- [sales/buyers-guide.md](sales/buyers-guide.md) — buyer evaluation narrative
- [competitive-sse.md](competitive-sse.md) — cloud SSE / Zero Trust fit gaps
- [competitive-observability.md](competitive-observability.md) — eBPF NPM / APM gaps
- [packetwolf.md](packetwolf.md) — suite co-existence
- [firewall.md](firewall.md) — leased deny model
- [AGENTS.md](../AGENTS.md) — hard boundaries for contributors
