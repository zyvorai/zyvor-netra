# P5 residual fit surfaces

Metadata-only follow-ons from the NGFW / SSE class maps after P0–P4.
No decrypt, no DLP payloads, no ZTNA. Parent catalog:
[`p0-p5-surfaces.md`](p0-p5-surfaces.md).

## Surfaces at a glance

| Surface | Endpoint | CLI | How it works |
|---|---|---|---|
| JA3 risk board | `GET /api/v1/ebpf/tls-fingerprints/risk` | `netractl ebpf tls-fingerprint-risk` | Ranks rare JA3 digests, missing SNI, and ECH (`0xfe0d`) from datapath + capture samples |
| ECH / missing SNI | `GET /api/v1/insights/ech-blind` | `netractl insights ech-blind` | HTTPS connect attempts without SNI; known ECH CDN suffixes; ECH ClientHello flags |
| DNS / C2 intel | `GET /api/v1/intel/dns-hits` | `netractl intel dns-hits` | Threat-feed DNS/SNI suffix match + high NX/failure ratio + light DGA-style label heuristics |
| Exfil heuristics | `GET /api/v1/insights/exfil` | `netractl insights exfil` | Per-workload fan-out, packet/byte volume, rare external hosts — **not** content DLP |
| Lateral playbooks | `GET /api/v1/insights/lateral` | `netractl insights lateral` | Turns scan-detect findings into review-only, lease-oriented operator steps |
| Category deny drafts | `GET /api/v1/insights/category-deny` | `netractl insights category-deny` | Review-only SNI deny suggestions from heuristic app categories |
| Fleet tenant risk | `GET /api/v1/fleet/tenants` | `netractl fleet-tenants` | MSSP/partner rollup with `RiskScore` from peer cluster labels |

## How each board is computed

### JA3 risk

Uses the same fingerprint store as `GET /api/v1/ebpf/tls-fingerprints`
(always-on `bpf/netra_tlsfp.c` + capture). Risk rows highlight:

- **Rare JA3** — digests seen on few workloads / low count  
- **Missing SNI** — ClientHello samples without a server name  
- **ECH** — extension `0xfe0d` present on the hello  

See [`tls-fingerprints.md`](tls-fingerprints.md).

### ECH / missing-SNI blindness

`internal/echblind` merges:

1. Workloads with HTTPS-looking connect attempts but no matching SNI metadata  
2. Destinations whose SNI/Host suffix matches known ECH-capable CDNs  
3. TLS fingerprint observations already flagged for ECH  

Observe-only — Netra cannot “open” ECH; the board tells operators where
hostname visibility is weak.

### DNS / C2 intel

`internal/dnsintel` walks agent DNS + SNI/Host metadata against the active
intel feed (exact + suffix) and adds heuristics (elevated failure/NX ratio,
long random-looking labels). Apply remains a **separate** leased step
(`POST /api/v1/intel/apply` or SNI/DNS deny).

### Exfil heuristics

`internal/exfil` aggregates per-workload unique destinations, external
destinations, packets/bytes, and hosts rare across the fleet. High fan-out
or rare-host volume raises score/severity. **No payload inspection.**

### Lateral playbooks + category deny

Review-only text/structured drafts. Nothing is applied; operators still
use plan-token + lease for any containment.

## Console

**Surfaces → Threat / Encrypted / Fleet** tabs. L7 shows JA3 + DoH/DoT
summaries; Fleet shows tenant risk.

## Boundaries

- No decrypt, no DLP, no ZTNA (for these surfaces; the separate, opt-in
  [`tls-plaintext.md`](tls-plaintext.md) is the one exception, and it exports only bounded metadata)  
- Drafts never auto-enforce  
- Pair with [`threat-intel.md`](threat-intel.md) and [`firewall.md`](firewall.md) for leased apply  

See [competitive-sse.md](competitive-sse.md), [competitive-quantum.md](competitive-quantum.md),
[tls-fingerprints.md](tls-fingerprints.md), [buyers guide](sales/buyers-guide.md).
