# Zero Trust suggestions (review-only)

`GET /api/v1/insights/zero-trust` maps live dependency edges and SNI to
workload identity and emits **draft** allow-CIDR / review-external /
document-SNI suggestions. Nothing is applied.
Parent: [`p0-p5-surfaces.md`](p0-p5-surfaces.md).

## How it works

1. Build the observed dependency graph from agent flow/L7 metadata.  
2. Attribute edges to namespace/pod/workload identity.  
3. Emit draft actions operators can review:
   - allow-list known east-west CIDRs  
   - review unexpected external edges  
   - document recurring SNI destinations  

Durable NetworkPolicy remains **PacketWolf/Cilium** when present. Netra
drafts are for incident review and short-lease emergency patterns only.

```bash
netractl insights zero-trust
```

**UX:** Surfaces → Zero Trust drafts. Related: [`identity-drafts.md`](identity-drafts.md),
[`microseg.md`](microseg.md).

See [competitive-quantum.md](competitive-quantum.md), [buyers guide](sales/buyers-guide.md).
