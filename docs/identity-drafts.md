# Identity drafts (ServiceAccount join)

Joins Kubernetes **ServiceAccount** (plus recommended workload labels) with
observed egress hosts to produce **review-only** Zero Trust drafts and a
CiliumNetworkPolicy sketch keyed by
`io.cilium.k8s.policy.serviceaccount`.
Parent: [`p0-p5-surfaces.md`](p0-p5-surfaces.md).

## How it works

1. Agents report workloads with `serviceAccountName` from the Kubernetes
   pod inventory.  
2. Controller joins SA (+ labels) to observed egress SNI/Host/DNS.  
3. Emits identity-aware drafts and an optional CNP sketch — never applied.

```text
GET /api/v1/insights/identity-drafts
netractl insights identity-drafts
```

**UX:** Surfaces → Identity drafts.

Use PacketWolf or a leased Netra allow for incidents only.

See [zero-trust.md](zero-trust.md), [policy-packs.md](policy-packs.md),
[competitive-sse.md](competitive-sse.md), [buyers guide](sales/buyers-guide.md).
