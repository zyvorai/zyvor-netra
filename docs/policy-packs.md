# Sanctioned-app policy packs

Builds **review-only** `CiliumNetworkPolicy` manifests that allow egress to
operator-sanctioned hostname suffixes observed in live SNI / HTTP Host / DNS
metadata. Netra never applies these packs.
Parent: [`p0-p5-surfaces.md`](p0-p5-surfaces.md).

## How it works

1. Operator configures the same allow-list used by shadow SaaS
   (`NETRA_SANCTIONED_HOSTS`).  
2. Controller finds which sanctioned suffixes appear in live metadata,
   grouped by namespace + recommended workload labels.  
3. Emits a pack with `toFQDNs` egress on port 443 (CNP sketch).  

Prefer PacketWolf (or `kubectl apply` after change-control) for durable
enforcement.

```bash
export NETRA_SANCTIONED_HOSTS='office.com,okta.com,github.com,slack.com'
```

```text
GET /api/v1/insights/policy-packs
netractl insights policy-packs
```

**UX:** Surfaces → Policy packs.

Pairs with [shadow-saas.md](shadow-saas.md) (unsanctioned board) and
[competitive-sse.md](competitive-sse.md), [buyers guide](sales/buyers-guide.md).
