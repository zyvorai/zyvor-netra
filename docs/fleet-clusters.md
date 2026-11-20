# Multi-cluster fleet (read-only)

`GET /api/v1/fleet` remains the single-cluster inventory.
`GET /api/v1/fleet/clusters` aggregates **this** controller plus optional
remote Netra peers — observe-only, no control-plane sync.
Parent: [`p0-p5-surfaces.md`](p0-p5-surfaces.md).

## How it works

1. Label this cluster with `NETRA_CLUSTER_NAME` (and optional
   `NETRA_CLUSTER_TENANT` for MSSP rollups).  
2. List peers as `name|url|apikey` or `name|url|apikey|tenant`.  
3. Controller polls each peer’s `GET /api/v1/fleet` best-effort and merges
   with local inventory. Per-peer errors are reported; local always returns.

```bash
export NETRA_CLUSTER_NAME=prod-east
export NETRA_CLUSTER_TENANT=acme   # optional partner/MSSP label
export NETRA_FLEET_PEERS='west|https://netra-west.example|APIKEY|acme,lab|https://netra-lab.example|APIKEY'
```

```text
GET /api/v1/fleet/clusters
GET /api/v1/fleet/tenants
netractl fleet-clusters
netractl fleet-tenants
```

**UX:** Surfaces → Fleet clusters / tenants; Fleet page.

Helm: `fleet.clusterName`, `fleet.clusterTenant`, `fleet.peers`.

Not SD-WAN. Axiom join can consume this later.

See [fleet-tenants.md](fleet-tenants.md), [competitive-quantum.md](competitive-quantum.md),
[buyers guide](sales/buyers-guide.md).
