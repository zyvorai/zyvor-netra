# Fleet tenants (partner / MSSP read views)

Extends multi-cluster fleet aggregation with optional **tenant** labels for
partner or MSSP rollups. Observe-only — no cross-tenant mutation or
control-plane sync. Parent: [`p0-p5-surfaces.md`](p0-p5-surfaces.md).

## How it works

1. Set `NETRA_CLUSTER_TENANT` on each controller.  
2. Optional 4th peer field: `name|url|apikey|tenant`.  
3. `GET /api/v1/fleet/tenants` groups clusters by tenant and computes a
   **`RiskScore`** from available inventory signals (stale agents, deny
   pressure, detector findings — see API `note`).

```bash
export NETRA_CLUSTER_NAME=prod-east
export NETRA_CLUSTER_TENANT=acme
# Peer format: name|url|apikey|tenant  (tenant optional)
export NETRA_FLEET_PEERS='west|https://netra-west.example|APIKEY|acme,lab|https://netra-lab.example|APIKEY|contoso'
```

```text
GET /api/v1/fleet/clusters   # includes tenant per cluster
GET /api/v1/fleet/tenants    # rollup by tenant
netractl fleet-clusters
netractl fleet-tenants
```

**UX:** Surfaces → Fleet tenants; Fleet page.

Helm: `fleet.clusterName`, `fleet.clusterTenant`, `fleet.peers`.

See [fleet-clusters.md](fleet-clusters.md), [competitive-sse.md](competitive-sse.md),
[buyers guide](sales/buyers-guide.md).
