# Netra Behavior Insights — v0.11

Netra v0.11 turns exact standalone eBPF counters into a workload dependency graph, a persisted known-good behavior inventory, drift findings, and review-only Cilium policy drafts. This layer does not require Cilium to observe or detect drift; Cilium is only needed if an operator chooses to use a generated CiliumNetworkPolicy draft.

## Dependency graph

`GET /api/v1/insights/dependencies` joins the latest non-stale node-agent flow counters with read-only Kubernetes Pod and Service metadata.

Targets are resolved in this order:

1. Kubernetes Service ClusterIP → `service:<namespace>:<name>`
2. Pod IP → immediate owner when available, otherwise Pod
3. anything else → `external:<ip>`

Only workload-attributed egress counters are used for the graph. The controller gets read-only `get/list` access to Pods and Services. The privileged node agent remains tokenless.

The graph is an observation product, not a service-discovery authority. Headless Services do not have a ClusterIP and therefore cannot be resolved through ClusterIP matching alone.

### Troubleshooting an empty graph

`GET /api/v1/insights/dependencies` (and the dashboard's Topology page) can render with no nodes/edges for two different reasons:

1. **Transient Kubernetes API failures blanking workload attribution.** `GET /api/v1/ebpf/config?node=<node>` fetches that node's Pod inventory from the Kubernetes API on every agent sync; the agent then joins its scanned cgroups against that inventory (`internal/workload.Resolve`) to attribute flow counters to a Namespace/Pod/WorkloadName. A single failed fetch (429, timeout, brief apiserver unavailability) used to leave that inventory empty for the request, which `Resolve` treats as "this node genuinely has zero workloads" and blanks every cgroup's identity — silently dropping that node's counters from the dependency graph until the next successful fetch. The controller now keeps a last-known-good inventory per node (`internal/api.workloadInventoryCache`) and falls back to it on a fetch error instead, so a single transient failure no longer empties the graph. If you still see this, check the controller logs for `"load node workload inventory"`: a `using last-known-good` message means the cache caught a real fetch failure (worth investigating apiserver health/rate limits); a plain failure message with no fallback means that node has never had a successful fetch at all (check the controller's Kubernetes RBAC/connectivity).
2. **Attribution disabled or unsupported at the agent.** Only workload-attributed egress counters feed the graph (see above). If `NETRA_CGROUP_ENABLED` is off, or the node's cgroup-skb hooks aren't attaching, no attributed counters exist to graph in the first place — this is a deployment/config issue, not a controller bug, and won't be fixed by the cache above.

## Known-good baseline

`POST /api/v1/insights/baseline` captures a persistent set of behaviors from non-stale agents:

- destination IP + destination port + protocol;
- DNS qname;
- TLS SNI;
- cleartext HTTP Host;
- remote TCP/UDP port use.

The baseline is stored in the same atomic controller state file as Netra policy history and eBPF configuration. HA failover therefore preserves it.

This is deliberately an **inventory baseline**, not a statistical rate baseline. It answers “is this behavior new since the known-good capture?” It does not claim that a lifetime counter implies a traffic spike.

Noise floors are applied before a new behavior becomes a finding: isolated one-off DNS/SNI/flow observations do not immediately create drift noise.

## Drift

`GET /api/v1/insights/drift` compares current non-stale agent state with the persisted baseline. New exact destinations and SNI are warning-level findings; new DNS/HTTP-host/remote-port behaviors are informational unless another health signal raises concern.

A finding remains visible until the baseline is recaptured or cleared. Recapture is an explicit operator decision because it accepts current behavior as known-good.

## Policy recommendations

`GET /api/v1/insights/recommendations` creates **review-only** CiliumNetworkPolicy drafts from observed dependencies when Netra can resolve a stable workload selector.

- Kubernetes Service destinations use Cilium `toServices` references.
- Direct IP destinations use exact `/32` or `/128` CIDRs.
- Repeated TLS SNI names can contribute `toFQDNs` rules on TCP/443.
- kube-dns access is included because FQDN policy and most applications require DNS.
- Only observed TCP/UDP destinations with a concrete destination port are translated into L4 rules.

Every generated object contains:

```text
netra.zyvor.dev/generated=observed-traffic
netra.zyvor.dev/review-required=true
```

Netra never automatically applies a recommendation. Observed traffic is not proof that all application paths, failover paths, maintenance jobs, disaster-recovery flows, or rare control-plane calls have been exercised. Review the draft, run Netra preflight, inspect the risk result, and then explicitly apply it through the normal policy path if appropriate.

## CLI

```bash
netractl insights summary
netractl insights dependencies
netractl insights baseline capture
netractl insights baseline show
netractl insights drift
netractl insights recommendations prod checkout
netractl insights baseline clear
```

Clearing a baseline requires an explicit confirmation header in the API; `netractl` adds it only for the `baseline clear` command.

## API

```text
GET    /api/v1/insights/summary
GET    /api/v1/insights/dependencies
GET    /api/v1/insights/baseline
POST   /api/v1/insights/baseline
DELETE /api/v1/insights/baseline
GET    /api/v1/insights/drift
GET    /api/v1/insights/recommendations
```

## Security boundaries

Behavior Insights does not collect additional packet payload. It consumes metadata already emitted by Netra's standalone maps and Kubernetes Pod/Service metadata available to the controller.

Recommendations are not enforcement. There is intentionally no “auto-learn then auto-deny” path in v0.11. This avoids converting incomplete observation into an outage-causing allowlist without an explicit operator review.
