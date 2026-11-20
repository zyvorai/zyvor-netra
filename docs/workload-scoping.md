# Workload-aware eBPF scoping — v0.8

Netra v0.8 adds Kubernetes-aware attribution and selected-workload enforcement without making the privileged node agent a Kubernetes API client.

## Identity pipeline

1. `netrad` reads Pod metadata with read-only `get/list pods` RBAC.
2. Each agent scans the host cgroup-v2 hierarchy at `NETRA_CGROUP_SCAN_INTERVAL` (default `10s`).
3. The agent derives the cgroup ID from the cgroup filesystem inode and recognizes Kubernetes pod UID/container-ID components in common systemd/cgroup paths.
4. The agent joins the local cgroup identity to the Pod inventory received from the authenticated controller endpoint.
5. cgroup packet/socket events and `workload_flow_stats` are enriched with namespace, pod, immediate controller owner, container ID and cgroup ID.

The privileged `netra-agent` ServiceAccount still has `automountServiceAccountToken: false`; Kubernetes metadata credentials never enter the node agent.
The default agent credential is cluster-wide rather than node-bound; a holder of that credential can request node-filtered Pod metadata for another node. Treat the agent key as a privileged cluster-agent secret and rotate it after node compromise.

## Enforcement modes

### `all`

This preserves the v0.7 behavior. Rules may enforce across descendant root-cgroup traffic and can therefore affect host/system services as well as Kubernetes workloads.

### `selected`

Only cgroup IDs matching one or more configured workload scopes are inserted into the `enforced_cgroups` BPF map. A scope may match:

- namespace;
- pod name;
- immediate owner kind/name;
- one or more exact labels;
- exact cgroup ID for non-Kubernetes/systemd targeting.

All supplied fields within one scope are ANDed. Multiple scopes are ORed.

In selected mode, traffic that cannot be attributed to a selected cgroup is allowed by the custom Netra enforcement layer. TCX/XDP continue collecting visibility but do **not** block because those hooks do not provide a trustworthy workload cgroup identity for this implementation.

Inspect the active scope from the map inventory:

```bash
netractl ebpf maps          # SCOPE section shows mode= + selectors
netractl ebpf scope show    # raw config JSON
```

See also [`ebpf-maps.md`](ebpf-maps.md).

## Preview before enforcement

Preview is metadata-based: it shows which Kubernetes Pods match the requested scope. Actual enforceable cgroup coverage is resolved independently on each node and is visible through agent status (`selectedCgroups`) and the dashboard node-coverage view.

A direct `cgroupID` scope may therefore preview as zero Pods while still resolving on an agent. Conversely, a newly created Pod may appear in the metadata preview before its local cgroup has been discovered. Selected mode remains fail-open while identity is unresolved.

## CLI examples

```bash
# inspect discovered Kubernetes workloads
netractl ebpf workloads

# preview in the UI/API first, then select all pods in a namespace
netractl ebpf scope selected --namespace payments

# select one owner (immediate ownerReference, for example ReplicaSet)
netractl ebpf scope selected --namespace payments --kind ReplicaSet --workload checkout-7cc884bb9

# select by exact label
netractl ebpf scope selected --namespace payments --label app=checkout

# return to node-wide behavior
netractl ebpf scope all

# inspect current configuration
netractl ebpf scope show
```

For multiple scopes, use `netractl ebpf scope set FILE` with the API JSON shape.

## Operational guidance

- Start in `observe` mode and verify workload attribution/topology before enabling a lease.
- Prefer `selected` mode for production emergency containment.
- Check every node's selected-cgroup count before assuming a scope is fully covered.
- Treat the owner name as the **immediate** Pod controller. A Deployment-managed Pod commonly reports its ReplicaSet owner in v0.8.
- Keep the cgroup filesystem mounted read-only into the agent.
- Do not treat labels or process names as cryptographic identity; they are operational selectors.
- If Pod metadata, cgroup discovery, or identity joining fails, selected-mode enforcement intentionally fails open for unresolved traffic.
