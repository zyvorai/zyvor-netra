# Netra controller high availability

Netra v0.7 retains the active/passive controller HA introduced in v0.6. Kubernetes `coordination.k8s.io/v1` Lease election chooses a single active replica. A candidate is not promoted until it also acquires the shared state file lock.

## Storage requirements

All controller replicas mount the same state directory. The volume must:

- be `ReadWriteMany` when more than one replica is scheduled;
- provide coherent atomic rename and fsync behavior;
- provide reliable POSIX advisory file locking (`flock`) across nodes.

CephFS, NFS implementations with working locking, or another Kubernetes RWX filesystem are typical choices. Object-store FUSE mounts that do not provide coherent filesystem locks are not appropriate for the Netra state file.

If auto-capture is enabled (`alerting.autoCapture` / `NETRA_AUTO_CAPTURE`), PCAP artifacts under `NETRA_AUTO_CAPTURE_DIR` are written by the **leader** only. Put that directory on the same RWX volume as the state file (the chart mounts it under the state PVC when persistence is enabled) so a failover does not orphan in-flight PCAPs on the old leader's local disk. See `docs/capture.md`.

## Election defaults

| Setting | Default |
|---|---:|
| Lease duration | 15s |
| Renew deadline | 10s |
| Retry period | 2s |
| Helm replicas in HA examples | 3 |

The invariant is `leaseDuration > renewDeadline > retryPeriod`. A leader that cannot renew for the renew deadline demotes itself before another replica is expected to be able to take over an expired Lease.

## Promotion sequence

1. Replica acquires or renews the Kubernetes Lease.
2. Replica opens the shared state file and acquires the exclusive file lock.
3. Persisted state is loaded. Any old emergency eBPF enforcement lease is forced to `observe`.
4. The API handler is installed behind the leader gate.
5. `/readyz` starts returning HTTP 200 and the Kubernetes Service can route traffic to that Pod.

If the storage lock cannot be acquired, the replica releases the Lease and stays unready.

## Demotion sequence

1. `/readyz` flips to HTTP 503 and new API requests are rejected.
2. Existing in-flight requests drain.
3. The state file is closed and its exclusive lock is released.
4. On graceful shutdown, the Kubernetes Lease is released immediately.

If Kubernetes API connectivity is lost, the current leader may continue serving only until the configured renew deadline. It then demotes even if no successor is available.

## Durable and ephemeral data

Durable across leader change:

- CiliumNetworkPolicy revision history;
- audit events;
- fast-path configuration (deny/allow-exception/CIDR/port/UID/process/DNS/SNI/rate entries, Shield, NetPol);
- unexpired preflight receipts.

Intentionally ephemeral:

- agent reports and stale-age snapshots;
- process-local Prometheus counters;
- live Hubble streams.

Agents repopulate node reports after the new leader is reachable. Hubble streams are re-established by clients.

## Preflight safety across failover

A successful policy plan persists its body-bound receipt before returning it. Applying a policy persists receipt consumption before the Kubernetes mutation is allowed to continue. Therefore an unused receipt can survive failover, while a used receipt cannot be replayed after failover.

## Helm example

```bash
helm upgrade --install netra ./helm/netra \
  --namespace netra-system --create-namespace \
  --set auth.apiKey="$(openssl rand -hex 32)" \
  --set auth.agentKey="$(openssl rand -hex 32)" \
  --set ha.enabled=true \
  --set replicaCount=3 \
  --set 'persistence.accessModes[0]=ReadWriteMany' \
  --set persistence.storageClass=<rwx-storage-class>
```

For an existing PVC, set `persistence.existingClaim`. The chart cannot verify that claim's access mode or locking semantics, so validate them independently.

## Verification

```bash
kubectl -n netra-system get pods -l app.kubernetes.io/name=netra
kubectl -n netra-system get lease netra-controller -o yaml
kubectl -n netra-system get endpoints netra
```

Exactly one controller Pod should be Ready. The Service endpoints should contain only that Pod. To test graceful failover, delete the Ready Pod and watch the Lease holder and endpoint move. To test abrupt failover, terminate the leader node or force-delete the leader Pod and verify takeover after Lease expiry.

After every leadership change, confirm `/api/v1/status` reports the new `controllerIdentity` and the Netra eBPF `fastPath.mode` is `observe` before re-enabling emergency enforcement.

### Tested in CI

`scripts/ci-ha-kind.sh` (nightly job `ha-kind`) installs the chart with two replicas on a real
kind cluster with a shared ReadWriteMany volume and asserts: exactly one replica is Ready and
holds the Lease; the standby is alive (`/healthz` 200) but refuses API calls (503); there is never
a sample with two Ready replicas; killing the leader without warning and deleting it gracefully
both promote the standby (within 60 s and 45 s respectively); rules written before the failover are
served by the new leader; an enforcement lease is not carried across the change (mode `observe`);
and the replaced pod returns as the standby. It runs on a one-node cluster, so it proves the election
and the shared-state lock, not a cross-node RWX filesystem.
