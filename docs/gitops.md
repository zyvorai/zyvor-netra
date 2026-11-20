# Policy-as-code / GitOps reconciliation (`internal/gitops`)

Optional, off-by-default mode of `netrad` (not a separate binary or sidecar) that reconciles a local directory of YAML CiliumNetworkPolicy manifests against the live cluster through the exact same plan → preflight → apply pipeline a human operator's Preflight → Apply click in the Policies dashboard already uses.

## Why this is a mode of `netrad`, not a new process

The reconciler needs the same `*kube.Client`/`*store.Store` the currently-elected leader already owns. A separate GitOps controller process would need either its own leader-election mechanism (a second source of truth for "who's allowed to write") or awkward IPC with `netrad` to share one — both worse than reusing the leader-election Netra already has. There is no second election mechanism here: whichever replica currently holds write access to the store is the only one that ever runs a reconciler.

## Bridging a Git repository

`netrad` itself stays Git-agnostic. Point `NETRA_GITOPS_DIR` at a local directory kept in sync with a Git ref by an operator-supplied sidecar — the same `git-sync`-style pattern Argo CD and Flux both use — rather than teaching `netrad` to speak Git directly. With `gitops.enabled: true`, the chart creates an `emptyDir` volume named `gitops-manifests`, mounted read-only into the `netrad` container at `gitops.dir` (default `/gitops/policies`) — the chart does **not** include the sync sidecar itself; patch the Deployment to add your own container mounting that same volume name (read-write) and writing your manifests into it.

## Enabling it

```bash
helm upgrade --install netra ./helm/netra --reuse-values \
  --set gitops.enabled=true \
  --set gitops.dir=/gitops/policies \
  --set gitops.autoApply=false
```

Or directly via environment variables on `netrad`:

| Var | Default | Notes |
|---|---|---|
| `NETRA_GITOPS_DIR` | unset | Local directory of `*.yaml`/`*.yml` CiliumNetworkPolicy manifests (flat, non-recursive — matches `git-sync`'s own checkout layout). Unset disables GitOps entirely. |
| `NETRA_GITOPS_AUTO_APPLY` | `false` | See below. |
| `NETRA_GITOPS_INTERVAL` | `60s` | Reconcile pass cadence. |

**Runs in both HA and non-HA mode.** In HA mode the reconciler starts and stops with `ha.Gate`'s own `Promote`/`Demote` — the same cancellation lifecycle `internal/alert.Poller` already uses there, so only the currently-elected leader ever reconciles. In a single non-HA replica there is structurally only one writer already, so the reconciler simply runs for the process's lifetime.

## What `NETRA_GITOPS_AUTO_APPLY=false` (the default) does

The reconciler still runs every `NETRA_GITOPS_INTERVAL`, loads every manifest, and computes a `ChangePlan` for each — but applies nothing. `GET /api/v1/policies/gitops/status` shows exactly what *would* happen. This matches this project's existing "a human clicks Apply after seeing a risk badge" pattern everywhere else in the Policies workbench (Preflight → dry-run → Apply, NetPol v2's plan → confirm-risk → apply) — an unattended process silently applying cluster policy on a schedule is a real departure from that, so it's opt-in.

## What auto-apply does and does not do

With `NETRA_GITOPS_AUTO_APPLY=true`, a manifest is auto-applied only when **all** of the following hold:

- Its live policy differs from the candidate (or the policy doesn't exist yet).
- Its live policy has **not drifted** from the last revision GitOps itself applied (see below).
- Its computed risk is `low` or `medium`.

A `high`/`critical`-risk change is **never** auto-applied, regardless of this setting — it surfaces in `gitops/status` as pending, same as a drifted policy, and resolving it requires the same explicit human step either way.

## Drift: a hand-edit outside Git is never silently overwritten

Every apply GitOps performs is recorded in the same revision history (`store.RecordPolicyRevision`, actor `"gitops"`) manual applies use. Before considering a new candidate, the reconciler compares the **live** policy against the **last revision GitOps itself applied** (via `internal/policy.AnalyzeChange` again — not a new comparator). A difference there means someone hand-edited the policy outside of Git since GitOps last touched it — the reconciler calls this **drift**, flags it in `gitops/status`, and never applies over it, auto-apply setting notwithstanding.

Resolving drift (or applying a pending high/critical-risk change) requires an explicit call:

```bash
netractl policy gitops status
netractl policy gitops resync path/to/candidate.yaml --confirm-risk high   # only if risk is high/critical
```

`POST /api/v1/policies/gitops/resync` applies the given candidate through the identical pipeline, bypassing the reconciler's own auto-apply gating — the same `X-Netra-Confirm-Risk` semantics as `POST /api/v1/policies/apply` for high/critical risk. This is a deliberate override: a human explicitly resyncing has already made the call the reconciler itself declines to make unattended.

## Evidence boundaries

- **Every apply lands in the same audit trail and revision/rollback UI as a manual apply.** No parallel audit mechanism — `AddAudit`/`RecordPolicyRevision` are called exactly as `internal/api/server.go`'s `applyPolicy` handler already calls them, tagged with actor `"gitops"`.
- **A brand-new policy is a real change even though `ChangePlan.SpecChanged` doesn't say so.** `internal/policy.AnalyzeChange`'s own "policy doesn't exist yet" branch never touches `SpecChanged` — this package checks `!plan.Exists || plan.SpecChanged` everywhere it decides whether to apply, not `SpecChanged` alone. This was caught and fixed during implementation via a regression test; without it, GitOps would silently never create a single new policy, only update already-existing ones.
- **One bad manifest file never blocks the others.** A YAML parse failure, or a file that fails `AnalyzeChange` for any reason, is recorded as a per-manifest error in the status response and reconciliation continues with the rest.
- **Server-side dry-run runs before every real apply**, exactly like a manual Preflight — a failing dry-run blocks the apply and is reported as an error, never silently retried or skipped.
- **`gitops/status` is cached, not live-computed per request** — it reflects the most recent completed reconcile pass (`LastRun`), not the instant you called the endpoint.

## Validation

`internal/gitops`'s unit tests cover: YAML→JSON manifest loading (including multi-document files and a malformed file not blocking the rest), auto-apply of a low-risk change, plan-only behavior when auto-apply is off, high/critical risk never auto-applying, a no-op when live already matches candidate, drift detection correctly blocking auto-apply after a hand-edit, and `resync` bypassing that same gating with its own risk-confirmation requirement. `internal/api`'s tests cover the two HTTP handlers, including the 409 when GitOps isn't enabled and the confirm-risk header requirement end to end against a fake Kubernetes backend.

**Live-cluster HA-failover check: done (2026-09-14, 0.27.47, against a live single-node k3s cluster).** The first attempt (see the 0.27.47 CHANGELOG entry) found and fixed a real, unrelated bug instead of completing the test: `internal/kube.TryAcquireOrRenewLease`/`ReleaseLease` formatted Lease timestamps with a layout a real Kubernetes API server's `metav1.MicroTime` decoding rejects outright, so HA leader election had never actually worked against a real cluster — only against the fake HTTP backend `internal/kube`'s own unit tests use. That shipped as 0.27.47 with a new regression test.

With the fix live, the actual failover test then succeeded cleanly: with `ha.enabled=true`/`replicaCount=2`, exactly one replica acquired the `netra-controller` Lease and logged `"controller promoted"`; its GitOps reconciler applied a test `CiliumNetworkPolicy` (`"gitops applied"`), while the standby replica's logs showed **zero** lease or GitOps activity the entire time. Deleting the leader's pod triggered a clean failover: the standby (already running the fixed image) acquired the lease, logged `"controller promoted"`, and its own reconciler applied the still-pending manifest — again with no activity at all from the sibling pod. This directly confirms the property this check exists to establish: `gate.Promote`/`Demote` correctly prevents double-reconciliation across replicas.

Caveats worth recording: this single-node k3s test cluster has no ReadWriteMany-capable StorageClass, so a throwaway hostPath-backed PV/PVC stood in for the chart's real RWX requirement — a genuine multi-node RWX backend (NFS, CephFS, etc.) is still unverified, though the leader-election/reconcile-exclusivity property itself doesn't depend on which RWX backend is used. Two unrelated operational mistakes were made and corrected during this test, both from Helm's behavior of pruning any templated resource that stops being rendered between revisions: pointing `auth.existingSecret`/`persistence.existingClaim` at the same names Helm had been chart-managing caused it to delete the live `netra-auth` Secret and the `netra-state` PVC (the latter's data was **not recoverable** — the cluster's `local-path` StorageClass uses a `Delete` reclaim policy — though this only cost operational audit/history rows, not any live Cilium policy or enforcement state). Both were restored/recreated before finishing. Anyone repeating this test on a cluster whose `netra-auth`/`netra-state` hold real data should use different secret/claim names for the test, not the production ones.
