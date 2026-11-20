# Netra quick start

Operator CLI details (PATH install, self-signed TLS, `~/.netra`):
[`docs/netractl.md`](docs/netractl.md).

## Path A — Helm on an existing Cilium cluster

```bash
make install   # netractl → /usr/local/bin

netractl install --namespace netra-system
# or:
helm upgrade --install netra ./helm/netra \
  --namespace netra-system --create-namespace \
  --set auth.apiKey="$(openssl rand -hex 32)" \
  --set auth.agentKey="$(openssl rand -hex 32)"

kubectl -n netra-system port-forward svc/netra 30870:30870
curl -skf https://127.0.0.1:30870/livez
netractl status
```

Open the UI at `https://127.0.0.1:30870` (self-signed TLS by default). Nav: **Overview**, **Pods**, **VMs**, **Network Health**, **Path Diagnostics**, **Drop Diagnostics**, **L7 Metadata**, **Surfaces**, **Features**, **Insights**, **Policies**, **Live flows**, **eBPF**, **Audit**.

- **Overview** — agents/datapath pulse plus Network Health score, L7 metadata, and Insights summary.
- **Pods / VMs** — pick a workload for scoped live flows, create/delete CNP rules, lock down / unlock.
- **Network Health** — TCP/DNS sockops health, anomalies, health score.
- **L7 Metadata** — TLS SNI / HTTP Host observation and leased SNI deny.
- **Insights** — dependency graph, behavior/rate baselines, drift, exposure scoring, review-only CNP drafts and remediations.
- **Policies** — guided builder + JSON workbench with preflight receipts.
- **Live flows** — Hubble stream plus `flows/summary` aggregates (verdicts, top destinations).
- **eBPF** — observe/enforce lease, scope, deny rules, workloads, topology.

## Path B — Remote full stack (K3s + Cilium + Netra)

SSH host gets K3s (or uses existing), Cilium with Hubble Relay, then Netra via Helm. Also installs `netractl` on PATH and writes `~/.netra/env` for self-signed NodePort access:

```bash
./scripts/deploy-remote.sh HOST USER --k8s
# on the host:
netractl status
# if the pod did not pick up a same-tag image rebuild:
kubectl -n netra-system rollout restart deploy/netra
```

Or with the container helper:

```bash
./scripts/deploy-container.sh user@YOUR_HOST
```

## Path C — Local binaries

```bash
make install
go run ./cmd/netrad
netractl status
```

Requires reachable Kubernetes API. Hubble Relay is optional (`NETRA_HUBBLE_ADDR`, default `hubble-relay.kube-system.svc:80`).

### Smoke APIs

```bash
curl -skf -H "Authorization: Bearer $(cat ~/.netra/api-key)" https://HOST:30870/api/v1/status | head
curl -skf -H "Authorization: Bearer $(cat ~/.netra/api-key)" https://HOST:30870/api/v1/features | head
```

```bash
netractl status
netractl features list
netractl ebpf health
netractl ebpf l7
netractl flows summary --direction EGRESS
netractl insights summary
netractl explain --all --format json   # passive, read-only — see docs/explain.md
netractl ai brief                      # heuristic by default, no config needed — see docs/ai.md
```

## Suite note

Netra is the standalone eBPF counterpart to PacketWolf (Cilium-first). See
[`docs/packetwolf.md`](docs/packetwolf.md).
