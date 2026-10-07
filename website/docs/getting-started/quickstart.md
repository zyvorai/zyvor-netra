---
sidebar_position: 1
---

# Quickstart

Netra is a single Helm chart with two workloads: a controller (`netrad`) and a
privileged node agent DaemonSet (**on by default**, one pod per node — like a
CNI agent). Pick the path that matches what you already have.

## Path A — Helm install (works with or without Cilium)

Netra doesn't require Cilium. This installs the controller **and** the node
agent against any Kubernetes cluster; if Cilium and Hubble Relay are already
running, Netra will also offer optional Cilium policy management and Hubble
flow viewing, but nothing here depends on it.

:::tip Installing a release
The chart pins its image tags to the version of the checkout, and only tagged releases have published
images (`0.28.0` was the first; use `0.30.0` or later). Clone a tag rather than `main`:
`git clone --branch v0.30.0 https://github.com/zyvorai/netra`. The images are signed; see
[Install from a release](https://github.com/zyvorai/netra/blob/main/deploy/README.md#install-from-a-release)
for the digests and the `cosign verify` command.
:::

```bash
make install   # netractl → /usr/local/bin (or PREFIX=$HOME/.local)

# Preferred — Cilium-style wrapper (agent+TLS on, installs CLI):
netractl install --namespace netra-system

# or classic Helm:
helm upgrade --install netra ./helm/netra \
  --namespace netra-system --create-namespace \
  --set auth.apiKey="$(openssl rand -hex 32)" \
  --set auth.agentKey="$(openssl rand -hex 32)"

kubectl -n netra-system port-forward svc/netra 30870:30870
curl -skf https://127.0.0.1:30870/livez
netractl status    # loopback skips self-signed verify automatically
```

Open `https://127.0.0.1:30870` (self-signed TLS by default, so expect a browser warning). Sign in with `admin` / `Admin@321` when the controller API key matches that demo token (or paste your `auth.apiKey` as the password). The nav bar: **Overview**, **Pods**, **VMs**, **Network Health**, **Path Diagnostics**, **Drop Diagnostics**, **L7 Metadata**, **Surfaces**, **Features**, **Insights**, **Firewall**, **Live flows**, **Policies**, **Audit**.

See [netractl CLI](./netractl) for PATH install, `~/.netra/env`, and
`NETRA_TLS_INSECURE` when talking to a NodePort over a non-loopback address.

| Page | What it's for |
|---|---|
| Overview | Agent/datapath health at a glance — Network Health score, L7 metadata, Insights summary |
| Pods / VMs | Pick a workload for scoped live flows, create/delete `CiliumNetworkPolicy` rules, one-click lock down / unlock |
| Network Health | TCP/DNS sockops health, anomalies, deterministic health score |
| L7 Metadata | TLS SNI / HTTP Host observation and leased SNI deny |
| Insights | Dependency graph, behavior/rate baselines, drift, exposure scoring, review-only policy drafts |
| Firewall | Every eBPF-enforced rule in one place — deny lists, DDoS shield, NetPol allow/default-deny |
| Live flows | Hubble stream when Cilium/Hubble is present, plus a 7-day flow history (pod, peer, port, RED, inferred paths). See the repo doc `docs/flow-log.md` |
| Policies | Guided `CiliumNetworkPolicy` builder + JSON workbench with preflight receipts |
| Audit | Bounded control-plane audit feed |

Controller-only (no privileged node agent):

```bash
helm upgrade --install netra ./helm/netra \
  --namespace netra-system --create-namespace \
  --set auth.apiKey="$(openssl rand -hex 32)" \
  --set auth.agentKey="$(openssl rand -hex 32)" \
  --set agent.enabled=false
```

## Path B — Remote full-stack script (K3s + Cilium + Netra)

For a fresh host with nothing installed yet: `scripts/deploy-remote.sh` bootstraps K3s, Cilium with Hubble Relay, then deploys Netra via Helm over SSH. The node agent is built and enabled by default on k3s/k8s profiles. The script also installs `netractl` onto PATH and writes `~/.netra/env` + `~/.netra/api-key` so bare `netractl status` works against the NodePort (self-signed TLS).

```bash
./scripts/deploy-remote.sh user@HOST --k8s
# on the host:
netractl status
```

Set `NETRA_AGENT_ENABLED=false` for controller-only, or `NETRA_AGENT_INTERFACES`/`NETRA_AGENT_XDP_INTERFACES` to attach TCX/XDP on specific interfaces. Run without `--quick` to rebuild images from source; with `--quick` to reuse whatever's already built on the host.

## Path C — Local binaries (development)

```bash
make install
go run ./cmd/netrad
netractl status   # defaults to https://127.0.0.1:30870; loopback skips self-signed verify
```

Requires a reachable Kubernetes API; Hubble is optional (`NETRA_HUBBLE_ADDR`, default `hubble-relay.kube-system.svc:80`).

## Smoke-test the API

```bash
curl -skf https://HOST:30870/api/v1/ebpf/health | head
curl -skf https://HOST:30870/api/v1/ebpf/l7 | head
curl -skf https://HOST:30870/api/v1/flows/summary?number=50 | head
curl -skf "https://HOST:30870/api/v1/flows/history?since=1h&limit=20" | head
curl -skf "https://HOST:30870/api/v1/insights/red?window=5m" | head
curl -skf https://HOST:30870/api/v1/insights/summary | head
```

```bash
netractl ebpf health
netractl ebpf maps                 # desired deny/allow/rate inventory
netractl ebpf l7
netractl flows summary --direction EGRESS
netractl flows history --since 1h --limit 20
netractl insights red 5m
netractl insights summary
netractl explain --all --format json   # passive, read-only — see docs/explain.md
netractl ai brief                      # heuristic by default, no config needed — see docs/ai.md
```

## Next steps

- [netractl CLI](./netractl) — PATH install, TLS/`~/.netra`, status and features.
- [Architecture](../core-concepts/architecture) — how the controller, agent, and eBPF datapath fit together.
- [Security](../security) — the threat model, fail-open guarantees, and what to review before production.
- [Optional kernel sensors](../core-concepts/sensors) — drop attribution, TCP events, listen queues, and the opt-in sampled-protocol and TLS sensors.
- [Access control and export](../core-concepts/access-and-export) — OIDC roles, mutual TLS, Prometheus objects, and OTLP/Loki/syslog push.
- [How Netra is tested](../core-concepts/verification) — what CI proves, including install, upgrade and rollback on a real cluster.
