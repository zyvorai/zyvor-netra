# Install, build and CLI examples

Moved from the README.

## Prerequisites

Standalone mode requires Linux with cgroup v2, bpffs at `/sys/fs/bpf`, and kernel BPF support. The ring-buffer-based implementation has a practical **Linux 5.8+** baseline; use a modern LTS kernel in production. TCX is optional and has a newer kernel requirement (Linux 6.6+ is the practical baseline used by this project). XDP support depends on the selected interface/driver and is off unless explicitly configured.

Before deploying the privileged node agent, run `netra-doctor` (see `docs/host-readiness.md`) to verify cgroup v2, bpffs, BTF, tracefs and related host gates. Use `--require-tcx` / `--require-drop-reasons` when those optional features are mandatory.

Build requirements are Go 1.27, Node 22 and Clang/LLVM with a BPF target.

## Build

```bash
make build            # web + binaries into ./bin
make install          # netractl → /usr/local/bin (or PREFIX=$HOME/.local)
make uninstall
# or manually:
npm --prefix web install
npm --prefix web run build
go mod tidy
go test ./...
go build ./cmd/netrad ./cmd/netractl ./cmd/netra-agent
make bpf
```

Container images:

```bash
docker build -t ghcr.io/zyvorai/netra:0.30.0 .
docker build -f Dockerfile.agent -t ghcr.io/zyvorai/netra-agent:0.30.0 .
```

Tagged releases publish both images (`linux/amd64` and `linux/arm64`) to `ghcr.io/zyvorai/netra` and
`ghcr.io/zyvorai/netra-agent`, signed with keyless cosign. To install a release rather than build one, see
[Install from a release](../deploy/README.md#install-from-a-release).

## Standalone Helm install

Generate independent API and agent credentials. The privileged **node agent
DaemonSet is on by default** (one pod per node, `tolerations: Exists` — same
coverage idea as a CNI agent). Opt out with `--set agent.enabled=false` for a
controller-only install.

```bash
# Install netractl onto PATH, then install the cluster:
make install                          # → /usr/local/bin/netractl (or PREFIX=$HOME/.local)
netractl install --namespace netra-system
# netractl install also copies itself onto PATH (use --skip-cli to opt out).
# or classic Helm:
helm upgrade --install netra ./helm/netra \
  --namespace netra-system --create-namespace \
  --set auth.apiKey="$(openssl rand -hex 32)" \
  --set auth.agentKey="$(openssl rand -hex 32)"
```

Then:

```bash
# After make install / deploy-remote, netractl reads ~/.netra/env + api-key.
# Loopback skips self-signed verify automatically; NodePort needs:
#   export NETRA_TLS_INSECURE=true   # or use ~/.netra/env from deploy
netractl status
netractl features list
netractl features enable dns-detect --yes
```

See [`docs/netractl.md`](netractl.md) (CLI, TLS, `~/.netra`) and
[`docs/features.md`](features.md) (feature catalog / API / UX).
This uses cgroup hooks and requires neither Cilium nor a configured interface. TCX can be enabled for explicit interfaces or all up non-loopback interfaces:

```bash
--set agent.interfaces=eth0
# or
--set agent.interfaces=auto
```

XDP is deliberately explicit:

```bash
--set agent.xdpInterfaces=eth0
```

Do not enable XDP blindly across interfaces; validate driver/kernel compatibility and desired policy scope first.

**Upgrades are tested.** CI (`scripts/ci-kind-lifecycle.sh`) installs the previous release, writes rules and a
baseline, runs `helm upgrade --reset-then-reuse-values` to the checkout, and asserts the state, the API key and
the mode (`observe`) survive, the agent DaemonSet starts and reports, a controller pod restart keeps the state, and
`helm rollback` returns to the previous release with its state still readable.

### Optional Cilium + Hubble

```bash
helm upgrade --install netra ./helm/netra \
  --namespace netra-system --reuse-values \
  --set cilium.enabled=true \
  --set hubble.enabled=true
```

`cilium.enabled=true` renders CiliumNetworkPolicy RBAC. `hubble.enabled=true` makes the controller connect to `hubble-relay.kube-system.svc:80` unless `hubble.address` is overridden.

For plain manifests, see `deploy/README.md`. `deploy/rbac-cilium.yaml` is intentionally separate and optional.

## eBPF CLI examples

```bash
# After make install / deploy-remote, netractl reads ~/.netra/env + api-key.
# Chart TLS is self-signed: loopback skips verify automatically; or:
#   export NETRA_TLS_INSECURE=true
#   export NETRA_URL=https://<node-ip>:30870
#   export NETRA_API_KEY=$(cat ~/.netra/api-key)

netractl ebpf summary
netractl ebpf maps              # human map inventory (desired deny/allow/…)
netractl ebpf maps --json
netractl ebpf census            # counts only
netractl ebpf coverage          # programs / missing pins
netractl ebpf capabilities
netractl ebpf health
netractl ebpf workloads
netractl ebpf scope show

# preview/select workload scope before enforcement
netractl ebpf scope selected --namespace payments --label app=checkout

# rules can be staged while observe-only
netractl ebpf deny add 203.0.113.10
netractl ebpf deny add 2001:db8::10
netractl ebpf cidr add 10.0.0.0/8 egress
netractl ebpf port add TCP 22 both
netractl ebpf uid add 1000
netractl ebpf process add curl
netractl ebpf dns add telemetry.example.com
netractl ebpf rate set 203.0.113.50 1500

# enforcement is leased, never permanent by default
netractl ebpf mode enforce 15m
netractl ebpf mode observe
```

The same controls are available in the **Firewall** dashboard page, including workload scope preview, discovered workloads, per-node selected-cgroup coverage and workload topology.

Behavior Insights CLI:

```bash
netractl insights summary
netractl insights dependencies
netractl insights baseline capture
netractl insights drift
netractl insights recommendations prod checkout

# time-window rate intelligence
netractl insights rates 5m
netractl insights rate-baseline capture 5m
netractl insights rate-drift 5m
netractl insights exposure 5m
netractl insights remediations 5m
```

AI briefs (heuristic by default; see `docs/ai.md`):

```bash
netractl ai status
netractl ai brief
netractl ai digest
netractl ai draft deny dns malware.example
netractl ai explain dns-failure high SERVFAIL ratio
netractl ai ask why is DNS failing in kube-system?
```

## Safety and persistence

Netra is secure-by-default: the controller requires independent API and agent credentials unless `NETRA_ALLOW_UNAUTHENTICATED=true` is explicitly set for local development. The privileged agent uses a tokenless ServiceAccount. The controller alone receives read-only `get/list` RBAC for Pods and Services to provide workload attribution and dependency resolution; Cilium RBAC remains opt-in.

Controller state is restart-durable when `NETRA_STATE_FILE` is configured. Active/passive HA uses Kubernetes Lease election plus a shared state-file lock. A leader transition or controller restart never resurrects an old eBPF enforcement lease: the datapath returns to observe first.

See the [Security](https://zyvorai.github.io/netra/docs/security) docs page, `docs/standalone-ebpf.md`, `docs/workload-scoping.md`, `docs/behavior-insights.md`, `docs/rate-insights.md`, and `docs/high-availability.md` before production deployment. CI (`.github/workflows/ci.yml`) runs the current, living validation checks (Go build/vet/test, web typecheck/test/build, Helm lint/render, and a real `clang` BPF compile check) on every push.
