# Validation record — Netra v0.14.0 (historical, frozen)

> **Historical snapshot, not a living document.** This is a one-time, point-in-time
> validation record from the v0.14.0 release cycle, written from an offline build
> environment with no outbound package resolution — several checks it lists as
> "environment-gated" (full `go test`, real BPF verifier load, Helm lint, npm
> build) are exactly what `.github/workflows/ci.yml`'s `go`/`web`/`helm`/`ebpf`
> jobs now run automatically on every push. Treat CI as the current, living
> validation record; this file is kept only for historical reference.

Validated on 2026-09-11 in the artifact build environment.

## Passed locally

- `gofmt` on all modified Go sources.
- Dependency-free Go regression tests passed for:
  - `internal/dropdiag`
  - `internal/pathdiag`
  - `internal/health`
  - `internal/insights`
  - `internal/store`
  - `internal/observability`
  - `internal/workload`
  - `internal/flowstats`
  - `internal/policy`
  - `internal/cgroupmeta`
  - `internal/l7`
  - `cmd/netractl`
- `go vet` passed for the same packages.
- `internal/dropdiag` tests cover aggregation, anomaly generation, and stale-agent exclusion.
- Strict eBPF C syntax passed with `clang -Wall -Wextra -Werror -fsyntax-only`.
- Plain deployment YAML and GitHub Actions workflow YAML parsed successfully.
- JSON examples parsed successfully.
- `sh -n hack/smoke.sh` passed.
- TypeScript compiler was invoked; React/Vitest/lucide packages are not installed in this offline workspace, so expected missing-module/JSX diagnostics were produced, with no TS1xxx parser-class diagnostics.
- Active release files were checked for v0.14.0 consistency; Go module was restored to `go 1.27.0` / `toolchain go1.27.1` after local dependency-free tests.

## v0.14 drop-diagnostics coverage

- New `kernel_drops` pinned map, separate from all existing map ABIs.
- `raw_tracepoint/kfree_skb` program increments cumulative kernel drop-reason counters using the third tracepoint argument.
- Agent checks tracefs for an explicit `skb_drop_reason` field before attaching the optional raw tracepoint.
- Agent reads Linux `/proc/net/softnet_stat` processed/drop/time-squeeze counters.
- Agent reads interface `rx_dropped`, `tx_dropped`, `rx_errors`, `tx_errors`, `rx_missed_errors`, and `rx_nohandler` counters.
- New `GET /api/v1/ebpf/drops` API.
- New `netractl ebpf drops` command.
- New Drop Diagnostics web page.
- New low-cardinality Prometheus drop/stack gauges.
- Kernel drop reasons remain node-level; Netra does not fabricate Pod/workload attribution.

## Upstream interface verification

The v0.14 agent uses `link.AttachRawTracepoint(link.RawTracepointOptions{Name: "kfree_skb", Program: p})`, matching the `github.com/cilium/ebpf` raw-tracepoint API used by the project dependency. The running-kernel tracepoint is still validated at runtime before attachment.

## Environment-gated checks

The build environment has Go 1.23.2 and no outbound package resolution. The release targets Go 1.27.0 / toolchain 1.27.1, and external Cilium/eBPF/gRPC modules are not available in the local module cache. Therefore the following remain GitHub CI/integration gates:

- full `go test ./...`, `go vet ./...`, and builds of `netrad`, `netra-agent`, and dependency-using packages;
- real `clang -target bpfel` object generation and Linux BPF verifier/load testing;
- actual `raw_tracepoint/kfree_skb` attachment on representative production kernels;
- npm dependency installation, full React typecheck/tests/build;
- Helm lint/render because Helm is not installed locally;
- live Kubernetes/Cilium/Hubble integration testing.

The optional kernel-drop hook failing to attach does not fail the agent: softnet/interface diagnostics and the rest of the standalone datapath remain available.

## Lab verification (zyvor) — v0.14

Executed after merge into the Netra lab tree (Apple CSS, TLS NodePort 30870, Insights null-safety, Overview/Flows/path wiring preserved):

- `go test ./...` including `internal/dropdiag` and `web` production build
- `GET /api/v1/ebpf/drops` registered (routes test) and Drop Diagnostics UI shipped
- Deploy via `NETRA_ALLOW_UNAUTHENTICATED=true ./scripts/deploy-remote.sh 212.8.248.187 sus --k8s`
- Console smoke: Overview drop pulse, Drop Diagnostics page, Path/Insights/Health/L7

