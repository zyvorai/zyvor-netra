# AGENTS.md

Instructions for coding agents working in this repository.

## What Netra is

Standalone eBPF network observability and emergency network control for
Linux/Kubernetes. Observe-first. Custom enforcement is lease-bounded and
fails open to observe. The node agent owns programs under
`/sys/fs/bpf/netra`. Cilium/Hubble are optional.

Suite counterpart to PacketWolf (Cilium-first flagship): same eBPF territory
from the opposite direction — not a dependency, agent, or API consumer of
PacketWolf. Co-existence rules: `docs/packetwolf.md`.

## Hard boundaries

- Never modify or pin over Cilium-owned BPF maps.
- Do not collect application payloads, argv/cmdline, or Secret contents.
- Do not add an MCP SDK or LLM SDK dependency. `internal/mcpserver` and
  `internal/ai` are stdlib-only.
- Mutating MCP tools must stay behind `NETRA_MCP_ALLOW_MUTATIONS`.
- Policy apply stays plan-token + risk confirm. Enforce stays leased.
- Do not wire a PacketWolf↔Netra control-plane sync unless product work
  explicitly requests it (today they export sideways only).
- The BPF attachment inventory (`internal/bpfattach`, `GET /api/v1/ebpf/attachments`)
  is read-only: it lists what the kernel reports and never attaches, detaches or
  replaces a program, and never touches a Cilium-owned program or map.
  Details: `docs/bpf-attachments.md`.
- The netlink recorder (`internal/netlinkwatch`, `GET /api/v1/netlink`) is
  read-only RTNL observation. Never add a route/link/address/neighbor/rule
  mutation to it or wire it to one. Its requester attribution (`internal/rtnlactor`,
  `bpf/netra_rtnl.c`) records only comm, pid and cgroup of the requester, the
  interface (index or name) and, for a route, its destination: never argv,
  environment or any other part of the message. Details: `docs/netlink-recorder.md`.
- The per-second metrics platform (`internal/tsdb`, `internal/collectors`,
  `internal/metricstream`, `internal/anomaly`, `internal/metricalert`,
  `internal/metricexport`, `/api/v1/metrics/*`) is observe-only. Collectors
  never write to what they read; the process collector groups by comm (and
  cgroup) and never reads `cmdline` or `environ`; app collectors take
  credentials only from operator config or environment variables, never from
  Kubernetes Secrets through the API. `internal/tsdb`, `internal/anomaly` and
  `internal/metricstream` stay stdlib-only. Metric alerts only notify (ack and
  silence change notification state, nothing else) and are never wired to
  mode/rule/policy apply. Details: `docs/metrics.md`, `docs/metric-alerts.md`,
  `docs/anomaly-detection.md`, `docs/app-collectors.md`.
- Security review (`internal/securityreview`, `/api/v1/security/*`, MCP
 `netra_security_*` and `netra_intel_history`) is read-only: it suggests and
 correlates, never deletes a rule, applies a deny or quarantines. Threat-feed
 updates, rollback and HTTPS refresh never apply deny entries; applying a feed
 stays leased with `X-Netra-Confirm-Risk: high`. Details: `docs/security-review.md`.
- New source files need the `LicenseRef-Zyvor-Production-1.0` SPDX header used everywhere else.
- P0–P5 observe surfaces catalog: `docs/p0-p5-surfaces.md`. Buyer narrative:
  `docs/sales/buyers-guide.md`.

## AI surface

- Heuristic briefs + optional OpenAI-compatible rewrite: `internal/ai`,
  `GET/POST /api/v1/ai/*` (`status`, `brief`, `ask`, `agent`, `draft`,
  `digest`, `suggestions`, `explain`), `netractl ai`, MCP `netra_ai_*`
  plus `netra://ai/*` resources.
- Multi-step NL graph: in-process `POST /api/v1/ai/agent` (`internal/ai.Run`,
  stdlib-only) and the optional Python companion `python/netra_langgraph/`
  (LangGraph extra). Docs: `docs/ai.md`, `docs/langgraph.md`,
  `docs/mcp-integration.md`.
- Datapath map inventory (read-only): `docs/ebpf-maps.md`,
  `netractl ebpf maps [--json]`, `GET /api/v1/ebpf/maps`, MCP
  `netra_ebpf_maps`.
- Briefs, digests and explain cite raised metric alerts and the most anomalous
  metrics (`ai.Snapshot.Metrics`, built in `internal/api/ai_metrics.go`); reading
  them never acks or silences an alert.
- AI endpoints are read-only. Do not wire them to mode/rule/policy apply.
  Do not import LangGraph/LangChain into Go.

## Validation before a PR

```bash
make fmt
go test ./...
./scripts/ci-tlsfp-unit.sh
./scripts/ci-p1-p5-unit.sh
./scripts/ci-netlink-unit.sh
./scripts/ci-bpfattach-unit.sh
./scripts/ci-metrics-unit.sh
./scripts/ci-deploy-guards.sh
make test-features
make test-netractl-commands
make test-netractl-live
make test-python
npm --prefix web run test
# eBPF compile + PROG_TEST_RUN (Linux root):
#   sudo ./scripts/ci-ebpf-tests.sh
# Live smokes (Linux root):
#   sudo ./scripts/ci-tlsfp-smoke.sh
#   sudo ./scripts/ci-auto-capture-veth.sh
#   sudo ./scripts/ci-flow-observe-veth.sh
#   sudo ./scripts/ci-netlink-veth.sh
#   sudo ./scripts/ci-metrics-veth.sh
# Live lab full netractl command board (not smoke):
#   ./scripts/ci-netractl-remote.sh
```

CI jobs live in `.github/workflows/ci.yml` (`go`, `web`, `helm`, `ebpf`,
`auto-capture-veth`, `flow-observe-veth`, `metrics-veth-smoke`, `netlink-veth-smoke`, `tlsfp-smoke`). Scripted gates:

| Script | Job / step |
|---|---|
| `scripts/ci-p1-p5-unit.sh` | `go` — P1–P5 package + API surface unit/race |
| `scripts/ci-tlsfp-unit.sh` | `go` — tlsfp + API JA3 unit/race |
| `scripts/ci-ebpf-tests.sh` | `ebpf` — C helpers, clang objects, bpfintegration |
| `scripts/ci-tlsfp-smoke.sh` | `tlsfp-smoke` — agent + openssl + iperf3 |
| `scripts/ci-auto-capture-veth.sh` | `auto-capture-veth` — AF_PACKET + iperf3 + drop context |
| `scripts/ci-flow-observe-veth.sh` | `flow-observe-veth` — veth + iperf3 flow history, RED, traces, stacks |
| `scripts/ci-netlink-unit.sh` | `go` — netlink recorder ring/cursor, resubscribe, controller history, API, metrics |
| `scripts/ci-deploy-guards.sh` | `go` — deploy-remote.sh disk guard, image GC repair, readiness wait, script ordering |
| `scripts/ci-bpfattach-unit.sh` | `go` — BPF attachment inventory, hook drift, carry-forward, API, metrics |
| `scripts/ci-netlink-veth.sh` | `netlink-veth-smoke` — real RTNL in a throwaway netns, forced ENOBUFS overrun |
| `scripts/ci-http-status-smoke.sh` | `http-status-smoke` — agent + cleartext HTTP/1 503 |
| `scripts/ci-govulncheck.sh` | `security` — reachable vulnerable deps, minus justified `scripts/govulncheck-ignore.txt` entries |
| `scripts/ci-metrics-unit.sh` | `go` — tsdb, collectors, app collectors, stream, anomalies, metric alerts, exporters, metrics APIs |
| `scripts/ci-metrics-veth.sh` | `metrics-veth-smoke` — real collectors + netrad, iperf3 on a veth, anomaly flagged, alert fires |

The auto-capture smoke needs Linux root + iperf3; run locally with
`sudo ./scripts/ci-auto-capture-veth.sh` when changing alert/auto-capture
or AF_PACKET paths (see `docs/capture.md`). The flow-observe smoke needs
Linux root + iperf3; run `sudo ./scripts/ci-flow-observe-veth.sh` when
changing flow history, RED, traces, or profiles (see `docs/flow-log.md`).
The metrics smoke needs Linux root + iperf3 and takes about two minutes
(a quiet phase trains the anomaly models); run `sudo ./scripts/ci-metrics-veth.sh`
when changing collectors, the metrics stream, anomaly detection or metric
alerts (see `docs/metrics.md`).
The HTTP/1 status smoke needs Linux root + clang; run
`sudo ./scripts/ci-http-status-smoke.sh` when changing
`netra_http_status_*` or `http_status_stats` (see `docs/l7-metadata.md`).
The TLSFP smoke needs Linux
root + clang + openssl + iperf3; run `sudo ./scripts/ci-tlsfp-smoke.sh`
when changing `bpf/netra_tlsfp.c` or agent JA3 wiring (see
`docs/tls-fingerprints.md`).
