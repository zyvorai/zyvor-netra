# Repository layout

```text
cmd/netrad/             controller/API/UI server
cmd/netractl/           operator CLI
cmd/netra-agent/        standalone privileged node agent
cmd/netra-doctor/       read-only host readiness preflight
cmd/netra-mcp/          MCP server: controller API as stdio tools + prompts for AI agents
cmd/netra-ci-*/         CI helpers: capture client (the browser's side of a capture), synthetic feeder, fake OIDC provider
internal/ai/             heuristic briefs + optional OpenAI-compatible rewrite
internal/agent/          BPF loading, hook attachment and reporting
internal/doctor/         host readiness checks used by netra-doctor
internal/observability/  standalone eBPF summaries and workload topology
internal/health/          TCP/DNS/connect health scoring and anomaly signals
internal/l7/              TLS SNI / HTTP Host / socket-attempt aggregation
internal/insights/         dependency graph, behavior/rate baselines, drift, exposure and drafts
internal/cgroupmeta/     cgroup-v2 Kubernetes path/inode discovery
internal/workload/       workload selector matching and cgroup joins
internal/api/            REST/SSE API
internal/store/          durable state, audit and preflight receipts
internal/siem/           CEF/syslog/JSONL/OTLP formatters + optional syslog push
internal/report/         point-in-time operator briefing builder
internal/playbook/       review-only operator steps from a report snapshot
internal/intel/          threat-intel preview + live feed (apply is lease-gated)
internal/ainet/          GenAI/MCP SaaS destination catalog (metadata observe)
internal/automitigate/   optional leased volumetric auto-mitigation
internal/auditstats/     actor/action/hour rollup of the audit log
internal/coverage/       per-node hook/program coverage matrix
internal/ebpfmaps/       read-only desired map inventory (CLI/API)
internal/denycensus/     deny/allow entry counts (no entry echo)
internal/ha/             active/passive controller leader election
internal/kube/           direct Kubernetes REST client
internal/hubble/         optional native Hubble gRPC client
internal/policy/         optional CiliumNetworkPolicy planning
internal/tcpevents/      TCP retransmit / reset / state-change tracepoints (bpf/netra_tcpevents.c), layouts read from the kernel
internal/dropinfo/       per-connection kernel drop attribution: tuple, reason, dropping function (bpf/netra_dropinfo.c, needs BTF)
internal/tpformat/       tracepoint `format` parser (record layouts and reason tables are read from the running kernel)
internal/ksym/           kernel address to symbol through /proc/kallsyms
internal/kmsg/           bounded, scrubbed view of kernel log lines
internal/listenq/        TCP accept-queue depth per listener through inet_diag
internal/mapscan/        cheap full scans of BPF hash maps (batched reads, bounded top-N)
internal/l7sample/       sampled protocol observation: Redis, Postgres, MySQL, Kafka, HTTP/1, HTTP/2, gRPC (bpf/netra_l7sample.c)
internal/sslprobe/       opt-in TLS plaintext sampling through OpenSSL uprobes (bpf/netra_ssl.c)
internal/mtls/           optional mutual TLS between agent and controller
internal/oidcauth/       OIDC/JWT verification and role mapping (viewer/operator/admin)
internal/otlppush/       OTLP/HTTP push of metrics, logs and spans
internal/lokipush/       Loki push of audit and block events
internal/pushfeed/       delivery logic shared by the push sinks (watermarks, bounded batches)
internal/slo/            network SLOs and burn rates
internal/workloadobs/    per-workload counters with a hard cardinality cap
bpf/netra_tc.c          standalone eBPF programs/maps (the core datapath)
bpf/netra_*.c           optional sensors, each its own object: edge_intel, capture, tlsfp, tcpevents, dropinfo, l7sample, ssl
scripts/ci-*.sh         one script per CI job (real controller, agent, kernel, cluster or browser); docs/ci.md maps them
scripts/lib/veth-lab.sh shared controller + agent + veth setup for the real-agent CI scripts
web/                     React/Vite dashboard
helm/netra/             Helm chart
deploy/                  plain manifests
docs/packetwolf.md       suite placement vs PacketWolf (counterparts, not a pipeline)
docs/standalone-ebpf.md  eBPF hook/map/limitation reference
docs/ebpf-maps.md         read-only map inventory (`netractl ebpf maps`)
docs/workload-scoping.md workload attribution/scoping runbook
docs/netractl.md          operator CLI: install, TLS, status, features, maps
docs/l7-metadata.md      metadata-only L7 behavior and limitations
docs/behavior-insights.md dependency/inventory-baseline/drift/recommendation runbook
docs/rate-insights.md     time-window rate baseline, exposure and remediation runbook
docs/high-availability.md HA runbook
docs/host-readiness.md    netra-doctor host readiness runbook
docs/drop-detective.md    conntrack + policy Drop Detective
docs/kernel-network-diagnostics.md sysctl/counter correlation and safe tuning workflow
docs/tcx-and-shield.md    TCX modes + XDP Shield
docs/native-netpol.md     optional native NetPol maps: v1 deny-list + v2 allow-list/default-deny
docs/fluxvm-borrow-backlog.md deferred FluxVM eBPF patterns
docs/alerting.md          multi-channel notify + alert poller; opt-in auto-capture env
docs/siem-export.md       pull-based SIEM encodings + operator report
deploy/grafana/           Prometheus dashboard JSON for the existing /metrics gauges
docs/process-metadata.md  optional /proc-derived process metadata (agent-side, hostPID opt-in)
docs/mcp-integration.md   MCP server runbook: tool reference, security, plan/apply flow, troubleshooting
docs/ai.md                heuristic briefs + optional LLM rewrite: HTTP/CLI/MCP surface, safety boundaries
docs/ipv6-diagnostics.md  IPv6 extension-header/fragmentation counters and anomalies
docs/interface-flow-attribution.md per-interface flow counters (TC/TCX hooks only)
docs/chatops.md           Slack ChatOps: slash commands, confirmation flow, Ask Netra integration
docs/chatops-teams.md     Microsoft Teams ChatOps: bot setup, confirm-by-reply flow, validation status
docs/syn-drop.md          SYN-drop mode: exact-IP and CIDR variants, kernel-verified CI coverage
docs/edge-tcp-intel.md    standalone TCX edge observer: handshake/RTT histograms, retransmit/RST/FIN counters
docs/capture.md           packet capture: eBPF vs AF_PACKET, auto-capture PCAPs, veth+iperf3 CI smoke
docs/tutorials/drop-incident-context.md  walkthrough: enable drop context, read it, reproduce with iperf3
docs/tls-fingerprints.md  JA3/JA4 datapath + encrypted DNS; openssl+iperf3 CI smoke
docs/p0-p5-surfaces.md    P0–P5 observe surface catalog (what / how / UX / APIs)
docs/p5-surfaces.md       P5 residual boards (JA3 risk, ECH, exfil, lateral, …)
docs/sales/               buyer guide + PDFs/PPTX + the brochure source (`brochure/`) — also on GitHub Pages /resources
docs/sales/buyers-guide.md evaluation narrative for buyers (P0–P5 + checklist)
docs/flow-log.md              queryable 7-day flow history, RED, inferred traces, stacks, kernel notes, pod warnings
docs/agent-map-reads.md           How the agent reads its BPF maps
docs/agent-mtls.md                Agent ↔ controller mutual TLS
docs/app-categories.md            App / category catalog
docs/auth-oidc-rbac.md            OIDC login, roles, and a locked-down `/metrics`
docs/blast-radius.md              Multi-hop blast radius (`internal/insights.BlastRadius`)
docs/capability-gated-deny.md     Capability-gated socket deny
docs/competitive-sse.md           Cloud SSE / Zero Trust → Netra feature gaps
docs/compliance.md                Compliance packs
docs/destination-risk.md          Destination risk scoring
docs/drop-explain.md              Unified Drop Explain
docs/drop-info.md                 Kernel drop attribution
docs/experience.md                Workload digital experience
docs/exporter-tetragon-borrow-backlog.md Patterns borrowed from Cloudflare ebpf_exporter and Cilium Tetragon
docs/fleet-clusters.md            Multi-cluster fleet (read-only)
docs/fleet-tenants.md             Fleet tenants (partner / MSSP read views)
docs/gitops.md                    Policy-as-code / GitOps reconciliation (`internal/gitops`)
docs/identity-drafts.md           Identity drafts (ServiceAccount join)
docs/investigation-ux.md          Native investigation UX
docs/l7-sampling.md               Sampled L7 protocol observation
docs/listen-queues.md             TCP listen-queue pressure
docs/netlink-recorder.md          Route / link / address / neighbor change recorder (read-only)
docs/bpf-attachments.md           BPF programs attached per interface + Netra hook drift (read-only)
docs/loki-push.md                 Loki push export
docs/microseg.md                  East-west microsegmentation guidance
docs/network-health.md            Netra Network Health — v0.10
docs/node-resources.md            Node Resources
docs/otlp-push.md                 OTLP push export
docs/policy-packs.md              Sanctioned-app policy packs
docs/prevention-report.md         Prevention coverage report
docs/protocol-downgrade.md        TLS→cleartext protocol-downgrade correlation
docs/quic-observed.md             QUIC-observed traffic counter
docs/shadow-saas.md               Shadow SaaS (CASB-lite)
docs/snowflake-export.md          Snowflake export
docs/sysctl-audit.md              Netra Sysctl Audit
docs/tcp-events.md                TCP event tracepoints
docs/tls-plaintext.md             TLS plaintext sampling (OpenSSL uprobes)
docs/udp-flow-health.md           UDP flow health beyond DNS
docs/workload-metrics-slo.md      Per-workload metrics, SLOs, and Prometheus Operator objects
docs/zero-trust.md                Zero Trust suggestions (review-only)
docs/competitive-observability.md  shipped observe versus Hubble-class and eBPF APM peers
docs/ci.md                     every CI job, the use case it proves, its script and how to run it locally
```
