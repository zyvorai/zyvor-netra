# Capabilities

Full catalog of what Netra observes and controls. Moved from the README; the README carries the short pitch.

## Observability

- IPv4 and IPv6 source:port → destination:port flow counters with packets, bytes and blocked counts.
- Ingress/egress and hook attribution (`cgroup`, optional `tcx`, optional `xdp`, socket hooks).
- TCP, UDP, ICMP and ICMPv6 visibility; TCP flag metadata for parsed TCP packets.
- Sampled flow-header events without application payload collection.
- Cleartext UDP/53 DNS query-name events.
- Socket context for new TCP connect / UDP sendmsg operations: PID, UID, cgroup ID and Linux process `comm`.
- Kubernetes attribution on cgroup traffic: namespace, pod, immediate owner, container ID and cgroup ID.
- Exact workload network topology derived from cgroup-attributed tuple counters.
- TCP connection health from cgroup sockops: active/passive establishes, closes, SRTT/min RTT, retransmissions, RTOs, congestion window, segments and byte counters.
- TCP path diagnostics from sockops: active connect-establishment latency, `packets_out`/`snd_cwnd` pressure, `lost_out`, `retrans_out`, cumulative retransmits, delivered-rate samples, MSS and TCP state.
- Exact TCP SYN/SYN-ACK/FIN/RST counters by cgroup.
- Cleartext UDP/53 DNS request/response latency, response-code and failure counters.
- Best-effort TLS ClientHello SNI metadata from single egress skbs, attributed to cgroup/workload.
- Best-effort cleartext HTTP/1 method + Host metadata from single egress skbs; no request body collection.
- Exact per-workload TCP-connect / UDP-sendmsg destination-attempt counters for fan-out and connection-health analysis.
- Deterministic network-health signals for high RTT, retransmit/RTO pressure, reset ratio, DNS failure ratio and DNS latency.
- Top destinations, top DNS names, top processes, block reasons and hook/protocol/direction summaries.
- Stale-agent detection and per-node hook coverage in the dashboard.
- Kernel skb drop-reason counters through an optional raw `kfree_skb` tracepoint, plus Linux softnet and interface drop/error counters.
- Prometheus control-plane/aggregate metrics at `/metrics`.
- Optional interval-driven anomaly alerting via multi-channel notify (webhook, email, Slack, Teams, Twilio SMS/WhatsApp, HTTP bridge), with severity-escalation-aware cooldown deduplication and concurrent per-channel delivery. Off by default; HA-aware (leader-only). Opt-in auto-capture on critical softnet/congestion/drop-spike signals persists PCAPs for download. See `docs/alerting.md` and `docs/capture.md`.
- Pull-based SIEM export of audit events, health anomalies, and incident clusters as JSON, JSONL, ArcSight CEF, RFC5424 syslog, or OTLP/HTTP JSON Logs (`GET /api/v1/export/audit`, `GET /api/v1/export/events`). Observe-only, stdlib-only, no payloads. See `docs/siem-export.md`.
- Point-in-time operator briefing (`GET /api/v1/report`, `netractl report`) combining health, drift, exposure, incidents, and recent audit into markdown or JSON for a ticket/handoff.
- Importable Grafana dashboard over the existing `/metrics` gauges (`deploy/grafana/netra-dashboard.json`).
- Review-only operator playbooks (`GET /api/v1/playbooks`), threat-intel preview plus live feed/hits/leased-apply (`POST /api/v1/intel/preview`, `PUT/GET /api/v1/intel/feed`, `GET /api/v1/intel/hits`, `POST /api/v1/intel/apply` — see `docs/threat-intel.md`), GenAI/MCP destination observe (`GET /api/v1/ebpf/ai-destinations`, `docs/ai-destinations.md`), optional volumetric auto-mitigation (`NETRA_AUTOMITIGATE_ENABLED`, `docs/auto-mitigate.md`), destination-flow SIEM export (`GET /api/v1/export/flows`), an actor/action/hour audit rollup (`GET /api/v1/audit/summary`), a per-node hook/program coverage matrix (`GET /api/v1/ebpf/coverage`, `netractl ebpf coverage`) — attached vs detached programs, missing maps, stale agents — and a read-only datapath map inventory (`GET /api/v1/ebpf/maps`, `netractl ebpf maps`, `docs/ebpf-maps.md`) — plus optional best-effort push sinks — syslog (`NETRA_SYSLOG_ADDR`) and Snowflake (`NETRA_SNOWFLAKE_ACCOUNT`, audit events only) — both off by default and leader-only in HA, alongside the pull-based SIEM export above. Dashboard **Report** page. See `docs/siem-export.md`. Perimeter NGFW fit gaps: `docs/competitive-quantum.md`.
- Optional `/proc`-derived process metadata (capabilities, seccomp, cgroup/pod attribution, kernel-thread/host/container/VM classification) for PIDs already attributed by the eBPF datapath. Off by default (`agent.procMetaEnabled`); resolved agent-side, never on the controller; never collects argv/cmdline content. See `docs/process-metadata.md`.
- `netra-mcp`, a Model Context Protocol server exposing the controller API as **189** stdio tools for AI agents (e.g. Hermes Agent) and other MCP clients. **129** read/generator tools (status, agents, pods/vms, flows, drops, eBPF diagnostics including map inventory, insights including shadow-SaaS/experience/destination-risk, AI brief/ask/agent/draft/digest/suggestions/explain, SIEM export, operator report, threat-intel, compliance, fleet clusters, policy list/history/build/lockdown-preview) are always available; **60** mutating tools (policy plan/apply/rollback/delete, eBPF rule add/delete, mode toggle, intel apply, AI destination deny, baseline capture/clear) require explicit opt-in (`NETRA_MCP_ALLOW_MUTATIONS`, off by default) and reuse Netra's existing bearer-token auth, single-use preflight tokens, self-reverting enforce-mode leases, and audit log unchanged — agent-driven mutations are tagged under a distinct actor label so they're distinguishable from human `netractl` use. Also advertises six MCP prompt templates and six read-only resources (`prompts/list`/`get`, `resources/list`/`read`) for canned triage/drops/rule-draft/on-call-digest/policy-review/incident-timeline workflows. Implemented stdlib-only (`internal/mcpserver`), no MCP SDK dependency. See `docs/mcp-integration.md`. Map inventory: `docs/ebpf-maps.md`.
- Built-in AI briefs: `GET /api/v1/ai/brief`, `POST /api/v1/ai/ask` (with optional short-lived, bounded multi-turn `conversationId` memory on web/ChatOps, cleared via `POST /api/v1/ai/forget`), `POST /api/v1/ai/agent` (in-process NL graph: classify → optional draft preview → synthesize; optional Python LangGraph companion in `python/netra_langgraph/`, see `docs/langgraph.md`), an on-call `GET /api/v1/ai/digest` (severity, incident fingerprint, copy-paste card, and — when the fingerprint changed — a deterministic `whyChanged` breakdown of exactly what moved plus an optional one-sentence LLM `whyChangedProse`), live `GET /api/v1/ai/suggestions`, a natural-language `POST /api/v1/ai/draft` rule previewer (never applies), and `POST /api/v1/ai/explain` for narrating one page finding — all turning live agent/health/insights aggregates into operator-facing text, heuristic by default (no vendor SDK, no extra process) with an optional OpenAI-compatible rewrite when `NETRA_AI_API_KEY` is set on the controller. Read-only — never flips enforce mode or applies policy; the snapshot it can see contains only aggregates and short findings, never payloads, argv, or secrets. The Overview dashboard page hosts a read-only **Ask Netra** card (now a real multi-turn thread) wired to all of this, the nav bar carries a live severity/fingerprint digest chip, and the Health/Drops/Path/Insights/Explain pages each get a per-finding **Explain** button (with an optional "draft a rule from this" preview when the finding names an IP/CIDR/DNS name) that narrates that one finding via `/api/v1/ai/explain`. See `docs/ai.md`.
- Optional ChatOps integration for Slack (slash commands + interactive confirmation buttons) and Microsoft Teams (bot messages): `/netra status|health|audit|ask|forget|mode`. Read commands reply immediately; the one mutating command (`mode`) always requires a second confirmation step, mirroring the web UI's own confirm dialogs. `/netra ask` shares the same AI layer as the web Ask Netra card, including per-channel-per-user conversation memory. Off by default; each provider needs its own signing secret/App ID to register its route at all. See `docs/chatops.md` and `docs/chatops-teams.md`.
- Cgroup-side TLS SNI / cleartext HTTP / DNS query-name observability runs in its own dedicated eBPF program (`NETRA_L7=auto|off|required`, attach-with-fallback), isolated from the conntrack/NetworkPolicy-deny program's verifier budget so the two can evolve independently. See `docs/l7-metadata.md`.
- IPv6 extension-header and fragmentation diagnostics (`docs/ipv6-diagnostics.md`), per-interface flow attribution for TC/TCX-attached NICs (`docs/interface-flow-attribution.md`), and XDP Shield per-class/per-source breakdowns (`docs/tcx-and-shield.md`) — all additive counters over data the eBPF datapath already computed internally.
- Kernel drop attribution: which connection's packets the kernel dropped, why (reason names come from the running kernel, whose numbering changes between versions) and which kernel function dropped them (`docs/drop-info.md`, needs BTF); TCP retransmit / reset / state-change events per flow (`docs/tcp-events.md`); TCP accept-queue depth per listener (`docs/listen-queues.md`); and a read-only record of host link, address, route and neighbor changes over netlink, with overflow counted rather than hidden (`docs/netlink-recorder.md`). Each is its own optional sensor: a node that cannot run one reports why instead of failing.
- Opt-in sampled application-protocol observation (Redis commands, SQL verbs, Kafka APIs, HTTP/2 and gRPC methods, HTTP status; counts only, never payload, `docs/l7-sampling.md`) and, separately and more sensitive, opt-in TLS plaintext sampling for HTTPS through OpenSSL uprobes limited by process name (`docs/tls-plaintext.md`). Both are off by default.
- Export and access: OTLP push (`docs/otlp-push.md`), Loki push (`docs/loki-push.md`), per-workload metrics with a hard cardinality cap plus a `ServiceMonitor`, `PrometheusRule` and SLOs (`docs/workload-metrics-slo.md`), OIDC login with viewer/operator/admin roles and an optional token-gated `/metrics` (`docs/auth-oidc-rbac.md`), and optional mutual TLS between agents and the controller (`docs/agent-mtls.md`, off by default).

## Emergency enforcement

- Exact IPv4 and IPv6 deny for egress, ingress, or both. Optional SYN-drop mode, per exact-IP entry or CIDR: block only new TCP connection attempts, allow other traffic for that address/range through. See `docs/syn-drop.md`.
- Exact IPv4/IPv6 allow-exception, evaluated before deny/CIDR/port/rate — does not itself enable enforce mode.
- IPv4/IPv6 CIDR deny for ingress, egress or both using BPF LPM tries.
- IPv4/IPv6 CIDR allow-exception for ingress, egress or both — same precedence as the exact-IP allow-exception.
- TCP/UDP/ANY destination-port deny for ingress, egress or both.
- TCP/UDP/ANY destination-port allow-exception for ingress, egress or both — same precedence as the exact-IP allow-exception.
- Linux UID deny for new socket operations.
- Linux UID allow-exception for new socket operations — skips UID/comm deny at the socket hook.
- Linux process-`comm` deny for new socket operations.
- Linux process-`comm` allow-exception for new socket operations — skips UID/comm deny at the socket hook.
- Capability-gated socket deny (`CAP_NET_RAW`/`CAP_NET_ADMIN`) for new connect/sendmsg operations — agent-sourced from a periodic `/proc` scan, TOCTOU-caveated, not a live kernel credential read.
- Exact cleartext DNS-name deny for UDP/53 queries.
- Exact TLS SNI deny when an ordinary ClientHello SNI is successfully parsed in the current egress skb.
- Exact IPv4/IPv6 destination PPS and/or independent BPS ceiling using a simple fixed one-second window.
- Per-workload new-TCP-connection-rate ceiling (namespace/pod/owner/labels selector, checked on `connect()` only; UDP excluded).
- Optional XDP early-ingress CIDR/port drop on explicitly selected interfaces.
- Workload-scoped enforcement by namespace, pod, immediate owner, exact labels, or cgroup ID.
- Review-only deny blast-radius preview (`POST /api/v1/ebpf/deny/preview`, `netractl ebpf deny-preview`) matching a proposed IP/CIDR/port/DNS/SNI/process deny against live non-stale agent counters. Applies nothing. See `docs/deny-preview.md`.
- Optional, off-by-default metadata-only DNS anomaly detection (tunneling, DGA, beaconing, NXDOMAIN/SERVFAIL storms — `NETRA_DNSDETECT_ENABLED`, `GET /api/v1/ebpf/dns-findings`, `netractl ebpf dns-findings`) and port-scan/fan-out/lateral-movement/SYN-flood detection (`NETRA_SCANDETECT_ENABLED`, `GET /api/v1/ebpf/scan-findings`, `netractl ebpf scan-findings`). Both are continuously-running, observe-only detectors — never enforcement. See `docs/dns-detect.md` and `docs/scan-detect.md`.
- Scope preview plus per-node selected-cgroup coverage before enforcement.
- Observe/enforce lease, controller failsafe and local node failsafe.

These controls are intentionally an emergency/containment layer, not a replacement for a full CNI policy engine, QoS system, L7 proxy or IDS/IPS.

- Native security intelligence and review: DNS QTYPE, managed threat feeds (revision journal, rollback, expiry, optional HTTPS refresh), flat deny-predicate suggestions and recent exact-workload DNS/scan/IP-intel correlation. See `docs/security-review.md`.
