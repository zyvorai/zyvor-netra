# Research wave 1: eBPF network observability and control

Date: 2026-11-23. Method: each product's public docs landing page was fetched once. **[V]** marks a claim read from a fetched page. **[U]** marks a claim from general knowledge that no fetched page confirmed; treat it as a lead, not a fact. Several fetches returned only a landing page, so most detail below is [U].

## What the tools offer

| Tool | What it does | Source |
|---|---|---|
| Cilium Hubble | Flow visibility at node, cluster and multi-cluster scope through a CLI and Relay; a UI that discovers L3/L4 and L7 service dependencies; flow exporters with performance tuning [V]. Policy verdicts and drop reasons per flow [U]. | https://docs.cilium.io/en/stable/observability/hubble/ |
| Tetragon | In-kernel filtering and blocking through TracingPolicy on arbitrary kernel functions, socket-to-process mapping, lower overhead from not waking user space [V]. | https://tetragon.io/docs/overview/ |
| Inspektor Gadget | eBPF programs packaged as OCI "Gadgets"; enrichment to pods, containers and DNS names; in-kernel filtering by Kubernetes names; restrictions on which Gadgets may run; CLI, client-server, API and Go library modes; WASM post-processing [V]. Specific network gadgets (trace_tcp, trace_dns, top_tcp, network-policy advisor): [U], the page did not list them. | https://inspektor-gadget.io/docs/latest/ |
| Retina (Azure) | Prometheus metrics, export to Prometheus and Azure Monitor, packet captures through `kubectl retina capture` or a Capture CRD [V]. Multi-node distributed capture and Hubble integration: not on the fetched page, [U]. | https://github.com/microsoft/retina |
| Falco | YAML rules loaded from config, outputs to stdout, file, syslog, a program or HTTP(S), falcosidekick for fan-out, plugins for non-syscall sources [V]. No built-in response engine described [V]. | https://falco.org/docs/ |
| Coroot | Docs index lists alerting, tracing, profiling, inspections, risk monitoring, dashboards, GitOps monitoring, AI root cause analysis and an MCP server [V]. Service map, SLO tracking and deployment tracking were not described on the page; Coroot's SLO and deployment-correlation features are [U]. | https://docs.coroot.com/ |
| Grafana Beyla | eBPF auto-instrumentation for HTTP/S and gRPC with RED metrics and traces, database and messaging clients, Kubernetes metadata, node/pod/service traffic measurement, OTel and Prometheus export; Grafana's distribution of OpenTelemetry eBPF Instrumentation [V]. | https://grafana.com/docs/beyla/latest/ |
| Sloth | Generates Prometheus SLOs from its own spec, OpenSLO or Kubernetes CRDs; based on Google's SRE book; plugin-based SLIs and alert rules [V]. Multiwindow multi-burn-rate output: not stated on the page, [U]. | https://sloth.dev/ |
| OpenSLO | Vendor-agnostic YAML SLO specification [V]. Kinds and fields (SLO, SLI, AlertPolicy, ratioMetric, budgetingMethod, timeWindow) are [U] from memory; the page pointed at the examples folder. | https://github.com/OpenSLO/OpenSLO |
| Pixie | Auto-telemetry, PxL scripts, service maps [U]. The docs host did not resolve, nothing verified. | not fetched |
| Groundcover, Isovalent Timescape, Calico flow logs, Parca/Pyroscope, Datadog/Honeycomb incident timelines | Not verified. The Calico flow-log docs URL returned 404; the others were not fetched. Flow history with policy verdicts (Timescape, Calico) and "change events overlaid on charts" (Datadog, Honeycomb) are [U]. | not fetched |

## What Netra already has (so these are not gaps)

Flow history with a 7-day retention, historical deny preview (`internal/counterfactual`), live deny preview (`internal/denysim`), a netlink change recorder with requester attribution, BPF attachment inventory and drift findings, drop attribution, per-second metrics with anomaly detection and alerts, workload SLOs with multi-window burn rates, an audit-plus-health timeline, a cross-signal incident correlator, bounded capture and a standalone MCP server.

## What Netra lacked

1. No single ordered view of change signals next to breakage signals. `/incidents/timeline` covered audit and health only; netlink, attachment drift, drops, anomalies and alerts lived on separate pages.
2. Deny previews reported blast radius but not self-lockout (apiserver, DNS, the controller itself).
3. SLOs were definable only through a Netra-specific JSON env var, with no file format shared with other SLO tooling.
4. Lease limits: an operator cannot cap concurrent or broad leases.
5. Capture filters cannot be generated from a flow or incident.
6. No policy-verdict-per-flow history comparable to Hubble or Calico flow logs (Netra records drops and denies, not every allow verdict). Needs datapath work, out of scope for this control-plane wave.

## Ranked ideas

| Rank | Idea | Why | Status |
|---|---|---|---|
| 1 | What-changed timeline joining netlink, attachment, audit, drops, anomalies, alerts | Highest operator value per line of code, uses only recorded data, fits the observe-only identity. The "change events next to symptoms" pattern is common in incident tooling [U]. | Built |
| 2 | Deny self-lockout guard | Netra's emergency deny is its riskiest verb; a preview that says "this cuts the kube-apiserver" is cheap and prevents the worst outcome. Tetragon and Cilium enforce in-kernel [V/U] and have no equivalent preview in the pages read. | Built |
| 3 | OpenSLO-style SLO file | Sloth and others accept OpenSLO [V]; a standard file removes a Netra-specific format and gives `lint` for CI. Constrained to what Netra can compute (no latency SLI). | Built |
| 4 | Lease safety rails (max concurrent leases, scope guard, dry-run) | Valuable but touches the enforce path (`internal/store` SetMode, per-rule leases). Larger blast radius for a mistake, needs live tests on Linux. | Deferred |
| 5 | Capture filter generation from a flow or incident | Small, no payloads needed. Lower value than 1 to 3. | Deferred |
| 6 | Policy-verdict history per flow | Hubble and Calico style [U]. Needs BPF changes. | Rejected for this wave (no BPF edits) |
| 7 | Network profiling a la Parca/Pyroscope | Not network-specific in any page fetched; Netra already ships kernel-stack summaries. | Rejected |
| 8 | Gadget-style loadable eBPF programs | Contradicts Netra's fixed, reviewed program set and its boundary of not loading arbitrary programs. | Rejected |
