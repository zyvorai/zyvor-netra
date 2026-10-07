---
sidebar_position: 3
---

# Security

Report suspected vulnerabilities privately to the Zyvor maintainers through the security contact configured for the GitHub organization. Do not publish exploitable details in a public issue before coordination.

## Standalone eBPF threat boundary

The Netra agent is privileged because it loads host kernel BPF programs, pins maps in bpffs, and attaches to host cgroup/interface hooks. Run it only on trusted nodes. The agent uses a dedicated ServiceAccount with `automountServiceAccountToken: false`; it does not need Kubernetes API credentials.

Netra programs/maps live below `/sys/fs/bpf/netra` and do not read or modify Cilium-owned maps. Cilium and Hubble are optional. Helm does not render `CiliumNetworkPolicy` RBAC unless `cilium.enabled=true`, and the controller rejects live Cilium policy operations while `NETRA_CILIUM_ENABLED` is disabled. Operators inspect desired control-plane map contents with `netractl ebpf maps` (see [ebpf-maps.md](https://github.com/zyvorai/zyvor-netra/blob/main/docs/ebpf-maps.md)) — read-only, no payloads.

XDP and TCX attachment are opt-in. The standalone default is root-cgroup v2 attachment, which avoids coupling policy behavior to a CNI-specific host interface. Root-cgroup attachment is intentionally broad and can cover host/system processes as well as container workloads. Treat broad CIDR/port/UID/process rules as node-level controls, test them in observe mode, and maintain an out-of-band recovery path before enforcing on production nodes.

For workload attribution, only the controller receives read-only `get/list` RBAC for Pods and Services. The privileged agent scans cgroup-v2 locally and requests node-filtered workload inventory through the authenticated Netra control channel. It never receives a Kubernetes API token.

The default DaemonSet uses one shared agent credential, so the controller filters inventory by the requested node but does not cryptographically bind that credential to a particular node identity. Optional mutual TLS (see [Agent to controller mutual TLS](#agent-to-controller-mutual-tls)) adds a client certificate as a second factor, but the certificate is also shared by all agents, so it still does not bind an agent to a node. Treat possession of the agent key as cluster-agent trust and rotate it after any node compromise. Pod metadata is the only Kubernetes inventory delivered on the agent config path; Secrets and ServiceAccount tokens are not exposed by this mechanism.

`scopeMode=selected` is the preferred production containment mode. It gates cgroup packet/socket enforcement through the resolved `enforced_cgroups` map. If Pod metadata or local cgroup identity cannot be resolved, that traffic fails open. TCX/XDP remain observe-only in selected mode because Netra does not claim trustworthy workload identity at those hooks. Preview is advisory Pod metadata; confirm each agent's `selectedCgroups` coverage before enabling a lease.

## Enforcement safety

The custom datapath starts in observe mode. Enforce mode is time-limited and fail-open:

- agent startup writes observe before controller synchronization;
- enforcement requires a controller-issued lease with an expiry;
- nodes locally expire the lease even if the controller is unreachable;
- failure to refresh desired state for `NETRA_FAILSAFE_AFTER` forces observe;
- controller restart and HA leadership change force observe before serving as leader.

Rules may remain staged/persisted while enforcement is off. This is intentional: operators can inspect the configuration before deliberately re-enabling a lease.

DNS-name blocking is limited to exact cleartext UDP/53 qnames. It does not inspect DoH/DoT/TCP DNS. Process-name blocking uses Linux `comm` and affects new connect/sendmsg operations; it is not a workload identity or process-kill mechanism. The destination PPS feature is emergency containment rather than a fair queue/QoS implementation.

TLS SNI enforcement is best-effort. It applies only when Netra parses an exact ordinary ClientHello SNI in the current cgroup egress skb. Fragmented handshakes, TCP segmentation that splits the SNI, ECH, QUIC/HTTP3 and unrecognized layouts are not blocked by an SNI rule. Treat SNI deny as an emergency supplemental control, not a substitute for a proxy/firewall with stream-aware TLS policy.

The always-on HTTP metadata is observation-only and limited to cleartext HTTP/1 method + `Host` seen in a single skb. Netra does not export request paths or bodies. Two **opt-in, off-by-default** sensors go further and are described in [Sampled protocols and TLS plaintext](#sampled-protocols-and-tls-plaintext) below; the always-on path still does not decode HTTPS, HTTP/2 or HTTP/3.

## Kernel drop-diagnostics safety

The optional `kfree_skb` raw tracepoint reports kernel drop-reason numbers at **node scope**. Netra attaches it only when tracefs confirms that the host event exposes a `skb_drop_reason` field. The tracepoint does not provide reliable Kubernetes cgroup identity, so Netra does not attribute those reasons to Pods or workloads. Reason numbers follow the running kernel's enum and should be interpreted with that kernel's symbols/source.

`softnet_stat` and `/sys/class/net/*/statistics` counters are cumulative host counters. They show queue/backlog/interface pressure but do not by themselves identify a remote switch, firewall, CNI, application, or hardware component as the root cause. The Drop Diagnostics page is observation-only and never changes policy.

## TCP path-diagnostics safety

Path Diagnostics is observation-only. It reads Linux TCP transport fields exposed to the cgroup sockops program and never changes congestion control or socket options. `lost_out` and `retrans_out` are TCP's current transport-state markers; they are not generic skb drop reasons and do not identify a switch, NIC, firewall, qdisc, or router as the root cause. `packets_out / snd_cwnd` is reported as congestion-window pressure, not as a byte-accurate socket send-queue measurement.

Active connect latency is measured only when Netra sees both the cgroup connect hook and the matching active-established sockops callback. The temporary `connect_start` map is deliberately not pinned across agent restarts.

## Behavior Insights safety

The behavior baseline contains operational metadata derived from Netra telemetry: workload identifiers, destination IP/port/protocol tuples, DNS names, TLS SNI values, and cleartext HTTP Host values. Treat the state file and baseline API output as sensitive infrastructure metadata. The baseline does not contain packet payloads or credentials.

Dependency resolution adds read-only Kubernetes Service metadata to the controller permission set. The privileged node agent remains tokenless and does not receive the cluster-wide Service list.

Policy recommendations are **never auto-applied**. They are generated from observed traffic, which may be incomplete. Rare failover paths, maintenance jobs, disaster-recovery calls, and cold-start dependencies can be absent from observations. A recommendation must go through operator review and the existing Netra preflight/apply path before it can change Cilium policy.

Baseline recapture is an explicit trust decision: it accepts current observed behavior as known-good. Baseline clearing requires a dedicated confirmation header. Stale agent reports are excluded from capture, drift, dependency, and recommendation calculations.

## Rate intelligence safety

The rolling rate window is computed from positive deltas between consecutive cumulative agent reports. Counter-reset intervals are discarded. Rolling samples are intentionally controller-memory-only and therefore enter a warming state after restart or HA failover; the persisted rate baseline is never compared against a one-sample window.

Rate drift thresholds and exposure scores are deterministic operational heuristics, not statistical guarantees, vulnerability scores, or intrusion verdicts. Remediation proposals are review-only objects and are never auto-executed. An operator must still deliberately stage a rule and enable a time-limited enforcement lease, or use the existing Cilium preflight/apply path.

## MCP server safety

`netra-mcp` is a translation layer over the existing authenticated HTTP API — every tool call is one HTTP request with the same auth, validation, and error responses as calling that endpoint directly. It introduces no new privilege boundary of its own.

Read tools (status, agents, pods/vms, flows, drops, eBPF diagnostics, insights, AI brief/ask/draft/digest/suggestions/explain, policy list/history/build/lockdown-preview) are always available. Mutating tools (policy plan/apply/rollback/delete, eBPF rule add/delete, mode toggle, baseline capture/clear) do not exist in the process at all unless `NETRA_MCP_ALLOW_MUTATIONS=true` is set — not merely hidden from `tools/list`. When enabled, they go through the exact same plan-token/risk-confirmation/lease machinery as `netractl` or the dashboard, and every mutating call is tagged with a distinct actor label (`NETRA_MCP_ACTOR`, default `mcp:hermes`) in the existing audit log, distinguishable from human use.

MCP prompts (`prompts/list`/`prompts/get`) are canned text templates, not a technical enforcement mechanism — a prompt telling a client "never call the apply tool" is advisory to whatever agent consumes it; the actual mutation gate is still `NETRA_MCP_ALLOW_MUTATIONS`. MCP resources (`resources/list`/`resources/read`) are read-only, URI-addressed fetches of the same data a matching read tool would return.

## AI layer safety

The AI endpoints (`GET/POST /api/v1/ai/*`) turn data the controller already computes into operator-facing text. The heuristic engine (default, always on) does this deterministically with no external calls. An optional LLM rewrite is off unless `NETRA_AI_API_KEY` is set **on the controller process**; `netra-mcp` never receives that key, it only calls `/api/v1/ai/*` with the existing API token.

The snapshot sent to an LLM provider, when configured, is bounded aggregates only: agent/stale/workload counts, fast-path mode, packet/byte/blocked totals, health score, top-N destinations/DNS/processes, and a handful of drift/exposure findings. It never contains packet payloads, HTTP bodies, TLS certificates, `argv`/cmdline, Kubernetes Secrets, either API key, or raw Hubble flow streams. The provider system prompt repeats those boundaries and forbids inventing counters or recommending unbounded enforce mode; provider failures fall back to the heuristic brief rather than failing the request.

Two AI-adjacent features never apply anything on their own: `POST /api/v1/ai/draft` (and the dashboard's "Draft rule from this" buttons) only preview a natural-language deny/rate request as the exact eBPF API body plus a `netractl` line — actually applying it is a separate, deliberate action through the normal mutating path. The optional webhook alert poller can additionally emit a `source=ai kind=digest` event when the cluster is not quiet, through the same dedup/cooldown/delivery path as every other alert source; this adds no new anomaly-detection logic, only a narrative rollup over counters that already power the other events.

The digest's incident fingerprint (a 12-hex hash over mode/health-bucket/stale-flag/finding-kinds, deliberately not raw packet counters) is in-process, unpersisted, and shared: the webhook poller, the dashboard's nav chip (polling every 30s while any page is open), and any interactive `GET /api/v1/ai/digest` caller all read and write one "last seen" slot, not one per caller. This is a UX convenience trade-off, not a security boundary — treat it as informational only.

## Kernel sensors safety

The optional sensors (drop attribution, TCP events, listen queues) are separate eBPF objects or netlink queries, each with its own `auto | off | required` mode. A sensor that cannot load reports the reason and the agent keeps running; one that is `required` stops the agent instead. They read kernel metadata about connections (addresses, ports, the reason and the kernel function of a drop); none reads packet payload. Drop attribution needs kernel BTF and, for real function names, permission to read `/proc/kallsyms`; the chart mounts the host's tracefs read-only for the tracepoint layouts. Treat the connection tuples they expose like flow data: sensitive operational telemetry.

## Sampled protocols and TLS plaintext

Both sensors are **off by default**. Turn them on only where you have decided you want the counts.

**Sampled L7** copies the first bytes of packets on ports you configure into a per-CPU ring buffer at a bounded rate, and the agent parses them to count Redis commands, SQL verbs, Kafka APIs, HTTP methods and statuses and gRPC methods. The parsers can only return an allowlisted operation name, a coarse outcome or a validated pattern; keys, SQL text, paths, query strings, headers and bodies are never returned, exported or logged. The property is enforced by the shape of the output and tested by planting secrets in real requests and asserting they appear nowhere the agent or controller exposes: not in the API, the agent's own report, `/metrics`, or either process's log.

**TLS plaintext sampling** is a deliberate, opt-in exception to "Netra does not decrypt". It attaches uprobes to OpenSSL's `SSL_write` and `SSL_read` in the libraries your processes load, so the agent sees a sample of plaintext at the point the application hands it over or receives it. Limits that matter:

- The plaintext is parsed in the agent's memory and **never exported**; only allowlisted counts leave it.
- Restrict it with `agent.tlsUprobesComms` (process names such as `nginx,envoy`). The allowlist is enforced in the kernel **before any byte is copied**, so processes off the list are never read. With no list it observes every process that uses libssl, on the whole node.
- It needs a host-PID view of the node to find each process's libssl, which the chart requests only when this or process metadata is enabled. That is a real widening of what the already-privileged agent can see.
- It covers OpenSSL only. Go's `crypto/tls`, statically linked BoringSSL and applications with their own TLS are not observed.

Both sensors are rate-limited and the kernel counts what it skipped, so a busy node cannot be made to spend unbounded CPU or memory on them.

## Agent to controller mutual TLS

`NETRA_AGENT_MTLS=optional|required` (Helm `mtls.mode`) makes the controller verify a client certificate from the agent. In `required` mode agent-only requests need the agent key **and** a certificate signed by your CA with the client-auth key usage, so a leaked agent key alone no longer works. People are never asked for a certificate.

It fails closed. The controller refuses to start on an invalid mode, a missing or empty CA file, or mutual TLS over plain HTTP, and a bad mode that reaches the request path is treated as `required`, never `off`. A certificate that is offered but wrong (another CA, expired, or without the client-auth usage) fails the handshake even in `optional` mode. Whether each agent's report arrived over a verified certificate is recorded by the controller from the handshake; an agent cannot claim it. An agent given an unusable certificate refuses to run rather than reporting into a wall.

What it does not do: the certificate is shared by all agents, so it proves "an agent", not which node. The controller reads its CA at startup, so rotating the CA needs a controller restart.

## Roles and login

With `NETRA_OIDC_ISSUER` set, people sign in through your identity provider and get one of three roles (`viewer`, `operator`, `admin`); the audit trail names the person. Static keys keep working as full admin. Roles are decided in one place on the matched route, a newly added mutating route is gated at operator by default, and tests fail the build if any mutating route resolves lower. A valid token that maps to no Netra role is a 403, and an unreachable identity provider is a 503, not a 401, so clients do not treat a provider outage as a logout.

## Push sinks

OTLP, Loki, syslog, Snowflake and the alert channels send data **out** of the controller, so review what leaves before enabling them. They are opt-in, best-effort and leader-only in HA. Their credentials (headers, secrets, passwords, tokens) are never logged and never appear in an API response, which CI checks by planting them and scanning every request body, log line and response. Webhook and bridge deliveries can be HMAC-signed. Loki and syslog carry audit and block events (addresses and actor names); treat the destination as sensitive.

## Authentication defaults

The controller refuses startup when either `NETRA_API_KEY` or `NETRA_AGENT_KEY` is missing. `NETRA_ALLOW_UNAUTHENTICATED=true` is an explicit local-development escape hatch and should not be used on shared networks. Helm enforces the same default and supports `auth.existingSecret`.

Netra can also authenticate people through OIDC with three roles (see [Roles and login](#roles-and-login)); the static keys remain full admin, so store them like root credentials. Use independent API and agent secrets. Rotate them through your normal Secret-management process. Restrict access to the controller Service with NetworkPolicy/firewall controls appropriate to your environment.

`/metrics` is unauthenticated by default for in-cluster Prometheus scraping but contains aggregate, low-cardinality operational data only. It does not export packet payloads, API keys or policy bodies. Set `NETRA_METRICS_TOKEN` to require a bearer token (the token is accepted in the `Authorization` header only, never in the URL). The opt-in per-workload counters add `namespace` and `workload` labels, bounded by a hard cap with an `other` bucket, so cardinality cannot grow without limit.

## Packet/process data

By default the ring buffer exports selected packet-header metadata and process context, and Netra does not copy packet payload bytes to userspace. The exception is the two opt-in sampling sensors below, which copy the first bytes of selected payloads to the agent to count operations; that data is parsed in the agent and never exported. Cleartext DNS qnames are intentionally extracted and may be sensitive; apply retention/access controls to any external logs or metrics pipeline that consumes Netra events.

Process events can include PID, UID, cgroup ID and `comm`. Treat them as operational telemetry.

## Optional Cilium policy controls

When Cilium integration is enabled, non-dry-run `CiliumNetworkPolicy` apply requires a fresh preflight receipt by default. Receipts are one-shot, expire after five minutes, and are bound to the exact candidate bytes. High/critical plans also require explicit matching risk confirmation. Keep `NETRA_REQUIRE_PREFLIGHT=true` in shared environments.

Rollback snapshots remove Kubernetes server-owned metadata and `status`. Exported history contains full policy manifests and should be treated as sensitive cluster configuration.

## Durable state and HA

The file backend uses atomic temporary-file + fsync + rename semantics and an exclusive process lock. HA adds Kubernetes Lease election as the first ownership barrier. Use RWX storage that provides coherent POSIX advisory locking and filesystem semantics; do not use object-backed mounts that cannot guarantee these properties.

Preflight receipt issuance and one-shot consumption are persisted. Leader promotion reopens state through the fail-open path so emergency eBPF enforcement is reset to observe after failover.
