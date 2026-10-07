# MCP integration

Netra ships a Model Context Protocol (MCP) server, `netra-mcp`, that exposes a running controller's HTTP API as MCP tools over stdio — so an AI agent such as [Hermes Agent](https://github.com/NousResearch/hermes-agent), or any other MCP client (Claude Desktop, etc.), can observe and, if enabled, act on a Netra deployment without hand-rolling HTTP calls.

## Why this exists

Hermes Agent (and MCP clients generally) connect to external capabilities exclusively through MCP servers — stdio child processes speaking JSON-RPC 2.0. Netra already has a rich, audited HTTP control plane (`internal/api`); `netra-mcp` is a thin, stdlib-only translation layer between that API and the MCP wire protocol. It adds no new capability of its own — every read and every mutation it exposes is something `netractl` could already do, with the same auth, the same lease/preflight safety machinery, and the same audit trail.

## Architecture

```
MCP client (Hermes Agent, Claude Desktop, ...)
   │  JSON-RPC 2.0, one message per line, over stdin/stdout
   ▼
netra-mcp  (cmd/netra-mcp)
   │  internal/mcpserver: generic, Netra-agnostic protocol engine + tool registry
   │  tools_read.go / tools_mutate.go: one MCP tool per controller endpoint
   │  client.go: plain net/http, mirrors cmd/netractl's auth/env conventions
   ▼  HTTPS + Bearer token
Netra controller  (cmd/netrad, internal/api)
```

`netra-mcp` is a single, long-lived stdio process per MCP client session. It holds no state of its own beyond the HTTP client configuration read from its environment at startup — every tool call is a fresh HTTP request to the controller, and every response is relayed back essentially verbatim (see [Response shape](#response-shape)). There is no caching, batching, or local policy evaluation in `netra-mcp` itself.

## Build and run

```bash
go build -o bin/netra-mcp ./cmd/netra-mcp
```

`netra-mcp` is a stdio process, not a daemon: an MCP client launches it, owns its lifecycle, and talks to it over its stdin/stdout. It never listens on a port, and it exits when its stdin is closed (the client disconnects).

To smoke-test it manually before wiring up a real MCP client, run it directly and paste JSON-RPC lines by hand:

```bash
NETRA_URL=https://127.0.0.1:30870 NETRA_API_KEY=... ./bin/netra-mcp
{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}
{"jsonrpc":"2.0","id":2,"method":"tools/list"}
{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"netra_status","arguments":{}}}
```

Each line you type after startup should produce one corresponding JSON-RPC response line (the `notifications/initialized` message, if you send it, produces none — see [Response shape](#response-shape)). Press Ctrl-D to close stdin and let the process exit.

## Environment variables

| Var | Default | Notes |
|---|---|---|
| `NETRA_URL` | `https://127.0.0.1:30870` | Base URL of the Netra controller, same convention as `netractl` |
| `NETRA_API_KEY` | unset | Bearer token; must match the controller's `NETRA_API_KEY`. If the controller has no API key configured, leave this unset too |
| `NETRA_TLS_INSECURE` | `false` | Set `true` to skip TLS verification against a local/self-signed controller. Never set this against a controller reachable over an untrusted network |
| `NETRA_MCP_ACTOR` | `mcp:hermes` | Recorded as `X-Netra-Actor` on every call, so mutations show up distinctly from human `netractl` use in `netra_audit`. Set a more specific value (e.g. `mcp:hermes:oncall-bot`) if you run several agent identities against the same controller |
| `NETRA_MCP_ALLOW_MUTATIONS` | `false` | When unset/false, only read tools and pure-generator tools are registered — the **60** mutating tool *names* do not exist in the running process at all. Set `true` (case-insensitive) to also register them |

Example:

```bash
export NETRA_URL=https://netra.prod.internal:30870
export NETRA_API_KEY=$(cat /run/secrets/netra-api-key)
export NETRA_MCP_ACTOR=mcp:hermes:prod
export NETRA_MCP_ALLOW_MUTATIONS=false   # explicit, even though it's the default
```

## Hermes Agent configuration

Add a server entry to Hermes's `~/.hermes/hermes-agent/config.yaml`:

```yaml
mcp_servers:
  netra:
    command: "/path/to/bin/netra-mcp"
    args: []
    env:
      NETRA_URL: "https://127.0.0.1:30870"
      NETRA_API_KEY: "..."
```

Then, from a Hermes session:

```
hermes mcp test netra
```

should report a successful handshake and list the **129** read tools. Run `/reload-mcp` inside a chat session after changing `config.yaml` to pick up changes without restarting Hermes entirely.

Mutations stay off by default even with this config — `NETRA_MCP_ALLOW_MUTATIONS` must be added explicitly on the `netra-mcp` process's own environment, not just in Hermes's config. A conservative read-only-by-convention setup, worth keeping even once mutations are enabled server-side, restricts which tools Hermes is allowed to call at all via `tools.include`:

```yaml
mcp_servers:
  netra:
    command: "/path/to/bin/netra-mcp"
    env:
      NETRA_URL: "https://127.0.0.1:30870"
      NETRA_API_KEY: "..."
    tools:
      include:
        - netra_status
        - netra_agents
        - netra_pods
        - netra_vms
        - netra_flow_summary
        - netra_flow_history
        - netra_drops_explain
        - netra_ebpf_health
        - netra_ebpf_path
        - netra_ebpf_drops
        - netra_ebpf_diagnose
        - netra_insights_summary
        - netra_insights_exposure
        - netra_insights_recommendations
        - netra_audit
```

`NETRA_MCP_ALLOW_MUTATIONS` is the real gate — mutating tool names don't exist in the process at all when it's unset, so a mismatched or missing `tools.include` can't accidentally expose one. `tools.include` is defense-in-depth on the Hermes side, worth setting regardless of the env var, since it also limits which *read* tools an agent persona can see (useful if an agent should only ever look at, say, one namespace's worth of concerns via `netra_workload_detail` and never touch cluster-wide policy listings).

## Security considerations

- **One API key, one privilege level.** Netra's controller has a single `NETRA_API_KEY` bearer token with no scoping — `netra-mcp` inherits whatever that token can do. There is no way to hand an MCP client a token that can read but not mutate; the *only* mutation gate is `NETRA_MCP_ALLOW_MUTATIONS` on the `netra-mcp` process itself. Run a dedicated `netra-mcp` process (with mutations enabled) separately from any process serving human dashboards or other integrations, so a compromised or misbehaving agent's blast radius is limited to what this specific process was allowed to do.
- **Every mutation is attributed and audited.** All **60** mutating tools flow through the controller's existing audit log (`store.appendAuditLocked`), tagged with the `X-Netra-Actor` value from `NETRA_MCP_ACTOR` (default `mcp:hermes`). Check `netra_audit` (or `GET /api/v1/audit`) regularly if you enable mutations for an autonomous agent — this is the primary way to notice an agent doing something unexpected.
- **Policy apply is the highest-consequence tool, and it's the most guarded.** `netra_policy_apply` requires a fresh `plan_token` from `netra_policy_plan` (single-use, content-hash-bound, 5-minute expiry) and, for high/critical-risk changes, an explicit `confirm_risk` echo. An agent cannot apply a policy it hasn't just planned, and cannot silently escalate past a risk warning — the confirmation string must appear as a literal argument value, which means the calling model has to have "read" the risk level and intentionally repeated it back, not just retried blindly.
- **Enforce mode is time-bounded by design.** `netra_ebpf_mode` can flip the whole fast path from observe to enforce, but every enforce period requires a lease (1m-24h, default 15m) and the controller auto-reverts to observe on expiry (`store.SetMode`'s fail-open behavior) — an agent cannot leave the cluster in enforce mode indefinitely by mistake; the lease must be actively renewed.
- **Baseline/rate-baseline clears require a literal confirmation value**, sent automatically by `netra-mcp` itself (`X-Netra-Confirm-Baseline-Clear: clear`) — this exists to stop an accidental clear via a generic scripted client, not to add friction for `netra-mcp`'s own calls; treat `netra_insights_baseline_clear`/`netra_insights_rate_baseline_clear` as fully live once mutations are enabled.
- **No credential management in `netra-mcp` itself.** It reads `NETRA_API_KEY` from its own process environment once at startup; it does not fetch, rotate, cache to disk, or log the key. Rotate the controller's API key the same way you would for any other client (update the env var, restart `netra-mcp`).
- **`flows/stream` and raw cluster secrets are out of reach.** The tool set is a strict subset of the controller's HTTP API (see [Not included](#not-included)); there is no path from any tool to raw Kubernetes Secret contents or arbitrary cluster API access — everything goes through Netra's own handlers, which only ever touch CiliumNetworkPolicies, its own eBPF fast-path config, and read-only workload/pod/VM listings.

## Response shape

Every tool call returns an MCP `tools/call` result of the form:

```json
{"content": [{"type": "text", "text": "<JSON body>"}], "isError": false}
```

`text` is the controller's JSON response, pretty-printed. On a non-2xx HTTP status, `isError` is `true` and `text` contains `{"status": <code>, "body": <parsed or raw body>}`. On a transport failure (DNS, connection refused, TLS handshake failure, timeout), `isError` is also `true` and `text` is the Go error string (e.g. `dial tcp ...: connect: connection refused`). A tool call is **never** a JSON-RPC protocol-level error — only a genuinely malformed request (bad JSON, unknown method, unknown tool name) is; see `internal/mcpserver`'s doc comments for the exact rationale.

## Prompts

`netra-mcp` advertises MCP prompts (`prompts/list`, `prompts/get`) in addition to tools. They are canned operator workflows — the client still has to call tools to do any work.

| Prompt | Arguments | Intent |
|---|---|---|
| `netra_triage` | — | Start with `netra_ai_brief`, stay read-only |
| `netra_explain_drops` | `namespace`, `pod` (optional) | Combine `netra_ai_ask` with drop/diagnose tools |
| `netra_draft_rule` | `request` **(required)** | Turn a deny/rate sentence into a preview rule via `netra_ai_draft`; never applies |
| `netra_oncall_digest` | — | Produce the on-call card via `netra_ai_digest`; if the fingerprint changed, quote `whyChanged`/`whyChangedProse` rather than guessing at a cause |
| `netra_incident_timeline` | `since` (optional) | Narrate `netra_incidents_timeline`'s entries in order; forbids inventing entries/causes/timestamps |
| `netra_policy_review` | `namespace`, `workload` (optional) | Review drafts via `netra_insights_policy_review`; forbids apply / mode changes |

See `docs/ai.md` for the controller-side brief/ask engines those prompts lean on.

## Resources

`netra-mcp` also advertises MCP resources (`resources/list`, `resources/read`) — read-only, URI-addressed snapshots a client can fetch without a tool call. Each resource's `Read` callback calls the same controller endpoint a matching tool would.

| URI | Endpoint | Notes |
|---|---|---|
| `netra://ai/brief` | `GET /api/v1/ai/brief` | Live heuristic brief |
| `netra://ai/digest` | `GET /api/v1/ai/digest` | On-call card + incident fingerprint |
| `netra://ai/suggestions` | `GET /api/v1/ai/suggestions` | Snapshot-derived follow-up questions |
| `netra://status` | `GET /api/v1/status` | Controller status |
| `netra://incidents` | `GET /api/v1/incidents` | Cross-signal incident clusters |
| `netra://incidents/timeline` | `GET /api/v1/incidents/timeline` | Chronological audit + health-signature-transition merge |

## Complete tool reference

All tool names are prefixed `netra_`. Every tool maps 1:1 to one Netra controller endpoint (`internal/api/server.go`), so behavior, validation, and error responses are identical to calling that endpoint directly with `netractl` or `curl`. Parameters listed as **(path)** are required and substituted directly into the URL; everything else is optional unless marked **required**.

### Status & inventory (always available)

| Tool | Endpoint | Parameters | Notes |
|---|---|---|---|
| `netra_ai_status` | `GET /api/v1/ai/status` | — | Whether the optional LLM rewrite path is configured. Heuristic briefs always work |
| `netra_ai_brief` | `GET /api/v1/ai/brief` | — | Deterministic cluster brief from live aggregates. Read-only, no payloads |
| `netra_ai_ask` | `POST /api/v1/ai/ask` | `question` **(required)**, `namespace`, `preferLlm` | Natural-language question over the same snapshot. Optional LLM rewrite lives on the controller (`NETRA_AI_API_KEY`), not in `netra-mcp`. Always stateless here — the endpoint's optional `conversationId` multi-turn memory (see `docs/ai.md#conversation-memory`) is a web/ChatOps feature; an MCP-calling agent already has its own conversation as context |
| `netra_ai_draft` | `POST /api/v1/ai/draft` | `question` **(required)** | Parses a deny/rate sentence into a preview eBPF rule (body + `netractl` line). Never applies it |
| `netra_ai_digest` | `GET /api/v1/ai/digest` | — | On-call card: severity, incident fingerprint, copy-paste text. Fingerprint is stable across counter chatter; when it changed, `whyChanged` (and optionally `whyChangedProse`) explains exactly what moved |
| `netra_ai_suggestions` | `GET /api/v1/ai/suggestions` | — | Live follow-up questions derived from the current snapshot |
| `netra_ai_explain` | `POST /api/v1/ai/explain` | `kind`, `subject`, `message`, `severity`, `page`, `question` (all optional) | Narrates one structured page finding against the live snapshot |
| `netra_ai_agent` | `POST /api/v1/ai/agent` | `question` **(required)**, `namespace`, `preferLlm`, `conversationId` | In-process NL graph (classify → optional draft preview → synthesize). Read-only. `conversationId` is a web/ChatOps feature — leave empty from MCP |
| `netra_status` | `GET /api/v1/status` | — | Fast-path config, agent counts/staleness, baseline state, Hubble/HA/Cilium flags |
| `netra_agents` | `GET /api/v1/agents` | — | One entry per reporting node agent |
| `netra_audit` | `GET /api/v1/audit` | `limit` (1-500, default 100) | Every mutating action recorded by the controller, including this MCP server's own |
| `netra_export_audit` | `GET /api/v1/export/audit` | `format` (`json`/`jsonl`/`cef`/`syslog`/`otlp`), `limit` (1-500, default 100) | SIEM encodings of the same audit log. Observe-only. See `docs/siem-export.md` |
| `netra_export_events` | `GET /api/v1/export/events` | `format`, `include` (`anomaly,incident,audit`), `limit` | Current anomalies/incidents (optional audit) in the same encodings |
| `netra_report` | `GET /api/v1/report` | `format` (`markdown`/`json`) | Point-in-time operator briefing. Never applies policy or extends a lease |
| `netra_playbooks` | `GET /api/v1/playbooks` | `format` (`json`/`markdown`) | Review-only operator steps. `autoApply` is always false |
| `netra_audit_summary` | `GET /api/v1/audit/summary` | `limit`, `since`, `until` | Actor/action/hour rollup of the audit log |
| `netra_export_flows` | `GET /api/v1/export/flows` | `format`, `limit` | Destination-flow counters as SIEM records. No payloads |
| `netra_export_blocks` | `GET /api/v1/export/blocks` | `format` (adds `otlp-trace`), `limit` | Blocked/dropped events as SIEM records; `otlp-trace` renders each as one OTLP span. No payloads |
| `netra_talkers` | `GET /api/v1/talkers` | `limit` (1-200, default 20) | Top destination IPs by packet count across current agent reports |
| `netra_namespace_heat` | `GET /api/v1/namespaces/heat` | `limit` (1-200, default 30) | Packets/bytes/blocked rolled up by Kubernetes namespace |
| `netra_protocols` | `GET /api/v1/protocols` | — | L4 protocol mix (TCP/UDP/…) across current destination stats |
| `netra_ebpf_census` | `GET /api/v1/ebpf/census` | — | Counts of deny/allow list entries. Never returns the entries themselves |
| `netra_ebpf_maps` | `GET /api/v1/ebpf/maps` | — | Read-only desired map inventory (deny/allow/rate/policy entries + limits). Not a raw bpftool dump. See `docs/ebpf-maps.md` |
| `netra_baselines` | `GET /api/v1/baselines` | — | Whether behavior and rate baselines exist and how old they are |
| `netra_ports` | `GET /api/v1/ports` | `limit` (1-200, default 30) | Top destination ports by packet count |
| `netra_dns_board` | `GET /api/v1/dns/board` | `limit` (1-200, default 30) | DNS names ranked by failure count |
| `netra_lease` | `GET /api/v1/lease` | — | Enforce-mode lease clock: remaining seconds, expired, or none |
| `netra_capture_status` | `GET /api/v1/capture/status` | — | Every node with an active packet-capture session (includes `backend` and auto-capture `requestor`). Never returns captured packets |
| `netra_export_status` | `GET /api/v1/export/status` | — | Whether syslog push is configured |
| `netra_ebpf_coverage` | `GET /api/v1/ebpf/coverage` | — | Per-node hook/program coverage matrix |
| `netra_intel_preview` | `POST /api/v1/intel/preview` | `text` (raw feed body) | Parse JSON/CSV/bare IPs into deny-import entries. Applies nothing |
| `netra_intel_feed_get` | `GET /api/v1/intel/feed` | — | Active threat-intel feed status/entries |
| `netra_intel_hits` | `GET /api/v1/intel/hits` | — | Match active feed against live agents (observe-only) |
| `netra_ebpf_ai_destinations` | `GET /api/v1/ebpf/ai-destinations` | — | Observe known GenAI/MCP SaaS via SNI/Host/DNS |
| `netra_ebpf_auto_mitigate` | `GET /api/v1/ebpf/auto-mitigate` | — | Volumetric auto-mitigation status |
| `netra_ebpf_deny_preview` | `POST /api/v1/ebpf/deny/preview` | `kind`, `value`, optional direction/protocol/scope | Observed-counter blast radius for a proposed deny. Applies nothing |
| `netra_ebpf_dns_findings` | `GET /api/v1/ebpf/dns-findings` | — | Metadata-only DNS anomaly findings (tunneling, DGA, beaconing, storms) from a continuously-running detector. Returns 409 if disabled |
| `netra_ebpf_scan_findings` | `GET /api/v1/ebpf/scan-findings` | — | Port-scan/fan-out/lateral-movement/SYN-flood findings from a continuously-running detector. Returns 409 if disabled |
| `netra_pods` | `GET /api/v1/pods` | `namespace` | Lockdown status included per pod |
| `netra_vms` | `GET /api/v1/vms` | `namespace` | Result's `available` field indicates whether KubeVirt is installed |
| `netra_workload_detail` | `GET /api/v1/workloads/{kind}/{namespace}/{name}` | `kind` **(path, required, `pod`\|`vm`)**, `namespace` **(path, required)**, `name` **(path, required)** | Phase, node, IP, labels, recommended selector, matching policies |
| `netra_ebpf_config` | `GET /api/v1/ebpf/config` | `node` | Live fast-path config; passing `node` also includes that node's workload inventory |
| `netra_ebpf_workloads` | `GET /api/v1/ebpf/workloads` | `node` | Workload identity list (pod/cgroup/container attribution) |
| `netra_ebpf_topology` | `GET /api/v1/ebpf/topology` | `limit` (1-1000, default 100) | Derived service/workload topology |
| `netra_ebpf_capabilities` | `GET /api/v1/ebpf/capabilities` | — | Static manifest of hooks/observability/enforcement capabilities |

### Flows & drops (always available)

| Tool | Endpoint | Parameters | Notes |
|---|---|---|---|
| `netra_flow_summary` | `GET /api/v1/flows/summary` | `number` (1-5000, default 500), `verdict` (`FORWARDED`\|`DROPPED`\|`ERROR`\|`AUDIT`\|`REDIRECTED`\|`TRACED`\|`TRANSLATED`), `namespace`, `pod`, `direction` (`EGRESS`\|`INGRESS`), `protocol`, `destination` | Bounded point-in-time aggregate; the tool-shaped equivalent of the `flows/stream` SSE endpoint, which is not exposed (see [Not included](#not-included)) |
| `netra_flow_history` | `GET /api/v1/flows/history` | `since` (duration or RFC3339, default 1h, max 168h), `namespace`, `pod`, `peer`, `protocol`, `app`, `node`, `limit` (1-2000, default 200) | Flow deltas in a 7-day sidecar. No payloads. See `docs/flow-log.md` |
| `netra_drops_explain` | `GET /api/v1/drops/explain` | `limit` (1-100, default 20), `namespace`, `pod` | Plain-English summary + remediation suggestions per dropped flow |
| `netra_ebpf_summary` | `GET /api/v1/ebpf/summary` | — | High-level rollup of fast-path activity across agents |
| `netra_ebpf_health` | `GET /api/v1/ebpf/health` | `limit` (1-200, default 20) | TCP health/retransmit/connect-latency anomalies |
| `netra_ebpf_capdrift` | `GET /api/v1/ebpf/capdrift` | `limit` (1-200, default 50) | Effective-capability gain/loss on tracked processes; agent-sourced from a periodic `/proc` scan, not a live kernel read; includes a `capdrift-coverage-gap` finding on recent agent restart |
| `netra_ebpf_nsdrift` | `GET /api/v1/ebpf/nsdrift` | `limit` (1-200, default 50) | Network-namespace changes on tracked processes (`setns` after start); same agent-sourced /proc-scan shape as capdrift, including an `nsdrift-coverage-gap` finding on recent agent restart |
| `netra_ebpf_exehash` | `GET /api/v1/ebpf/exehash` | `limit` (1-200, default 50) | Executable-content-hash changes on tracked processes (observe-only half of exe-hash leased deny); same agent-sourced /proc-scan shape as capdrift, including an `exehash-coverage-gap` finding on recent agent restart |
| `netra_ebpf_path` | `GET /api/v1/ebpf/path` | `limit` (1-500, default 50) | Per-hop/per-hook path diagnostics |
| `netra_ebpf_drops` | `GET /api/v1/ebpf/drops` | `limit` (1-500, default 50) | Kernel skb drop-reason counters aggregated across agents |
| `netra_ebpf_diagnose` | `GET /api/v1/ebpf/diagnose` | `limit` (default 50) | Drop-detective root-cause findings correlated with current fast-path config |
| `netra_ebpf_l7` | `GET /api/v1/ebpf/l7` | `limit` (1-1000, default 100) | Best-effort TLS SNI / cleartext HTTP metadata |
| `netra_ebpf_ipv6` | `GET /api/v1/ebpf/ipv6` | `limit` (1-500, default 50) | IPv6 extension-header/fragmentation counts and anomalies per node |
| `netra_ebpf_sysctl_audit` | `GET /api/v1/ebpf/sysctl-audit` | `limit` (1-500, default 50) | Baseline-checked network-hardening/tuning sysctl inventory (security posture, IPv6, TCP lifecycle, conntrack timeouts, ARP/bridge); most entries are informational by design — see `docs/sysctl-audit.md` |
| `netra_node_resources` | `GET /api/v1/node-resources` | `limit` (1-200, default 20) | Per-node CPU/memory/load-average snapshot plus per-workload cgroup v2 CPU/memory usage, top-N by CPU — a "top"-like view attributed to workloads, not raw PIDs — see `docs/node-resources.md` |
| `netra_ebpf_interfaces` | `GET /api/v1/ebpf/interfaces` | `limit` (1-200, default 10) | Per-interface packets/bytes/blocked + top destinations, from TC/TCX-attached hooks only (not cgroup or XDP-early-deny traffic) |
| `netra_ebpf_shield` | `GET /api/v1/ebpf/shield` | `limit` (1-500, default 50) | XDP DDoS shield diagnostics: allowed/dropped/audited by class (SYN/UDP/ICMP/other) per node, plus top offending sources, with anomaly detection |
| `netra_ebpf_rules_list` | `GET /api/v1/ebpf/rules` | — | Every eBPF fast-path deny rule with its stable ID, for use with `netra_ebpf_rules_patch`/`_delete`/`_history` instead of the legacy value-keyed add/delete tools |
| `netra_ebpf_rules_get` | `GET /api/v1/ebpf/rules/{id}` | `id` **(path, required)** | One rule by its stable ID |
| `netra_ebpf_rules_history` | `GET /api/v1/ebpf/rules/{id}/history` | `id` **(path, required)**, `limit` (1-200, default 50) | Before/after revision history for one rule's edits via `netra_ebpf_rules_patch`. Creation/deletion remain visible via `netra_audit` instead |

### Insights (always available)

| Tool | Endpoint | Parameters | Notes |
|---|---|---|---|
| `netra_insights_summary` | `GET /api/v1/insights/summary` | — | Rollup counts across all insight categories |
| `netra_insights_dependencies` | `GET /api/v1/insights/dependencies` | `limit` (1-5000, default 500) | Inferred service dependency graph, including external destinations |
| `netra_insights_baseline_get` | `GET /api/v1/insights/baseline` | — | Currently captured behavior baseline, if any |
| `netra_insights_drift` | `GET /api/v1/insights/drift` | — | How current traffic differs from the captured baseline |
| `netra_insights_recommendations` | `GET /api/v1/insights/recommendations` | `limit` (1-200, default 50), `namespace`, `workload` | Suggested policy changes; result always carries `applyRequiresReview: true` |
| `netra_insights_rates` | `GET /api/v1/insights/rates` | `window` (duration string, 30s-2h, default 5m) | Current traffic-rate window |
| `netra_insights_rate_baseline_get` | `GET /api/v1/insights/rate-baseline` | — | Currently captured rate baseline, if any |
| `netra_insights_rate_drift` | `GET /api/v1/insights/rate-drift` | `window` | How current rates differ from the rate baseline |
| `netra_insights_exposure` | `GET /api/v1/insights/exposure` | `window` | Dependency graph combined with behavior + rate drift |
| `netra_insights_blast_radius` | `GET /api/v1/insights/blast-radius` | `root` (required), `hops` (1-6, default 3) | Multi-hop *observed traffic reachability* from one node — never a policy allow/deny determination |
| `netra_insights_health_trend` | `GET /api/v1/insights/health-trend` | `threshold` (0-99, default 50) | Linear time-to-breach projection from recent health-score history; confidence is always low/medium, never high |
| `netra_insights_policy_review` | `GET /api/v1/insights/policy-review` | `recommendationId` (required) | Governing-policy resolution + semantic diff + traffic-aware blast radius + revision history for one recommendation; read-only |
| `netra_insights_new_since_start` | `GET /api/v1/insights/new-since-start` | `maxRestarts` (0-disables, default 5) | Drift findings whose owning pod/workload started after the captured baseline; baseline-relative, not a precise timing claim |
| `netra_insights_protocol_downgrades` | `GET /api/v1/insights/protocol-downgrades` | — | Workload/host pairs with baseline TLS history now showing cleartext HTTP; coexistence-tolerant correlation, never a verdict; check `l7Degraded` before reading empty as "clean" |
| `netra_incidents` | `GET /api/v1/incidents` | `auditLimit` (1-1000, default 200) | Cross-signal clusters joining health/drift/rate-drift/exposure/detective/audit findings by shared source; only surfaced with ≥2 contributing signal kinds |
| `netra_incidents_timeline` | `GET /api/v1/incidents/timeline` | `since` (RFC3339, optional) | Chronological, human-readable merge of the audit log and cluster-health-signature transitions |
| `netra_insights_remediations` | `GET /api/v1/insights/remediations` | `limit` (1-200, default 50), `window` | Proposed remediations; result always carries `reviewRequired: true`, `autoApply: false` |
| `netra_insights_red` | `GET /api/v1/insights/red` | `window` (duration, default 5m, max 168h) | Per-workload rate, drop/retransmit errors, and TCP SRTT. Not HTTP status. See `docs/flow-log.md` |
| `netra_insights_traces` | `GET /api/v1/insights/traces` | `since` (duration, default 15m, max 168h), `namespace`, `pod` | Inferred spans from flow edges and pod IPs. No propagated traceparent |
| `netra_insights_profiles` | `GET /api/v1/insights/profiles` | — | Kernel stacks and `wchan` for the hottest host comms. No argv. Not a user-space flame graph |
| `netra_insights_workload_events` | `GET /api/v1/insights/workload-events` | `namespace`, `pod` | Kubernetes Warning events for pods. Not the application journal |
| `netra_insights_kernel_notes` | `GET /api/v1/insights/kernel-notes` | — | Scrubbed kernel lines about netdev, TCP, UDP, conntrack, and OOM |

### Policies — read & generate (always available)

None of these mutate the cluster or Netra's store, and none record an audit event.

| Tool | Endpoint | Parameters | Notes |
|---|---|---|---|
| `netra_policies_list` | `GET /api/v1/policies` | `namespace` (default `default`) | Raw CiliumNetworkPolicy list; requires Cilium integration enabled on the controller |
| `netra_policies_history` | `GET /api/v1/policies/history` | `namespace`, `name`, `limit` (1-200, default 50) | Recorded revisions: checkpoints, applies, rollbacks, deletes |
| `netra_policies_history_export` | `GET /api/v1/policies/history/export` | — | Full revision archive as JSON, for backup or `netra_policy_history_import` on another controller |
| `netra_policy_gitops_status` | `GET /api/v1/policies/gitops/status` | — | GitOps reconciler status for every manifest under `NETRA_GITOPS_DIR`; 409 if GitOps is not enabled |
| `netra_policy_build` | `POST /api/v1/policies/build` | body: `name` **(required)**, `namespace` **(required)**, `selector` (object), `kind`, `to` (array of CIDR/FQDN/entity strings), `port`, `protocol`, `includeDns` (bool) | Generates a manifest only — feed the result to `netra_policy_plan` |
| `netra_policy_lockdown` | `POST /api/v1/policies/lockdown` | body: `name` **(required)**, `namespace` (default `default`), `kind` (`pod`\|`vm`, default `pod`), `selector` (auto-detected if omitted) | Generates a deny-all manifest only — feed the result to `netra_policy_plan`, or use `netra_policy_unlock` to remove an already-applied one |
| `netra_policy_simulate` | `POST /api/v1/policies/simulate` | body: `manifest` **(required, raw CNP JSON/YAML)** | Evaluates candidate egress rules against observed traffic; `toFQDNs` destinations are always `"unverified"`, never a false `"denied"` |
| `netra_ebpf_scope_preview` | `POST /api/v1/ebpf/scope/preview` | body: `scopes` **(required, array of objects)** | Dry match against live pods; does not change the active scope |

### Policies — mutating (`NETRA_MCP_ALLOW_MUTATIONS=true`)

| Tool | Endpoint | Parameters | Notes |
|---|---|---|---|
| `netra_policy_plan` | `POST /api/v1/policies/plan` | `manifest` **(required)** | Server-side dry-run + risk assessment; returns `receipt.token` (single-use, 5-minute expiry) |
| `netra_policy_apply` | `POST /api/v1/policies/apply` | `manifest` **(required)**, `plan_token` **(required)**, `confirm_risk` (required only if the plan's risk was `high`/`critical`) | See [The plan → apply flow](#the-plan--apply-flow) below |
| `netra_policy_rollback` | `POST /api/v1/policies/{namespace}/{name}/rollback/{revision}` | `namespace` **(path)**, `name` **(path)**, `revision` **(path)**, `dryRun` (bool), `confirmRisk` (required if risk is high/critical) | Pass `dryRun: true` first to preview; repeat with `confirmRisk` matching the previewed risk to actually apply |
| `netra_policy_delete` | `DELETE /api/v1/policies/{namespace}/{name}` | `namespace` **(path)**, `name` **(path)** | Records a checkpoint of the deleted manifest before deleting |
| `netra_policy_unlock` | `DELETE /api/v1/policies/lockdown/{namespace}/{name}` | `namespace` **(path)**, `name` **(path, workload name)** | Deletes the lockdown policy for a workload, restoring normal access |
| `netra_policy_history_import` | `POST /api/v1/policies/history/import` | `archive` **(required, object from `netra_policies_history_export`)**, `mode` (`merge`\|`replace`, default `merge`), `confirm_replace` (bool, required when `mode=replace`) | Discards existing history first when `mode=replace` |
| `netra_policy_gitops_resync` | `POST /api/v1/policies/gitops/resync` | `manifest` **(required)**, `confirm_risk` (required only if risk is `high`/`critical`) | Human override for a manifest the GitOps reconciler declined to auto-apply (drift or risk too high); 409 if GitOps is not enabled |

### eBPF fast path — mutating (`NETRA_MCP_ALLOW_MUTATIONS=true`)

| Tool | Endpoint | Parameters | Notes |
|---|---|---|---|
| `netra_ebpf_mode` | `PUT /api/v1/ebpf/mode` | `mode` **(required, `observe`\|`enforce`)**, `lease` (duration, 1m-24h, default 15m) | Self-limiting: enforce auto-reverts to observe when the lease expires |
| `netra_ebpf_scope_set` | `PUT /api/v1/ebpf/scope` | `mode` **(required, `all`\|`selected`)**, `scopes` (array, required when `mode=selected`) | Preview matches first with `netra_ebpf_scope_preview` |
| `netra_ebpf_deny_add` / `netra_ebpf_deny_delete` | `POST /api/v1/ebpf/deny` / `DELETE .../deny/{ip}` | `ip` **(required)**, `direction` (`egress`\|`ingress`\|`both`, default `egress`, add only) | Exact IPv4 or IPv6 address |
| `netra_ebpf_allow_add` / `netra_ebpf_allow_delete` | `POST /api/v1/ebpf/allow` / `DELETE .../allow/{ip}` | `ip` **(required)** | Exact IPv4 or IPv6 allow-exception; evaluated before deny/CIDR/port/rate |
| `netra_ebpf_allow_cidr_add` / `netra_ebpf_allow_cidr_delete` | `POST /api/v1/ebpf/allow-cidr` / `POST .../allow-cidr/delete` | `cidr` **(required)**, `direction` (`egress`\|`ingress`\|`both`, default `egress`) | CIDR-shaped allow-exception; evaluated before deny/CIDR/port/rate, mirrors `netra_ebpf_cidr_add`'s deny-side shape |
| `netra_ebpf_cidr_add` / `netra_ebpf_cidr_delete` | `POST /api/v1/ebpf/cidr` / `POST .../cidr/delete` | `cidr` **(required)**, `direction` (`egress`\|`ingress`\|`both`, default `egress`) | |
| `netra_ebpf_syn_drop_add` / `netra_ebpf_syn_drop_delete` | `POST /api/v1/ebpf/syn-drop` / `POST .../syn-drop/delete` | `address` **(required, exact IPv4 or IPv6)**, `direction` **(required, `egress`\|`ingress` — no `both`, unlike CIDR)** | Flags an *existing* exact-IP deny entry so only new TCP SYNs are dropped, not every packet; has no effect without a matching deny entry for the same address+direction |
| `netra_ebpf_port_add` / `netra_ebpf_port_delete` | `POST /api/v1/ebpf/port` / `POST .../port/delete` | `port` **(required, 1-65535)**, `protocol` (`TCP`\|`UDP`\|`ANY`, default `ANY`), `direction` (default `egress`) | |
| `netra_ebpf_allow_port_add` / `netra_ebpf_allow_port_delete` | `POST /api/v1/ebpf/allow-port` / `POST .../allow-port/delete` | `port` **(required, 1-65535)**, `protocol` (`TCP`\|`UDP`\|`ANY`, default `ANY`), `direction` (default `egress`) | L4 port allow-exception; evaluated before deny/CIDR/port/rate, mirrors `netra_ebpf_port_add`'s deny-side shape |
| `netra_ebpf_uid_add` / `netra_ebpf_uid_delete` | `POST /api/v1/ebpf/uid` / `DELETE .../uid/{uid}` | `uid` **(required)** | Linux UID |
| `netra_ebpf_allow_uid_add` / `netra_ebpf_allow_uid_delete` | `POST /api/v1/ebpf/allow-uid` / `DELETE .../allow-uid/{uid}` | `uid` **(required)** | Linux UID exception; evaluated before UID/comm deny at the socket hook, mirrors `netra_ebpf_uid_add`'s deny-side shape |
| `netra_ebpf_dns_add` / `netra_ebpf_dns_delete` | `POST /api/v1/ebpf/dns` / `POST .../dns/delete` | `name` **(required)** | Exact plain-DNS query name over UDP/53; no wildcards |
| `netra_ebpf_process_add` / `netra_ebpf_process_delete` | `POST /api/v1/ebpf/process` / `POST .../process/delete` | `name` **(required)** | Linux `comm`, up to 15 bytes |
| `netra_ebpf_allow_process_add` / `netra_ebpf_allow_process_delete` | `POST /api/v1/ebpf/allow-process` / `POST .../allow-process/delete` | `name` **(required)** | Linux `comm` exception, up to 15 bytes; evaluated before UID/comm deny at the socket hook, mirrors `netra_ebpf_process_add`'s deny-side shape |
| `netra_ebpf_capability_add` / `netra_ebpf_capability_delete` | `POST /api/v1/ebpf/capability` / `POST .../capability/delete` | `name` **(required, `CAP_NET_RAW`\|`CAP_NET_ADMIN` only)** | Denies new socket() attempts for any process with this capability effective at the agent's last periodic `/proc` scan — agent-sourced and TOCTOU-caveated, not a live kernel credential read |
| `netra_ebpf_sni_add` / `netra_ebpf_sni_delete` | `POST /api/v1/ebpf/sni` / `POST .../sni/delete` | `name` **(required)** | Exact TLS SNI, best-effort (requires ClientHello parsing); no wildcards |
| `netra_ebpf_rate_set` / `netra_ebpf_rate_delete` | `PUT /api/v1/ebpf/rate` / `DELETE .../rate/{ip}` | `destination` **(required, exact IPv4 or IPv6)**, `pps` (1-10000000, set only), `bps` (bytes/sec, set only) — **at least one of `pps`/`bps` required, independent of each other** | |
| `netra_ebpf_shield_set` | `PUT /api/v1/ebpf/shield` | `mode` **(`off`\|`audit`\|`enforce`)**, `protectAll` (bool), `protectedIpv4`/`protectedIpv6` (arrays, ignored if `protectAll`), `synPps`/`udpPps`/`icmpPps`/`otherPps` (0-10000000, 0 disables that class), `burstSeconds` | XDP DDoS shield: per-source-class PPS token-bucket limiter, independent of the fast-path deny-list. Use `audit` before `enforce` to preview what would be dropped |
| `netra_ebpf_netpol_config_set` | `PUT /api/v1/ebpf/netpol/config` | `enabled` **(required, bool)** | Enable/disable the legacy per-workload NetPol-emulation deny engine (independent of the fast-path deny-list and the v2 engine below) |
| `netra_ebpf_netpol_v2_config_set` | `PUT /api/v1/ebpf/netpol/v2/config` | `enabled` **(required, bool)** | Enable/disable the v2 per-workload allow-list/default-deny engine. An explicit `allow` rule (`netra_ebpf_netpol_rule_add`) can override even the flat fast-path deny-list for that workload+peer — deliberate, not a bug |
| `netra_ebpf_netpol_rule_add` | `POST /api/v1/ebpf/netpol/rules` | `selector` **(required, object: namespace/pod/workloadKind/workloadName/labels/cgroupId, at least one field)**, `peerIpv4` **(required, exact)**, `port`, `protocol` (default `ANY`), `direction` (default `egress`), `action` **(required, `allow`\|`deny`)** | Returns the updated fast-path config with the new rule's assigned `id` |
| `netra_ebpf_netpol_rule_delete` | `DELETE /api/v1/ebpf/netpol/rules/{id}` | `id` **(path, required)** | From the fast-path config's `netPolRules`, or the `rule_add` response |
| `netra_ebpf_netpol_default_deny_plan` | `POST /api/v1/ebpf/netpol/default-deny/plan` | `selector` **(required, object)**, `enabled` **(required, bool)**, `lease` (default `5m`, 1m-60m), `allowNoRules` (bool) | Mandatory first step for v2 default-deny: assesses risk (zero covering allow rules ⇒ `critical`, refused unless `allowNoRules`) and issues a single-use, 5-minute `receipt.token`. Deactivating is always `low` risk. Mutates nothing else |
| `netra_ebpf_netpol_default_deny_set` | *(PUT, path not separately listed)* | `selector`/`enabled`/`lease` **(must exactly match the prior plan call)**, `plan_token` **(required)**, `confirm_risk` (required if the plan's risk was `medium`+) | The single highest-blast-radius mutation in the firewall feature — a workload in default-deny posture only accepts traffic an explicit allow rule permits. Requires a fresh `netra_ebpf_netpol_default_deny_plan` token |
| `netra_ebpf_conn_rate_limit_add` | `POST /api/v1/ebpf/conn-rate-limit` | `selector` **(required, object, at least one field)**, `perSecond` **(required, >0)** | Caps new TCP connection attempts per second for matching workloads; checked on `connect()` only, not UDP. The strictest (lowest) `perSecond` wins when multiple rules match one workload. Returns the updated fast-path config with the new rule's assigned `id` |
| `netra_ebpf_conn_rate_limit_delete` | `DELETE /api/v1/ebpf/conn-rate-limit/{id}` | `id` **(path, required)** | From the fast-path config's `connRateLimits`, or the `add` response |
| `netra_intel_feed_put` | `PUT /api/v1/intel/feed` | `text` **(required)** | Replace active threat-intel feed; does not apply denies |
| `netra_intel_apply` | `POST /api/v1/intel/apply` | `confirm_risk` **(required, `high`)**, `matched_only` (bool) | Requires enforce lease; imports feed (or live hits only) into deny maps |
| `netra_ebpf_ai_destinations_deny` | `POST /api/v1/ebpf/ai-destinations/deny` | `confirm_risk` **(required, `high`)** | Lease-deny observed GenAI/MCP SaaS SNI hosts |
| `netra_ebpf_rules_patch` | `PATCH /api/v1/ebpf/rules/{id}` | `id` **(path, required)**, plus the fields matching the rule's type (`ip` for ip4/ip6; `cidr`+`direction` for cidr; `protocol`+`port`+`direction` for port; `uid` for uid; `name` for dns/sni/process; `destination`+`pps` for rate) | Edits one rule in place by its stable ID, preserving the ID and recording a before/after revision (see `netra_ebpf_rules_history`). Same validation as the corresponding add tool |
| `netra_ebpf_rules_delete` | `DELETE /api/v1/ebpf/rules/{id}` | `id` **(path, required)** | Stable-ID equivalent of the legacy value-keyed delete tools |
| `netra_ebpf_rules_rollback` | `POST /api/v1/ebpf/rules/{id}/rollback/{revision}` | `id` **(path, required)**, `revision` **(path, required)** | Undoes one specific edit, restoring its pre-edit value — recorded as a new revision rather than rewriting history |

Every eBPF mutating tool returns the full updated `EBPFFastPathConfig` on success.

### Packet capture — mutating (`NETRA_MCP_ALLOW_MUTATIONS=true`)

| Tool | Endpoint | Parameters | Notes |
|---|---|---|---|
| `netra_capture_start` | `PUT /api/v1/vms/{node}/capture` | `node` **(required)**, at least one of `protocol`/`host`/`port` **(required — no unfiltered captures)**, `backend` (`ebpf`\|`afpacket`, default `ebpf`), `snapLen`, `maxPps`, `durationSeconds` (1-300, default 60) | Captures full packet bytes by default, which can include cleartext application secrets — prefer a narrow filter. Auto-expires; live packets stream to the Capture dashboard page, not through this tool. Controller-side opt-in auto-capture on critical drops is separate (`NETRA_AUTO_CAPTURE`, see `docs/capture.md`) and is not started via this tool |
| `netra_capture_stop` | `DELETE /api/v1/vms/{node}/capture` | `node` **(required)** | Stops an active session before its duration expires |

### Insights — mutating (`NETRA_MCP_ALLOW_MUTATIONS=true`)

| Tool | Endpoint | Parameters | Notes |
|---|---|---|---|
| `netra_insights_baseline_capture` | `POST /api/v1/insights/baseline` | — | Replaces any existing behavior baseline with a fresh snapshot |
| `netra_insights_baseline_clear` | `DELETE /api/v1/insights/baseline` | — | `netra-mcp` sends the required confirmation header automatically |
| `netra_insights_rate_baseline_capture` | `POST /api/v1/insights/rate-baseline` | `window` (duration, 30s-2h, default 5m) | Replaces any existing rate baseline |
| `netra_insights_rate_baseline_clear` | `DELETE /api/v1/insights/rate-baseline` | — | `netra-mcp` sends the required confirmation header automatically |

## The plan → apply flow

`netra_policy_apply` never accepts a manifest on its own — it requires proof that the exact same manifest was just dry-run planned. This is the one place where the calling agent has to carry state between two tool calls:

1. Call `netra_policy_plan` with `manifest`. The result includes `plan.risk` (`low`/`medium`/`high`/`critical`) and `receipt.token`.
2. If `plan.risk` is `low` or `medium`, call `netra_policy_apply` with the same `manifest` and `plan_token` set to `receipt.token`.
3. If `plan.risk` is `high` or `critical`, call `netra_policy_apply` with the same `manifest`, `plan_token`, **and** `confirm_risk` set to that exact risk string. Omitting it, or getting the string wrong, is rejected with a 409 (surfaced as an `isError: true` tool result, not a crash).
4. The token is single-use and expires after 5 minutes — a stale or reused token, or a manifest that doesn't byte-for-byte match what was planned, is rejected with a 412/428 (also surfaced as `isError: true`).

`netra_policy_rollback` has the same two-step shape folded into one tool via `dryRun`/`confirmRisk` query parameters instead of a separate token, since a rollback target is already an exact, previously-recorded manifest rather than new arbitrary input.

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| Every tool call returns `isError: true` with `dial tcp ...: connect: connection refused` | `NETRA_URL` doesn't point at a reachable controller | Verify the controller is running and the URL/port are correct |
| `isError: true`, body `{"error":"invalid API token"}`, status 401 | `NETRA_API_KEY` missing or wrong | Match it to the controller's own `NETRA_API_KEY` |
| TLS handshake errors against a local controller | Self-signed certificate | Set `NETRA_TLS_INSECURE=true` (local/dev only) |
| `netra_policy_apply` returns status 428 `"a fresh preflight receipt is required"` | Called apply without planning first, or the token expired | Call `netra_policy_plan` again immediately before applying |
| `netra_policy_apply` returns status 409 `"preflight risk is high; ... apply with X-Netra-Confirm-Risk: high"` | Risk is high/critical and `confirm_risk` was omitted or didn't match | Pass `confirm_risk` equal to the risk string from the plan result |
| `netra_policy_apply` / `netra_policy_rollback` return status 412 `"preflight receipt is expired, already used, or does not match this exact policy body"` | Token reused, expired, or the manifest changed since planning | Re-plan the exact manifest you intend to apply |
| A mutating tool name doesn't appear in `tools/list` at all | `NETRA_MCP_ALLOW_MUTATIONS` isn't `true` on the `netra-mcp` process | Set it and restart `netra-mcp` (Hermes will relaunch the child process) |
| Any write returns status 507 `"could not persist ..."` | Controller's durable state backend is failing to write | Check the controller's own logs/storage; this is not specific to MCP |
| `hermes mcp test netra` fails outright | Binary path wrong, not executable, or crashes on startup | Run `netra-mcp` manually per [Build and run](#build-and-run) and check stderr |

## Not included

- **No `flows/stream` tool.** `GET /api/v1/flows/stream` is a Server-Sent-Events stream; it doesn't fit a request/response MCP `tools/call`. `netra_flow_summary` is the live aggregate. `netra_flow_history` is the 7-day flow sidecar (`docs/flow-log.md`), not a stream and not a column store.
- **Tools only — no MCP resources or prompts.** Every capability is exposed as a callable tool; there is no resource-subscription or prompt-template surface.
- **No additional rate limiting.** `netra-mcp` adds no throttling of its own beyond whatever the controller's own API already enforces.
- **No per-tool credential scoping.** See [Security considerations](#security-considerations) — one API key covers everything `netra-mcp` is allowed to do; the mutation gate is process-wide, not per-tool.
- **No credential management.** `netra-mcp` reads `NETRA_API_KEY` from its own process environment; it does not fetch, rotate, or store credentials itself.
- **No batching or transactions.** Each tool call is one independent HTTP request; there is no way to apply several eBPF rule changes atomically.

## Verification in CI

`scripts/ci-mcp-live.sh` (job `mcp-live`) runs the real `netra-mcp` over stdio JSON-RPC against a real
`netrad`. Read-only by default: the read tools, prompts and resources are listed, a read tool returns
the controller's real answer, none of the mutating tools (names read from `cmd/netra-mcp/tools_mutate.go`)
is listed and calling one is refused as unknown, a wrong API key is a tool error not a crash, and
malformed input gets a parse error while the server keeps serving. With `NETRA_MCP_ALLOW_MUTATIONS=true`
exactly the source-defined mutating set is added, a deny rule added through MCP reaches the controller
and the audit log names the MCP actor (`NETRA_MCP_ACTOR`), and bad arguments change nothing.

### Security review tools

| Tool | Endpoint | Behavior |
|---|---|---|
| `netra_security_optimizer` | `GET /api/v1/security/optimizer` | Review flat deny predicates and sampled matching events; no apply |
| `netra_security_incidents` | `GET /api/v1/security/incidents` | Exact-workload temporal correlation; no attack verdict |
| `netra_intel_history` | `GET /api/v1/intel/history` | Read retained feed snapshots and expiry; no rollback |

See [Security intelligence and review](security-review.md). These three tools remain available with mutations disabled.
