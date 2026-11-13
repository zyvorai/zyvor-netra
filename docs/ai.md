# AI features

Netra can brief an operator — and an MCP client — on the *already computed*
observability picture. It does not add a new datapath, does not parse
payloads, and does not apply policy.

There are two engines:

| Engine | When it runs | What it does |
|---|---|---|
| **Heuristic** (default) | Always | Turns agent/health/insights aggregates into a structured brief |
| **LLM rewrite** (opt-in) | `NETRA_AI_API_KEY` set on the controller | Sends the *same* compact snapshot to an OpenAI-compatible `/v1/chat/completions` endpoint and replaces the summary paragraph |

Mutations stay on the existing audited paths (`netractl`, dashboard, MCP
mutating tools behind `NETRA_MCP_ALLOW_MUTATIONS`). The AI endpoints are
GET/POST read-only.

## Why this is separate from `netra-mcp`

`netra-mcp` is a translation layer: one MCP tool per controller HTTP
endpoint. It still leaves the model to decide *which* of the 107 read
tools to call and how to narrate the JSON.

The AI endpoints give the model (or a human) a single, bounded snapshot
plus a brief, so a first question like "what is on fire?" does not
require eight tool calls.

Use both: `netra_ai_brief` / `netra_ai_ask` for orientation, then the
specialist tools (`netra_ebpf_diagnose`, `netra_insights_recommendations`,
…) for evidence.

## HTTP API

All routes require the same bearer token as the rest of `/api/v1`.

```http
GET  /api/v1/ai/status
GET  /api/v1/ai/brief
GET  /api/v1/ai/digest
GET  /api/v1/ai/suggestions
POST /api/v1/ai/ask
POST /api/v1/ai/forget
POST /api/v1/ai/draft
POST /api/v1/ai/explain
POST /api/v1/ai/agent
Content-Type: application/json

{"question":"why is DNS failing in kube-system?","namespace":"kube-system"}
```

`GET /api/v1/ai/status` reports whether the rewrite path is configured.
It never returns the API key.

`GET /api/v1/ai/brief` always uses the heuristic engine.

`POST /api/v1/ai/ask` classifies the question (drops / health / policy /
exposure / mode / brief), specialises the heuristic answer, then — if a
provider is configured — asks the model to rewrite the summary. Provider
failures fall back to the heuristic brief instead of 5xx.

`GET /api/v1/ai/digest` is the on-call card: severity, a 12-hex
**incident fingerprint**, and copy-paste text. The fingerprint covers
mode, health-score bucket, stale-agent flag, and finding kinds — not
raw packet counters — so two operators can tell whether they are looking
at the same incident cluster after counters have moved.

When the fingerprint changes, the response also carries `whyChanged`: a
deterministic list of exactly which signal moved (mode, severity, health
band, stale-agent count, exposure/drift counts, or which finding kinds
appeared/resolved). The fingerprint is a one-way SHA-256 hash and cannot
be decomposed after the fact, so this works by keeping the plain
components alongside it — `whyChanged` covers the *complete* input to the
hash, so it is never empty when the fingerprint actually changed. An
optional `whyChangedProse` adds a one-sentence LLM rewrite of the same
bullets when a provider is configured — same "deterministic step, optional
prose" split `ai/ask` and the incident timeline use. This is computed only
on the `GET /api/v1/ai/digest` path (so the web digest chip/card,
`netractl ai digest`, and `netra_ai_digest` all get it); the webhook alert
poller calls the deterministic builder directly and gets the bullets
embedded in the card text, not a per-poll LLM call.

`POST /api/v1/ai/draft` turns "deny dns malware.example" / "rate limit
1.2.3.4 to 100 pps" / "allow 10.0.0.5" into a preview of the existing eBPF
API body and the matching `netractl` line. It never applies the rule.

`POST /api/v1/ai/explain` narrates one structured finding (kind /
subject / message / page) against the live snapshot.

`POST /api/v1/ai/agent` runs the in-process natural-language graph
(classify → optional draft preview → synthesize). Same snapshot and
read-only contract as `ai/ask`; the response adds a step trace and a
preview-only `draft` when the sentence looks like deny/rate/allow.
The optional Python LangGraph companion (`python/netra_langgraph/`,
`docs/langgraph.md`) calls this endpoint plus specialist GETs from a
separate process — LangGraph is not a Go dependency.

`POST /api/v1/ai/forget` clears one conversation's stored memory
(`{"conversationId": "..."}` → `{"ok": true}`) — see "Conversation memory"
below.

## Conversation memory

`ai/ask` is opt-in short-lived, bounded multi-turn memory: send a
client-chosen `conversationId` on the request and a follow-up like "what
about the second one?" can resolve against the last few turns of that same
conversation. Omit it (or send `""`) and behavior is exactly the fully
stateless single-shot answer this endpoint has always given.

- **In scope today: the web Ask Netra card and ChatOps only** — the two
  places a "conversation" already exists. The web card mints a random id
  per browser tab; ChatOps derives one automatically from
  (channel, user) for Slack and (conversation, user) for Teams, so
  `/netra ask` remembers the last few turns per channel per user with no
  new command to learn.
- **Out of scope, intentionally**: `netractl ai ask` and the `netra_ai_ask`
  MCP tool stay stateless. A one-shot CLI invocation has no session to hang
  memory on, and an MCP tool call already has the *calling agent's own*
  conversation as its memory — server-side history there would be
  redundant, not additive.
- **What's stored**: only the question text and the answer's summary
  already shown to the operator for up to the last 6 turns — never the raw
  snapshot, never anything the operator hasn't already seen.
- **Bounds**: 6 turns per conversation (oldest dropped first), a 30-minute
  idle TTL, and a soft global cap on how many conversations this process
  tracks at once — past the cap, new conversations are simply not
  remembered rather than erroring the request. All in-process; restarting
  `netrad` clears it, same as the digest's incident fingerprint.
- History only ever influences the *optional LLM rewrite* path, and only
  to resolve a reference — the system prompt makes explicit that prior
  turns are not new cluster data, and every existing boundary (no invented
  counters, no unbounded-enforce suggestions) still applies unchanged.
- `/netra forget` (ChatOps) or the web card's "New conversation" button
  clear it deterministically instead of waiting out the TTL.

## Dashboard

The Overview page hosts a read-only **Ask Netra** card
(`web/src/components/AskNetra.tsx`).

- Loads `GET /api/v1/ai/brief` on mount
- Submits `POST /api/v1/ai/agent` from the question box or a suggestion chip (classify → optional draft preview → synthesize; `/ai/ask` remains for one-shot callers)
- Shows severity, headline, findings, next steps, and the graph step trace
- Surfaces whether the controller is heuristic-only or has an LLM rewrite configured
- Contains no enforce / apply / rule-edit controls
- Loads live suggestion chips from `/api/v1/ai/suggestions`
- If the question looks like deny/rate/allow, shows a rule preview (never an Apply button)
- Copy on-call card + incident fingerprint from `/api/v1/ai/digest`

The nav bar (`web/src/components/DigestChip.tsx`) shows a small severity/fingerprint chip, polling `GET /api/v1/ai/digest` every 30s while any page is open; clicking it jumps to Overview. Because the dashboard now polls this endpoint continuously, it's an active participant in the shared "last fingerprint" state described above alongside the alert poller and any interactive CLI/MCP calls.

Every **Explain** popover (`web/src/components/ExplainFinding.tsx`, on Health/Drops/Path/Insights/L7/Explain findings) can additionally try to draft a rule from that finding: it regex-extracts an IP, CIDR, or DNS/SNI name from the finding's kind/subject/message and, if found, offers a "Draft rule from this" button that calls `POST /api/v1/ai/draft` — same preview-only endpoint the Ask Netra card and `netractl ai draft` use, never applies anything.

`/netra ask <question>` in Slack or Microsoft Teams (`internal/chatops`, see [`docs/chatops.md`](chatops.md)) is a further surface for the same `POST /api/v1/ai/agent` graph the Ask Netra card uses — no new boundary, same heuristic/LLM fallback, read-only. A understood draft is appended as a preview, never applied.

## CLI

```bash
netractl ai status
netractl ai brief
netractl ai digest
netractl ai draft deny dns malware.example
netractl ai explain dns-failure high SERVFAIL ratio
netractl ai ask why are we dropping packets in kube-system?
netractl ai agent deny dns malware.example
```

## MCP

Always-on read tools:

- `netra_ai_status`
- `netra_ai_brief`
- `netra_ai_ask` (`question` required) — stateless; `conversationId` is a web/ChatOps-only feature, see "Conversation memory" above
- `netra_ai_draft` (`question` required) — preview only, never applies
- `netra_ai_digest` — on-call card + incident fingerprint, plus `whyChanged`/`whyChangedProse` when it changed
- `netra_ai_suggestions` — live follow-up questions
- `netra_ai_explain` (`kind`, `subject`, `message`, `severity`, `page`, `question`, all optional)
- `netra_ai_agent` (`question` required) — in-process NL graph; preview-only draft; stateless from MCP

Prompts (MCP `prompts/list` / `prompts/get`):

- `netra_triage` — start with the brief, stay read-only
- `netra_explain_drops` — optional `namespace` / `pod`
- `netra_draft_rule` (`request` required) — draft via `netra_ai_draft`; never applies
- `netra_oncall_digest` — the on-call card via `netra_ai_digest`; if the fingerprint changed, quotes `whyChanged`/`whyChangedProse` rather than guessing at a cause
- `netra_congestion_triage` — optional `window`; kernel-network congestion via `netra_ai_congestion_brief`
- `netra_incident_timeline` — optional `since`; narrates the audit log and cluster-health-signature transitions in order
- `netra_policy_review` — optional `namespace` / `workload`; forbids apply
- `netra_tls_triage`, `netra_security_review`, `netra_metrics_oncall`, `netra_netlink_churn`, `netra_ai_destinations_review`, `netra_shadow_saas`, `netra_capture_status`, `netra_fleet_rollcall`

Resources (MCP `resources/list` / `resources/read`) — read-only, URI-addressed, no tool call needed:

- `netra://ai/brief`, `netra://ai/digest`, `netra://ai/congestion`, `netra://ai/suggestions`, `netra://status`, `netra://incidents/timeline`, `netra://incidents`
- `netra://ebpf/health`, `netra://ebpf/tls-risk`, `netra://ebpf/ai-destinations`, `netra://insights/exposure`, `netra://security/incidents`, `netra://compliance`

See `docs/mcp-integration.md` for the full tool/prompt/resource reference.

## Optional LLM provider

| Var | Default | Notes |
|---|---|---|
| `NETRA_AI_API_KEY` | unset | Enables rewrite. Leave unset for heuristic-only. |
| `NETRA_AI_BASE_URL` | `https://api.openai.com/v1` | Any OpenAI-compatible gateway |
| `NETRA_AI_MODEL` | `gpt-4o-mini` | Model id the provider expects |

Helm (`helm/netra/values.yaml`):

```yaml
ai:
  enabled: true
  baseURL: "https://api.openai.com/v1"
  model: "gpt-4o-mini"
  existingSecret: netra-ai          # key: api-key
```

The controller process is the only thing that holds the provider key.
`netra-mcp` does not receive it; it just calls `/api/v1/ai/*` with the
existing `NETRA_API_KEY`.

## What the model is allowed to see

The snapshot contains:

- agent / stale / workload counts
- fast-path mode and lease seconds
- packet / byte / blocked totals
- health score and up to 8 health anomalies
- top destinations / DNS names / processes / block reasons
- dependency / external / drift / exposure / recommendation counts
- up to 6 drift findings and 6 exposure findings

It does **not** contain:

- packet payloads, HTTP bodies, TLS certificates
- argv / cmdline
- Kubernetes Secrets
- the `NETRA_API_KEY` or `NETRA_AI_API_KEY`
- raw Hubble flow streams

The provider system prompt repeats those boundaries and forbids
inventing counters or recommending unbounded enforce mode.

## Safety

- Observe-first: briefs never flip `mode=enforce`.
- Policy drafts stay drafts. `reviewRequired` / plan→apply is unchanged.
- AI routes are authenticated the same way as `/api/v1/insights/*`.
- No new BPF maps. No new privileged agent capabilities.
- The optional webhook alert poller (`docs/alerting.md`) also emits a `source=ai kind=digest` event when the cluster isn't quiet, through the exact same dedup/cooldown/delivery path as every other alert source — no new thresholds, no new detector, and it's a narrative over counters that already power the other events.
- The digest's incident fingerprint is in-process, unpersisted, **shared** state: the webhook poller, the nav's digest chip (30s poll while any page is open), and any interactive `GET /api/v1/ai/digest` call all read and write the same single "last fingerprint" slot, not one per caller. Running more than one of these concurrently means each can affect the others' `changed` flag.
