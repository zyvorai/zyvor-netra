# LangGraph natural-language companion

Netra already answers operator questions from a compact snapshot
(`docs/ai.md`). Two layers sit on top of that for multi-step natural
language:

| Layer | Where | Dependencies | When to use |
|---|---|---|---|
| **In-process graph** | `POST /api/v1/ai/agent`, `netractl ai agent`, MCP `netra_ai_agent` | None (stdlib) | Dashboard / CLI / MCP want a step trace + optional draft in one call |
| **LangGraph companion** | `python/netra_langgraph/` | Optional `langgraph` extra | An external agent should fan out to specialist read endpoints, then synthesize |

Neither layer applies rules or flips enforce mode.

## Why two layers

`AGENTS.md` keeps `internal/ai` and `internal/mcpserver` stdlib-only —
no LangChain, no LangGraph, no MCP SDK in `netrad`. The Python package
is therefore a *companion process* that uses the same bearer token as
`netractl` and the same sanitized AI snapshot the controller already
builds.

```
operator question
        │
        ▼
┌───────────────────────────────┐
│ python/netra_langgraph        │  classify → gather → specialist → draft → synthesize
│ (optional LangGraph compile)  │
└──────────────┬────────────────┘
               │ HTTP + bearer
               ▼
┌───────────────────────────────┐
│ netrad  POST /api/v1/ai/agent │  classify → optional draft → Answer()
│          GET  /api/v1/ai/*    │  heuristic brief, optional LLM rewrite
│          GET  /api/v1/ebpf/*  │  specialist evidence
│          GET  /api/v1/insights/*
└───────────────────────────────┘
```

## In-process graph

```http
POST /api/v1/ai/agent
{"question":"deny dns malware.example","namespace":"kube-system"}
```

Response shape:

```json
{
  "intent": "drops",
  "engine": "heuristic",
  "brief": { "headline": "...", "summary": "...", "snapshot": {} },
  "draft": { "understood": true, "cli": "…", "note": "Preview only. …" },
  "suggestions": ["Why are packets being dropped?"],
  "steps": [
    { "node": "classify", "detail": "drops" },
    { "node": "draft", "detail": "dns-deny/high" },
    { "node": "synthesize", "detail": "answer from snapshot" }
  ]
}
```

`draft` is omitted when the question is purely diagnostic.
`conversationId` is accepted for the web/ChatOps memory path and ignored
by `netractl` / MCP, same contract as `/ai/ask`.

```bash
netractl ai agent why is DNS failing in kube-system?
netractl ai agent deny dns malware.example
```

## Python companion

See `python/README.md` for install and CLI flags.

```bash
export NETRA_URL=http://127.0.0.1:8080
export NETRA_API_KEY=…
PYTHONPATH=python python3 -m netra_langgraph --namespace kube-system "why is DNS failing?"
```

Safety copied from `docs/ai.md`:

- Snapshot and specialist GETs contain aggregates and short findings, not
  payloads, argv, or Secret contents.
- System prompt (when a companion-side API key is set) forbids invented
  counters and unbounded enforce recommendations.
- `POST /ai/draft` is preview-only; the graph never calls a mutating
  path even if `NETRA_MCP_ALLOW_MUTATIONS` is on for some other client.

## Optional LLM

The controller rewrite (`NETRA_AI_API_KEY` on `netrad`) still runs inside
`/ai/ask` and `/ai/agent` synthesize. The companion can do a *second*
pass over multiple tool results when `NETRA_LANGGRAPH_API_KEY` or
`NETRA_AI_API_KEY` is set **in the Python process**. Leave both unset
for a fully heuristic graph.
