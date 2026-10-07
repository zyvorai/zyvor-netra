# netra-langgraph

Optional **LangGraph** companion for [Netra](https://github.com/zyvorai/zyvor-netra)
natural-language triage.

`netrad` stays Go / stdlib-only (`AGENTS.md`). This package is a separate
process that treats the controller's existing `/api/v1/ai/*` and read-only
observability endpoints as tools.

## Graph

```
START → classify → gather_core → specialist → maybe_draft → synthesize → END
```

| Node | What it calls |
|---|---|
| `classify` | Keyword router aligned with `internal/ai.Classify` |
| `gather_core` | `GET /ai/status`, `/ai/brief`, `/ai/digest` |
| `specialist` | One extra read-only endpoint from intent (drops, insights, exposure, …) |
| `maybe_draft` | `POST /ai/draft` when the sentence looks like deny/rate/allow |
| `synthesize` | Heuristic compose, optional OpenAI-compatible rewrite |

No mutating tools are registered. A draft is a preview. Enforce mode is
never flipped from this graph.

## Install

```bash
# from the repo root — no extra deps required for the linear runner
PYTHONPATH=python python3 -m netra_langgraph "why are packets being dropped?"

# optional: real LangGraph compile path
pip install -e 'python/[langgraph]'
```

## Configure

| Var | Default | Purpose |
|---|---|---|
| `NETRA_URL` | `http://127.0.0.1:8080` | Controller base URL |
| `NETRA_API_KEY` | unset | Same bearer token as `netractl` |
| `NETRA_AI_API_KEY` / `NETRA_LANGGRAPH_API_KEY` | unset | Optional rewrite *in this process* |
| `NETRA_AI_BASE_URL` | `https://api.openai.com/v1` | OpenAI-compatible gateway |
| `NETRA_AI_MODEL` | `gpt-4o-mini` | Model id |

```bash
export NETRA_URL=https://netra.example
export NETRA_API_KEY=...
python3 -m netra_langgraph --namespace kube-system "why is DNS failing?"
python3 -m netra_langgraph --json "deny dns malware.example"
```

`--no-langgraph` forces the stdlib linear runner even if LangGraph is
installed.

## Tests

```bash
PYTHONPATH=python python3 -m unittest discover -s python/tests -v
```

## Why this is not inside `netrad`

`AGENTS.md` forbids adding an LLM or MCP SDK dependency to the
controller. The in-process equivalent is `POST /api/v1/ai/agent`
(`internal/ai.Run`) — same classify → draft → synthesize shape, no new
Go modules.
