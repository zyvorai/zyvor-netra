# Copyright 2026 Zyvor AI Labs · https://zyvor.dev
# SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
"""LangGraph StateGraph for Netra natural-language triage.

Topology (acyclic, bounded — no open ReAct loop against mutating tools):

    START → classify → gather_core → specialist → maybe_draft → synthesize → END

`gather_core` always pulls brief + digest + AI status (the same compact
snapshot the controller already sanitizes). The specialist node then
fetches one extra read-only endpoint based on intent. Mutations are not
registered as tools.

The graph degrades without LangGraph installed: `invoke_agent` will run
the same node functions in order so unit tests and air-gapped operators
still get a deterministic answer.
"""

from __future__ import annotations

import os
from typing import Any, Callable

from .client import NetraClient, NetraError
from .prompts import SYSTEM, user_prompt
from .state import AgentState, Intent

# Keyword router — mirrors internal/ai.Classify so heuristic-only mode
# stays aligned with the controller even when no LLM is configured.
_INTENT_RULES: list[tuple[Intent, tuple[str, ...]]] = [
    ("draft", ("deny ", "allow ", "rate limit", "rate-limit", "throttle", "whitelist")),
    ("investigate", ("can't reach", "cannot reach", "investigate connection", "failed connection", "why can't", "unreachable")),
    ("congestion", ("congestion", "rcvbuf", "listen queue", "listen backlog", "softnet", "qdisc", "udp drop", "tcp memory")),
    ("drops", ("drop", "deny", "block", "reset", "rto", "kfree")),
    ("health", ("rtt", "latency", "retrans", "dns fail", "health", "score")),
    ("policy", ("policy", "netpol", "allow-list", "allow list", "recommend", "draft")),
    ("exposure", ("expos", "drift", "external", "internet", "egress")),
    ("mode", ("enforce", "observe", "lease", "mode")),
    ("metrics", ("metric", "anomal", "alert", "cpu", "memory", "disk", "spike")),
]


def classify_intent(question: str) -> Intent:
    q = question.lower()
    for intent, needles in _INTENT_RULES:
        if any(n in q for n in needles):
            return intent
    return "brief"


def _append(state: AgentState, step: str) -> list[str]:
    steps = list(state.get("steps") or [])
    steps.append(step)
    return steps


def _err(state: AgentState, message: str) -> list[str]:
    errors = list(state.get("errors") or [])
    errors.append(message)
    return errors


def make_nodes(client: NetraClient) -> dict[str, Callable[[AgentState], AgentState]]:
    def classify(state: AgentState) -> AgentState:
        intent = classify_intent(state.get("question") or "")
        return {
            **state,
            "intent": intent,
            "steps": _append(state, f"classify:{intent}"),
        }

    def gather_core(state: AgentState) -> AgentState:
        out = dict(state)
        try:
            out["status"] = client.status()
            out["steps"] = _append(out, "gather:status")
        except NetraError as exc:
            out["errors"] = _err(out, f"status:{exc}")
        try:
            out["brief"] = client.brief()
            out["steps"] = _append(out, "gather:brief")
        except NetraError as exc:
            out["errors"] = _err(out, f"brief:{exc}")
        try:
            out["digest"] = client.digest()
            out["steps"] = _append(out, "gather:digest")
        except NetraError as exc:
            out["errors"] = _err(out, f"digest:{exc}")
        return out  # type: ignore[return-value]

    def specialist(state: AgentState) -> AgentState:
        intent = state.get("intent") or "brief"
        ns = state.get("namespace") or ""
        out = dict(state)
        try:
            if intent == "drops":
                out["specialist"] = {"drops": client.drops(ns), "diagnose": client.diagnose(ns)}
            elif intent == "health":
                out["specialist"] = {"insights": client.insights_summary()}
            elif intent in ("policy", "draft"):
                out["specialist"] = {"recommendations": client.recommendations(ns)}
            elif intent == "exposure":
                out["specialist"] = {"exposure": client.exposure(), "drift": client.drift()}
            elif intent == "mode":
                out["specialist"] = {"cluster": client.cluster_status()}
            else:
                out["specialist"] = {"ask": client.ask(state.get("question") or "", ns, state.get("conversation_id") or "")}
            out["steps"] = _append(out, f"specialist:{intent}")
        except NetraError as exc:
            out["errors"] = _err(out, f"specialist:{exc}")
        return out  # type: ignore[return-value]

    def maybe_draft(state: AgentState) -> AgentState:
        q = state.get("question") or ""
        if classify_intent(q) not in ("draft", "drops", "policy") and not any(
            w in q.lower() for w in ("deny", "allow", "rate", "block")
        ):
            return {**state, "steps": _append(state, "draft:skip")}
        out = dict(state)
        try:
            draft = client.draft(q)
            out["draft"] = draft
            understood = bool(draft.get("understood")) if isinstance(draft, dict) else False
            out["steps"] = _append(out, "draft:understood" if understood else "draft:not-understood")
        except NetraError as exc:
            out["errors"] = _err(out, f"draft:{exc}")
        return out  # type: ignore[return-value]

    def synthesize(state: AgentState) -> AgentState:
        out = dict(state)
        brief = state.get("brief") or {}
        findings = list(brief.get("findings") or [])
        next_steps = list(brief.get("nextSteps") or [])
        engine = "heuristic"
        answer = _heuristic_answer(state)

        rewritten = _optional_llm_rewrite(state)
        if rewritten:
            answer = rewritten
            engine = "llm"

        draft = state.get("draft") or {}
        if isinstance(draft, dict) and draft.get("understood"):
            next_steps = [
                "PREVIEW ONLY — review the draft, then apply with netractl / Firewall / a mutating MCP tool after a human lease.",
                *next_steps,
            ]

        out.update(
            {
                "answer": answer,
                "engine": engine,
                "findings": findings,
                "next_steps": next_steps,
                "steps": _append(out, f"synthesize:{engine}"),
            }
        )
        return out  # type: ignore[return-value]

    return {
        "classify": classify,
        "gather_core": gather_core,
        "specialist": specialist,
        "maybe_draft": maybe_draft,
        "synthesize": synthesize,
    }


def _heuristic_answer(state: AgentState) -> str:
    brief = state.get("brief") or {}
    digest = state.get("digest") or {}
    parts: list[str] = []
    headline = brief.get("headline") or digest.get("headline")
    summary = brief.get("summary") or digest.get("summary")
    if headline:
        parts.append(str(headline))
    if summary:
        parts.append(str(summary))
    draft = state.get("draft") or {}
    if isinstance(draft, dict) and draft.get("understood"):
        parts.append("Rule preview: " + str(draft.get("summary") or draft.get("cli") or "understood"))
        parts.append(str(draft.get("note") or "Preview only. Nothing was applied."))
    errors = state.get("errors") or []
    if errors and not parts:
        parts.append("Could not reach the controller: " + "; ".join(errors[:3]))
    if not parts:
        parts.append("No brief available. Check NETRA_URL / NETRA_API_KEY and that netrad is up.")
    return " ".join(parts)


def _optional_llm_rewrite(state: AgentState) -> str | None:
    """Second-pass rewrite in the companion process.

    Uses the same OpenAI-compatible shape as internal/ai.Provider so
    NETRA_AI_BASE_URL gateways work. Disabled unless NETRA_AI_API_KEY is
    set *in this process*. Controller-side rewrite may already have run
    inside /ai/ask; this pass only fires when the companion has its own key.
    """
    key = os.environ.get("NETRA_LANGGRAPH_API_KEY") or os.environ.get("NETRA_AI_API_KEY")
    if not key:
        return None
    try:
        from urllib.request import Request, urlopen
        import json

        base = (os.environ.get("NETRA_AI_BASE_URL") or "https://api.openai.com/v1").rstrip("/")
        model = os.environ.get("NETRA_AI_MODEL") or "gpt-4o-mini"
        payload = {
            "status": state.get("status"),
            "brief": _thin_brief(state.get("brief") or {}),
            "digest": _thin_digest(state.get("digest") or {}),
            "draft": state.get("draft"),
            "intent": state.get("intent"),
            "specialist_keys": sorted((state.get("specialist") or {}).keys()),
        }
        body = json.dumps(
            {
                "model": model,
                "temperature": 0.2,
                "messages": [
                    {"role": "system", "content": SYSTEM},
                    {"role": "user", "content": user_prompt(state.get("question") or "", payload)},
                ],
            }
        ).encode("utf-8")
        req = Request(
            base + "/chat/completions",
            data=body,
            headers={"Authorization": "Bearer " + key, "Content-Type": "application/json"},
            method="POST",
        )
        with urlopen(req, timeout=20) as resp:
            parsed = json.loads(resp.read().decode("utf-8", "replace"))
        choices = parsed.get("choices") or []
        if not choices:
            return None
        text = ((choices[0].get("message") or {}).get("content") or "").strip()
        return text or None
    except Exception:
        return None


def _thin_brief(brief: dict[str, Any]) -> dict[str, Any]:
    snap = brief.get("snapshot") or {}
    return {
        "headline": brief.get("headline"),
        "severity": brief.get("severity"),
        "summary": brief.get("summary"),
        "engine": brief.get("engine"),
        "healthScore": snap.get("healthScore"),
        "mode": snap.get("mode"),
        "blocked": snap.get("blocked"),
        "agentsStale": snap.get("agentsStale"),
        "findings": (brief.get("findings") or [])[:8],
        "nextSteps": (brief.get("nextSteps") or [])[:6],
    }


def _thin_digest(digest: dict[str, Any]) -> dict[str, Any]:
    return {
        "severity": digest.get("severity"),
        "fingerprint": digest.get("fingerprint"),
        "changed": digest.get("changed"),
        "whyChanged": digest.get("whyChanged"),
        "card": (digest.get("card") or "")[:500],
    }


def invoke_linear(client: NetraClient, state: AgentState) -> AgentState:
    """Run the nodes in order without importing LangGraph."""
    nodes = make_nodes(client)
    current: AgentState = dict(state)
    for name in ("classify", "gather_core", "specialist", "maybe_draft", "synthesize"):
        current = nodes[name](current)
    return current


def build_graph(client: NetraClient | None = None):
    """Compile a LangGraph StateGraph when the library is installed."""
    try:
        from langgraph.graph import END, START, StateGraph
    except ImportError as exc:  # pragma: no cover - exercised via invoke_linear
        raise RuntimeError(
            "langgraph is not installed. `pip install -e python/[langgraph]` "
            "or call invoke_agent() which falls back to the linear runner."
        ) from exc

    client = client or NetraClient()
    nodes = make_nodes(client)
    builder = StateGraph(AgentState)
    builder.add_node("classify", nodes["classify"])
    builder.add_node("gather_core", nodes["gather_core"])
    builder.add_node("specialist", nodes["specialist"])
    builder.add_node("maybe_draft", nodes["maybe_draft"])
    builder.add_node("synthesize", nodes["synthesize"])
    builder.add_edge(START, "classify")
    builder.add_edge("classify", "gather_core")
    builder.add_edge("gather_core", "specialist")
    builder.add_edge("specialist", "maybe_draft")
    builder.add_edge("maybe_draft", "synthesize")
    builder.add_edge("synthesize", END)
    return builder.compile()


def invoke_agent(
    question: str,
    *,
    namespace: str = "",
    conversation_id: str = "",
    client: NetraClient | None = None,
    prefer_langgraph: bool = True,
) -> AgentState:
    """Public entry: LangGraph if installed, otherwise the linear runner."""
    client = client or NetraClient()
    initial: AgentState = {
        "question": question,
        "namespace": namespace,
        "conversation_id": conversation_id,
        "steps": [],
        "errors": [],
    }
    if prefer_langgraph:
        try:
            graph = build_graph(client)
            result = graph.invoke(initial)
            return result  # type: ignore[return-value]
        except Exception:
            pass
    return invoke_linear(client, initial)
