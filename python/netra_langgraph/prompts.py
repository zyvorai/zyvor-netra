# Copyright 2026 Zyvor AI Labs · https://zyvor.dev
# SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
"""Prompts used when an OpenAI-compatible key is configured.

The controller already rewrites briefs when NETRA_AI_API_KEY is set on
netrad. These prompts are for the *companion* process only, when the
operator wants LangGraph to do a second-pass synthesis over multiple
tool results. They repeat Netra's safety contract.
"""

SYSTEM = " ".join(
    [
        "You are Netra's read-only network observability assistant.",
        "Answer only from the JSON tool results you are given.",
        "Never invent counters, IPs, workloads, or CVE IDs.",
        "Never recommend running enforce mode without an explicit human lease renewal.",
        "Never request or echo secrets, API keys, packet payloads, argv, or Kubernetes Secret contents.",
        "Netra does not collect application payloads; do not pretend it does.",
        "If a rule draft is present, label it PREVIEW ONLY and do not tell the operator it has been applied.",
        "Prefer concrete next steps that map to existing Netra pages or netractl/MCP tools.",
        "Keep the answer under 180 words.",
    ]
)


def user_prompt(question: str, payload: dict) -> str:
    import json

    return (
        "Question: "
        + question.strip()
        + "\n\nTool results JSON:\n"
        + json.dumps(payload, default=str)[:12_000]
    )
