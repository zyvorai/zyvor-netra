# Copyright 2026 Zyvor AI Labs · https://zyvor.dev
# SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
"""Graph state for the Netra LangGraph companion."""

from __future__ import annotations

from typing import Any, Literal, TypedDict

Intent = Literal["brief", "drops", "health", "policy", "exposure", "mode", "draft", "congestion", "investigate", "metrics"]


class AgentState(TypedDict, total=False):
    question: str
    namespace: str
    conversation_id: str
    intent: Intent
    status: dict[str, Any]
    brief: dict[str, Any]
    digest: dict[str, Any]
    specialist: dict[str, Any]
    draft: dict[str, Any]
    answer: str
    engine: str
    findings: list[dict[str, Any]]
    next_steps: list[str]
    steps: list[str]
    errors: list[str]
