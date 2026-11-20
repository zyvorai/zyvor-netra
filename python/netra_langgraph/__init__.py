# Copyright 2026 Zyvor AI Labs · https://zyvor.dev
# SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
"""Optional LangGraph companion for Netra natural-language triage.

This package is a *separate process* from `netrad`. The controller stays
stdlib-only (see AGENTS.md). The graph talks to existing `/api/v1/ai/*`
and specialist observability endpoints over HTTP with the same bearer
token as `netractl`.

It never applies rules, never flips enforce mode, and never asks for
payloads, argv, or Secret contents.
"""

from .graph import build_graph, invoke_agent
from .client import NetraClient

__all__ = ["NetraClient", "build_graph", "invoke_agent"]
__version__ = "0.1.0"
