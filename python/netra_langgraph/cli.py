# Copyright 2026 Zyvor AI Labs · https://zyvor.dev
# SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
"""CLI: python -m netra_langgraph "why is DNS failing in kube-system?" """

from __future__ import annotations

import argparse
import json
import sys

from .client import NetraClient
from .graph import invoke_agent


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="netra-langgraph",
        description="Natural-language triage over a live Netra controller (read-only).",
    )
    parser.add_argument("question", nargs="+", help="Operator question")
    parser.add_argument("--namespace", default="", help="Optional namespace hint")
    parser.add_argument("--conversation-id", default="", dest="conversation_id")
    parser.add_argument("--url", default=None, help="Controller base URL (default NETRA_URL)")
    parser.add_argument("--json", action="store_true", help="Print the full graph state as JSON")
    parser.add_argument("--no-langgraph", action="store_true", help="Force the linear stdlib runner")
    args = parser.parse_args(argv)

    question = " ".join(args.question).strip()
    client = NetraClient(base_url=args.url)
    result = invoke_agent(
        question,
        namespace=args.namespace,
        conversation_id=args.conversation_id,
        client=client,
        prefer_langgraph=not args.no_langgraph,
    )
    if args.json:
        json.dump(result, sys.stdout, indent=2, default=str)
        sys.stdout.write("\n")
        return 0

    print(result.get("answer") or "(no answer)")
    engine = result.get("engine") or "heuristic"
    intent = result.get("intent") or "brief"
    print(f"\n— intent={intent} engine={engine} steps={','.join(result.get('steps') or [])}")
    draft = result.get("draft") or {}
    if isinstance(draft, dict) and draft.get("understood"):
        print("draft:", draft.get("summary") or draft.get("cli"))
        print("note:", draft.get("note"))
    errors = result.get("errors") or []
    if errors:
        print("errors:", "; ".join(errors))
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
