# Copyright 2026 Zyvor AI Labs · https://zyvor.dev
# SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
"""Thin authenticated HTTP client for the Netra controller."""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.parse
import urllib.request
from typing import Any


class NetraError(RuntimeError):
    def __init__(self, status: int, body: str) -> None:
        super().__init__(f"Netra HTTP {status}: {body[:300]}")
        self.status = status
        self.body = body


class NetraClient:
    """Bearer-token client. Uses stdlib urllib so the package can run
    its unit tests without extra native deps. Production callers may
    swap this for httpx if they prefer.
    """

    def __init__(
        self,
        base_url: str | None = None,
        api_key: str | None = None,
        timeout: float = 20.0,
    ) -> None:
        self.base_url = (base_url or os.environ.get("NETRA_URL") or "http://127.0.0.1:8080").rstrip("/")
        self.api_key = api_key if api_key is not None else os.environ.get("NETRA_API_KEY", "")
        self.timeout = timeout

    def get(self, path: str, query: dict[str, Any] | None = None) -> Any:
        url = self.base_url + path
        if query:
            parts = []
            for k, v in query.items():
                if v is None or v == "":
                    continue
                parts.append(f"{k}={urllib.parse.quote(str(v))}")
            if parts:
                url += "?" + "&".join(parts)
        return self._request("GET", url, None)

    def post(self, path: str, body: dict[str, Any] | None = None) -> Any:
        return self._request("POST", self.base_url + path, body or {})

    def status(self) -> Any:
        return self.get("/api/v1/ai/status")

    def brief(self) -> Any:
        return self.get("/api/v1/ai/brief")

    def digest(self) -> Any:
        return self.get("/api/v1/ai/digest")

    def suggestions(self) -> Any:
        return self.get("/api/v1/ai/suggestions")

    def ask(self, question: str, namespace: str = "", conversation_id: str = "") -> Any:
        payload: dict[str, Any] = {"question": question}
        if namespace:
            payload["namespace"] = namespace
        if conversation_id:
            payload["conversationId"] = conversation_id
        return self.post("/api/v1/ai/ask", payload)

    def agent(self, question: str, namespace: str = "", conversation_id: str = "") -> Any:
        payload: dict[str, Any] = {"question": question}
        if namespace:
            payload["namespace"] = namespace
        if conversation_id:
            payload["conversationId"] = conversation_id
        return self.post("/api/v1/ai/agent", payload)

    def draft(self, question: str) -> Any:
        return self.post("/api/v1/ai/draft", {"question": question})

    def explain(self, **finding: Any) -> Any:
        return self.post("/api/v1/ai/explain", finding)

    def drops(self, namespace: str = "") -> Any:
        q = {"namespace": namespace} if namespace else None
        return self.get("/api/v1/ebpf/drops", q)

    def diagnose(self, namespace: str = "") -> Any:
        q = {"namespace": namespace} if namespace else None
        return self.get("/api/v1/ebpf/diagnose", q)

    def insights_summary(self) -> Any:
        return self.get("/api/v1/insights/summary")

    def exposure(self) -> Any:
        return self.get("/api/v1/insights/exposure")

    def drift(self) -> Any:
        return self.get("/api/v1/insights/drift")

    def recommendations(self, namespace: str = "") -> Any:
        q = {"namespace": namespace} if namespace else None
        return self.get("/api/v1/insights/recommendations", q)

    def cluster_status(self) -> Any:
        return self.get("/api/v1/status")

    def _request(self, method: str, url: str, body: dict[str, Any] | None) -> Any:
        data = None
        headers = {"Accept": "application/json"}
        if self.api_key:
            headers["Authorization"] = "Bearer " + self.api_key
        if body is not None and method != "GET":
            data = json.dumps(body).encode("utf-8")
            headers["Content-Type"] = "application/json"
        req = urllib.request.Request(url, data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                raw = resp.read().decode("utf-8", "replace")
                if not raw:
                    return {}
                return json.loads(raw)
        except urllib.error.HTTPError as exc:
            raw = exc.read().decode("utf-8", "replace")
            raise NetraError(exc.code, raw) from exc
