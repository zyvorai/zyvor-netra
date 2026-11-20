# Copyright 2026 Zyvor AI Labs · https://zyvor.dev
# SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

from __future__ import annotations

import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from netra_langgraph.client import NetraClient
from netra_langgraph.graph import classify_intent, invoke_agent


class FakeNetra(BaseHTTPRequestHandler):
    def log_message(self, fmt: str, *args) -> None:  # noqa: A003
        return

    def _json(self, payload, code=200):
        raw = json.dumps(payload).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self):  # noqa: N802
        path = self.path.split("?", 1)[0]
        if path == "/api/v1/ai/status":
            return self._json({"enabled": False, "heuristicOnly": True, "mutations": "never"})
        if path == "/api/v1/ai/brief":
            return self._json(
                {
                    "headline": "Drop and block picture",
                    "severity": "warning",
                    "summary": "Blocked traffic is attributed to deny-list=12.",
                    "engine": "heuristic",
                    "findings": [{"kind": "blocked-packets", "message": "12 packets blocked", "severity": "info"}],
                    "nextSteps": ["Open the Drops page"],
                    "snapshot": {"healthScore": 70, "blocked": 12, "mode": "observe", "agentsStale": 0},
                }
            )
        if path == "/api/v1/ai/digest":
            return self._json({"severity": "warning", "fingerprint": "abc123def456", "changed": False, "card": "WARN abc123def456"})
        if path == "/api/v1/ebpf/drops":
            return self._json({"items": [{"reason": "deny-list", "count": 12}]})
        if path == "/api/v1/ebpf/diagnose":
            return self._json({"verdict": "policy-deny"})
        if path == "/api/v1/insights/summary":
            return self._json({"healthScore": 70})
        if path == "/api/v1/insights/recommendations":
            return self._json({"items": []})
        if path == "/api/v1/insights/exposure":
            return self._json({"items": []})
        if path == "/api/v1/insights/drift":
            return self._json({"findings": []})
        if path == "/api/v1/status":
            return self._json({"mode": "observe"})
        return self._json({"error": "not found"}, 404)

    def do_POST(self):  # noqa: N802
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length else b"{}"
        body = json.loads(raw.decode("utf-8") or "{}")
        path = self.path.split("?", 1)[0]
        if path == "/api/v1/ai/ask":
            return self._json({"summary": "heuristic answer", "question": body.get("question"), "engine": "heuristic"})
        if path == "/api/v1/ai/agent":
            return self._json({"intent": "drops", "steps": [{"node": "classify"}]})
        if path == "/api/v1/ai/draft":
            q = body.get("question") or ""
            understood = "deny" in q or "allow" in q
            return self._json(
                {
                    "understood": understood,
                    "kind": "dns-deny" if understood else "",
                    "summary": "DNS deny malware.example" if understood else "not a rule",
                    "cli": "netractl ebpf deny-dns add malware.example" if understood else "",
                    "note": "Preview only. Netra will not apply this.",
                }
            )
        return self._json({"error": "not found"}, 404)


def start_fake() -> tuple[ThreadingHTTPServer, str]:
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), FakeNetra)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    host, port = httpd.server_address[:2]
    return httpd, f"http://{host}:{port}"


class ClassifyTest(unittest.TestCase):
    def test_drops(self):
        self.assertEqual(classify_intent("why are packets being dropped?"), "drops")

    def test_draft_beats_drops_for_deny_sentence(self):
        self.assertEqual(classify_intent("deny dns malware.example"), "draft")

    def test_default_brief(self):
        self.assertEqual(classify_intent("what is going on?"), "brief")


class GraphTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.httpd, cls.url = start_fake()
        cls.client = NetraClient(base_url=cls.url, api_key="test")

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()

    def test_diagnostic_question(self):
        result = invoke_agent(
            "why are packets being dropped?",
            client=self.client,
            prefer_langgraph=False,
        )
        self.assertEqual(result["intent"], "drops")
        self.assertIn("classify:drops", result["steps"])
        self.assertIn("gather:brief", result["steps"])
        self.assertIn("specialist:drops", result["steps"])
        self.assertTrue(result["answer"])
        self.assertEqual(result["engine"], "heuristic")
        self.assertFalse(result.get("errors"))

    def test_rule_preview(self):
        result = invoke_agent(
            "deny dns malware.example",
            client=self.client,
            prefer_langgraph=False,
        )
        self.assertEqual(result["intent"], "draft")
        self.assertTrue((result.get("draft") or {}).get("understood"))
        self.assertIn("Preview only", result["answer"])


if __name__ == "__main__":
    unittest.main()
