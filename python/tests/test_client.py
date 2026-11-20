# Copyright 2026 Zyvor AI Labs · https://zyvor.dev
# SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

from __future__ import annotations

import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from netra_langgraph.client import NetraClient, NetraError


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt: str, *args) -> None:  # noqa: A003
        return

    def do_GET(self):  # noqa: N802
        if self.headers.get("Authorization") != "Bearer secret":
            self.send_response(401)
            self.end_headers()
            return
        raw = json.dumps({"ok": True, "path": self.path}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)


class ClientTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=cls.httpd.serve_forever, daemon=True).start()
        host, port = cls.httpd.server_address[:2]
        cls.url = f"http://{host}:{port}"

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()

    def test_auth_header(self):
        c = NetraClient(base_url=self.url, api_key="secret")
        out = c.get("/api/v1/ai/status")
        self.assertTrue(out["ok"])

    def test_401(self):
        c = NetraClient(base_url=self.url, api_key="wrong")
        with self.assertRaises(NetraError) as ctx:
            c.get("/api/v1/ai/status")
        self.assertEqual(ctx.exception.status, 401)


if __name__ == "__main__":
    unittest.main()
