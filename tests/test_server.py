from __future__ import annotations

import json
import tempfile
import threading
import unittest
import urllib.request
from pathlib import Path

from lifedb.server import LifeDBServer
from lifedb.vault import Vault


class LifeDBServerTest(unittest.TestCase):
    TOKEN = "test-api-token-for-lifedb-tests-2026"

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.vault = Vault(Path(self.temporary.name) / "vault")
        self.vault.init()
        self.server = LifeDBServer(
            ("127.0.0.1", 0), self.vault, api_token=self.TOKEN
        )
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.base = f"http://127.0.0.1:{self.server.server_port}"

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)
        self.temporary.cleanup()

    def request(self, path: str, *, body: bytes | None = None, headers=None):
        request_headers = {"Authorization": f"Bearer {self.TOKEN}"}
        request_headers.update(headers or {})
        request = urllib.request.Request(
            self.base + path,
            data=body,
            headers=request_headers,
            method="POST" if body is not None else "GET",
        )
        with urllib.request.urlopen(request, timeout=3) as response:
            return response.status, json.loads(response.read().decode())

    def test_health_ingest_rebuild_and_context(self):
        status, health = self.request("/health")
        self.assertEqual(status, 200)
        self.assertEqual(health["status"], "ok")

        status, record = self.request(
            "/v1/ingest",
            body="AIが記憶ツールを呼ばなくても自動検索する。".encode(),
            headers={
                "Content-Type": "text/plain; charset=utf-8",
                "X-LifeDB-Source": "api-test",
                "X-LifeDB-Filename": "api-note.txt",
            },
        )
        self.assertEqual(status, 201)

        status, _ = self.request("/v1/rebuild", body=b"")
        self.assertEqual(status, 200)
        status, pack = self.request(
            "/v1/context",
            body=json.dumps({"query": "記憶の自動検索", "client": "test"}).encode(),
            headers={"Content-Type": "application/json"},
        )
        self.assertEqual(status, 200)
        self.assertTrue(any(item["source_id"] == record["id"] for item in pack["relevant"]))


if __name__ == "__main__":
    unittest.main()
