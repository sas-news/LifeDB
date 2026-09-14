from __future__ import annotations

import json
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from pathlib import Path

from lifedb.server import LifeDBServer
from lifedb.vault import Vault

from scripts.docs_runtime import HttpObservation, failure_scenario, request, runtime_scenario


class DocsRuntimeTest(unittest.TestCase):
    TOKEN = "docs-runtime-token-with-more-than-32-bytes-2026"

    def test_request_parses_json_headers_and_watermark(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            vault = Vault(Path(directory) / "vault")
            vault.init()
            server = LifeDBServer(("127.0.0.1", 0), vault, api_token=self.TOKEN)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                observation = request(
                    f"http://127.0.0.1:{server.server_port}",
                    "/health",
                )
                self.assertIsInstance(observation, HttpObservation)
                self.assertEqual(observation.status, 200)
                self.assertEqual(observation.body["status"], "ok")
                self.assertEqual(observation.cache_control, "no-store")
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=2)

    def test_runtime_scenario_observes_real_success_and_failure_contracts(self) -> None:
        result = runtime_scenario()
        self.assertIn("200", result)
        self.assertIn("201", result)
        self.assertIn("401", result)
        self.assertIn("409", result)
        self.assertIn("422", result)
        self.assertIn("clean", result)

    def test_request_reports_bounded_service_down_without_spool(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            observation = request("http://127.0.0.1:1", "/health", timeout=0.2)
            self.assertEqual(observation.status, 0)
            self.assertIsNotNone(observation.error)
            self.assertEqual(tuple(root.iterdir()), ())

    def test_unconfigured_server_returns_503_and_wrong_auth_returns_401(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            vault = Vault(Path(directory) / "vault")
            vault.init()
            server = LifeDBServer(("127.0.0.1", 0), vault, api_token=None)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                base = f"http://127.0.0.1:{server.server_port}"
                body = json.dumps({}).encode()
                self.assertEqual(request(base, "/v1/context", data=body).status, 503)
                self.assertEqual(
                    request(base, "/v1/context", token="wrong-token-000000000000000000000000", data=body).status,
                    503,
                )
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=2)

    def test_failure_scenario_observes_401_409_503(self) -> None:
        self.assertEqual(failure_scenario(), ("401", "409", "503"))


if __name__ == "__main__":
    unittest.main()
