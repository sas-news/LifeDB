"""Shared ephemeral-server harness for the POST /v1/turns boundary tests."""

from __future__ import annotations

import http.client
import json
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from pathlib import Path

from lifedb.server import LifeDBServer
from lifedb.vault import Vault


def build_turn_bytes(turn_id: str, **overrides: object) -> bytes:
    """Encode one canonical turn request; callers override scalar fields."""
    fields: dict[str, object] = {
        "host": "opencode",
        "session_id": "session-42",
        "turn_id": turn_id,
        "workspace": "/srv/project",
        "user_text": "What remains open after validation?",
        "assistant_text": "The migration continues after the rebuild.",
        "captured_at": "2026-09-07T00:00:00Z",
    }
    fields.update(overrides)
    return json.dumps(fields).encode("utf-8")


class TurnsServerHarness(unittest.TestCase):
    TOKEN = "turns-boundary-test-token-2026-lifedb!!"

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.vault = Vault(Path(self.temporary.name) / "vault")
        self.vault.init()
        self.server = LifeDBServer(
            ("127.0.0.1", 0),
            self.vault,
            api_token=self.TOKEN,
            principal="test-http-principal",
        )
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.base = f"http://127.0.0.1:{self.server.server_port}"

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)
        self.temporary.cleanup()

    def post_turn(
        self,
        body: bytes,
        *,
        headers: dict[str, str] | None = None,
        authenticated: bool = True,
        token: str | None = None,
        path: str = "/v1/turns",
        method: str = "POST",
    ) -> tuple[int, dict[str, object], http.client.HTTPMessage]:
        merged = dict(headers or {})
        if authenticated:
            merged.setdefault("Authorization", f"Bearer {token or self.TOKEN}")
        merged.setdefault("Content-Type", "application/json")
        request = urllib.request.Request(
            self.base + path, data=body, headers=merged, method=method
        )
        try:
            response = urllib.request.urlopen(request, timeout=3)
        except urllib.error.HTTPError as exc:
            payload: dict[str, object] = json.loads(exc.read().decode("utf-8"))
            return exc.code, payload, exc.headers
        with response:
            ok_payload: dict[str, object] = json.loads(response.read().decode("utf-8"))
            return response.status, ok_payload, response.headers

    def raw_turn(
        self, header_list: list[tuple[str, str]], body: bytes
    ) -> tuple[int, bytes, bool]:
        connection = http.client.HTTPConnection(
            "127.0.0.1", self.server.server_port, timeout=3
        )
        connection.putrequest("POST", "/v1/turns")
        for name, value in header_list:
            connection.putheader(name, value)
        connection.endheaders(body)
        response = connection.getresponse()
        payload = response.read()
        status = response.status
        will_close = response.will_close
        connection.close()
        return status, payload, will_close

    def durable_counts(self) -> tuple[int, int]:
        evidence = sum(
            1 for path in (self.vault.root / "evidence").rglob("*.json") if path.is_file()
        )
        objects = sum(
            1 for path in (self.vault.root / "objects").rglob("*") if path.is_file()
        )
        return (evidence, objects)
