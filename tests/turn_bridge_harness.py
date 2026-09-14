"""Ephemeral HTTP harness for bridge integration tests."""

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

TOKEN = "bridge-integration-token-2026-lifedb!!"
RAW_SESSION = "bridge-shared-raw-05"
WORKSPACE = "/srv/bridge-project"
TOKEN_ALPHA = "bridgelexicalalpha05"
TOKEN_BETA = "bridgelexicalbeta05"


def turn_bytes(
    host: str, turn_id: str, user_text: str, assistant_text: str, workspace: str
) -> bytes:
    """Encode one bridge payload with deliberately varied workspace spacing."""
    return json.dumps(
        {
            "host": host,
            "session_id": RAW_SESSION,
            "turn_id": turn_id,
            "workspace": workspace,
            "user_text": user_text,
            "assistant_text": assistant_text,
            "captured_at": "2026-09-07T00:00:00Z",
        }
    ).encode("utf-8")


class TurnBridgeHarness(unittest.TestCase):
    """Own a fresh Vault and real LifeDBServer for each integration case."""

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.vault = Vault(Path(self.temporary.name) / "vault")
        self.vault.init()
        self.server = LifeDBServer(
            ("127.0.0.1", 0), self.vault, api_token=TOKEN,
            principal="test-bridge-principal",
        )
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.base = f"http://127.0.0.1:{self.server.server_port}"

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)
        self.temporary.cleanup()

    def call(
        self, method: str, path: str, body: bytes | None = None
    ) -> tuple[int, dict[str, object]]:
        """Call an authenticated endpoint and decode its JSON response."""
        request = urllib.request.Request(
            self.base + path,
            data=body,
            headers={
                "Authorization": f"Bearer {TOKEN}",
                "Content-Type": "application/json",
            },
            method=method,
        )
        try:
            response = urllib.request.urlopen(request, timeout=5)
        except urllib.error.HTTPError as exc:
            return exc.code, json.loads(exc.read().decode("utf-8"))
        with response:
            return response.status, json.loads(response.read().decode("utf-8"))

    def evidence_id(self, record: dict[str, object]) -> str:
        """Extract a non-empty Evidence identifier."""
        value = record.get("id")
        if not isinstance(value, str) or not value:
            self.fail("evidence record id must be a non-empty string")
        return value

    def counts(self) -> tuple[int, int]:
        """Count durable Evidence records and object bytes in this Vault."""
        evidence = sum(
            1 for path in (self.vault.root / "evidence").rglob("*.json") if path.is_file()
        )
        objects = sum(
            1 for path in (self.vault.root / "objects").rglob("*") if path.is_file()
        )
        return evidence, objects

    def continuity_ids(self, pack: dict[str, object]) -> list[str]:
        """Extract source IDs from a Context Pack continuity projection."""
        items = pack.get("continuity")
        if not isinstance(items, list):
            self.fail("context pack continuity must be a list")
        found: list[str] = []
        for item in items:
            if not isinstance(item, dict):
                self.fail("continuity item must be an object")
            source_id = item.get("source_id")
            if not isinstance(source_id, str):
                self.fail("continuity source_id must be a string")
            found.append(source_id)
        return found

    def context(
        self,
        *,
        session: str | None = None,
        workspace: str | None = None,
        query: str = "bridge recall after validation",
    ) -> dict[str, object]:
        """Fetch a Context Pack using optional Continuity selectors."""
        payload: dict[str, str] = {"query": query}
        if session is not None:
            payload["session"] = session
        if workspace is not None:
            payload["workspace"] = workspace
        status, pack = self.call(
            "POST", "/v1/context", json.dumps(payload).encode("utf-8")
        )
        self.assertEqual(status, 200)
        return pack

    def seed_pair(self) -> tuple[str, str]:
        """Store one OpenCode and one Hermes turn sharing normalized workspace."""
        status, opened = self.call(
            "POST", "/v1/turns",
            turn_bytes(
                "opencode", "bridge-open-05",
                f"When does {TOKEN_ALPHA} ship after validation?",
                f"The {TOKEN_ALPHA} migration continues after the rebuild.",
                "  " + WORKSPACE,
            ),
        )
        self.assertEqual(status, 201)
        status, hermes = self.call(
            "POST", "/v1/turns",
            turn_bytes(
                "hermes", "bridge-hermes-05",
                f"Where is {TOKEN_BETA} tracked overnight?",
                f"{TOKEN_BETA} stays in the workspace queue.",
                WORKSPACE + "  ",
            ),
        )
        self.assertEqual(status, 201)
        return self.evidence_id(opened), self.evidence_id(hermes)
