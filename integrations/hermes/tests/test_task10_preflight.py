from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest

from integrations.hermes import preflight, settings, transport


class _Context:
    def __init__(self, values: dict[str, str | int | float | bool | None]) -> None:
        self.values = values
        self.calls: list[str] = []

    def get_config(self, key: str, default: str | int | float | bool | None = None) -> str | int | float | bool | None:
        self.calls.append(key)
        return self.values.get(key, default)


class _Transport:
    def __init__(self, body: bytes, status: int = 200) -> None:
        self.body = body
        self.status = status
        self.requests: list[tuple[str, str, bytes, float]] = []

    def request(self, url: str, token: str, body: bytes, timeout: float) -> transport.HttpResponse:
        self.requests.append((url, token, body, timeout))
        return transport.HttpResponse(self.status, self.body)


def _pack(markdown: str = "# LifeDB Context Pack\n\n<lifedb-data source=\"evidence:019d0000-0000-7000-8000-000000000001\" sensitivity=\"personal\" untrusted=\"true\">x</lifedb-data>\n") -> bytes:
    return json.dumps({
        "schema": "0.2", "id": "019d0000-0000-7000-8000-000000000001",
        "generated_at": "2026-09-09T00:00:00Z", "query": "hello", "client": "hermes",
        "core": [], "continuity": [], "relevant": [], "evidence_handles": [],
        "rendered_markdown": markdown,
        "authorization": {"principal": "owner", "sensitivity_ceiling": "personal"},
        "budget": {"budget_chars": 12000, "core_chars": 4000, "continuity_chars": 2000, "relevant_chars": 6000, "used_chars": 1},
        "watermark": {"durable_sequence": 1, "indexed_sequence": 1, "dirty": False},
        "truncated": False, "degraded": [],
    }, separators=(",", ":")).encode()


class Task10PreflightTests(unittest.TestCase):
    def _factory(self, values: dict[str, str | int | float | bool | None], fake: _Transport, cwd: str = "/work/current"):
        context = _Context(values)
        callback = preflight.create_preflight(context, transport_factory=lambda _cap: fake, cwd=lambda: cwd)
        return context, callback

    def test_valid_callback_returns_only_rendered_context_and_exact_request(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            token = Path(directory) / "token"
            token.write_bytes(b"t" * 32)
            token.chmod(0o600)
            fake = _Transport(_pack())
            context, callback = self._factory({"token_file": str(token), "workspace": "/configured/project", "timeout_seconds": 1.25}, fake)
            result = callback(session_id="session-1", task_id="task-1", turn_id="turn-1", user_message="hello", conversation_history=["secret"], is_first_turn=True, model="m", platform="p", parent_session_id=None, sender_id=None)
            self.assertEqual(result, {"context": json.loads(_pack())["rendered_markdown"]})
            self.assertEqual(len(fake.requests), 1)
            self.assertEqual(json.loads(fake.requests[0][2]), {
                "client": "hermes", "query": "hello", "session": "agent:hermes:session:session-1",
                "workspace": "/configured/project", "limit": 8, "budget_chars": 12000,
                "core_chars": 4000, "continuity_chars": 2000, "relevant_chars": 6000,
            })
            self.assertEqual(fake.requests[0][3], 1.25)
            self.assertIn("workspace", context.calls)

    def test_workspace_falls_back_to_absolute_cwd_or_omits(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            token = Path(directory) / "token"
            token.write_bytes(b"u" * 32)
            token.chmod(0o600)
            for configured, cwd, expected in ((None, "/work/current", "/work/current"), (None, "relative", None)):
                fake = _Transport(_pack())
                values = {"token_file": str(token)}
                if configured is not None:
                    values["workspace"] = configured
                _, callback = self._factory(values, fake, cwd)
                callback(session_id="s", task_id="t", turn_id="r", user_message="q")
                payload = json.loads(fake.requests[0][2])
                self.assertEqual(payload.get("workspace"), expected)

    def test_invalid_input_or_pack_fails_open_without_history_transport(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            token = Path(directory) / "token"
            token.write_bytes(b"v" * 32)
            token.chmod(0o600)
            for message in (None, "", " \n", "x\x00", "x" * 4097):
                fake = _Transport(_pack())
                _, callback = self._factory({"token_file": str(token)}, fake)
                self.assertIsNone(callback(session_id="s", task_id="t", turn_id="r", user_message=message, conversation_history=["do not send"]))
                self.assertEqual(fake.requests, [])
            malformed = _Transport(b"{}")
            _, callback = self._factory({"token_file": str(token)}, malformed)
            self.assertIsNone(callback(session_id="s", task_id="t", turn_id="r", user_message="q"))
            self.assertEqual(len(malformed.requests), 1)

    def test_status_timeout_and_transport_fail_open(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            token = Path(directory) / "token"
            token.write_bytes(b"w" * 32)
            token.chmod(0o600)
            for status in (400, 401, 503):
                fake = _Transport(_pack(), status=status)
                _, callback = self._factory({"token_file": str(token)}, fake)
                self.assertIsNone(callback(session_id="s", task_id="t", turn_id="r", user_message="q"))

            class FailingTransport(_Transport):
                def request(self, url: str, bearer: str, body: bytes, timeout: float) -> transport.HttpResponse:
                    del url, bearer, body, timeout
                    raise TimeoutError("deadline")

            fake = FailingTransport(_pack())
            _, callback = self._factory({"token_file": str(token)}, fake)
            self.assertIsNone(callback(session_id="s", task_id="t", turn_id="r", user_message="q"))

    def test_settings_are_read_for_each_invocation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            token = Path(directory) / "token"
            token.write_bytes(b"x" * 32)
            token.chmod(0o600)
            fake = _Transport(_pack())
            context, callback = self._factory({"token_file": str(token)}, fake)
            callback(session_id="s", task_id="t", turn_id="r", user_message="q")
            context.values["token_file"] = None
            self.assertIsNone(callback(session_id="s", task_id="t", turn_id="r", user_message="q"))
            self.assertEqual(len(fake.requests), 1)


if __name__ == "__main__":
    unittest.main()
