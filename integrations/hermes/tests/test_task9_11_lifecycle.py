from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path
import tempfile
import unittest
from typing import Callable

from integrations.hermes import hooks, postflight, transport
from integrations.hermes.settings import SettingValue


class _Context:
    def __init__(self, values: dict[str, SettingValue]) -> None:
        self.values = values
        self.calls: list[str] = []

    def get_config(self, key: str, default: SettingValue = None) -> SettingValue:
        self.calls.append(key)
        return self.values.get(key, default)


class _Transport:
    def __init__(self) -> None:
        self.requests: list[tuple[str, str, bytes, float]] = []

    def request(self, url: str, token: str, body: bytes, timeout: float) -> transport.HttpResponse:
        self.requests.append((url, token, body, timeout))
        return transport.HttpResponse(201, b"{}")


class LifecycleTests(unittest.TestCase):
    def _callbacks(
        self, fake: _Transport, *, guard_limit: int = 128
    ) -> tuple[Callable[..., None], Callable[..., None]]:
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        token = Path(directory.name) / "token"
        token.write_bytes(b"t" * 32)
        token.chmod(0o600)
        context = _Context({"url": "http://bridge", "token_file": str(token)})
        return postflight.make_lifecycle_callbacks(
            context,
            lambda _limit: fake,
            lambda: datetime(2026, 9, 9, tzinfo=timezone.utc),
            guard_limit=guard_limit,
        )

    def test_post_llm_call_buffers_without_request_or_configuration_access(self) -> None:
        fake = _Transport()
        context = _Context({})
        post, _ = postflight.make_lifecycle_callbacks(
            context,
            lambda _limit: fake,
            lambda: datetime.now(timezone.utc),
        )

        self.assertIsNone(
            post(
                session_id="session",
                turn_id="turn",
                user_message="hello",
                assistant_response="world",
            )
        )

        self.assertEqual(fake.requests, [])
        self.assertEqual(context.calls, [])

    def test_failed_terminal_outcome_discards_truthy_candidate(self) -> None:
        fake = _Transport()
        post, session_end = self._callbacks(fake)
        post(
            session_id="session",
            turn_id="turn",
            user_message="hello",
            assistant_response="world",
        )

        session_end(
            session_id="session",
            turn_id="turn",
            completed=True,
            failed=True,
            interrupted=False,
        )

        self.assertEqual(fake.requests, [])

    def test_successful_terminal_outcome_submits_once_at_finalization(self) -> None:
        fake = _Transport()
        post, session_end = self._callbacks(fake)
        post(
            session_id="session",
            turn_id="turn",
            user_message="hello",
            assistant_response="world",
            conversation_history=["ignored"],
            model="ignored",
            platform="ignored",
            failed=True,
        )
        self.assertEqual(fake.requests, [])

        session_end(
            session_id="session",
            turn_id="turn",
            completed=True,
            failed=False,
            interrupted=False,
            turn_exit_reason="ignored",
            model="ignored",
            platform="ignored",
        )
        self.assertEqual(len(fake.requests), 1)

    def test_successful_finalization_serializes_configured_workspace(self) -> None:
        fake = _Transport()
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        token = Path(directory.name) / "token"
        token.write_bytes(b"t" * 32)
        token.chmod(0o600)
        context = _Context(
            {"url": "http://bridge", "token_file": str(token), "workspace": "/workspace"}
        )
        post, session_end = postflight.make_lifecycle_callbacks(
            context,
            lambda _limit: fake,
            lambda: datetime(2026, 9, 9, tzinfo=timezone.utc),
        )

        post(session_id="session", turn_id="turn", user_message="hello", assistant_response="world")
        session_end(session_id="session", turn_id="turn", completed=True, failed=False, interrupted=False)

        self.assertEqual(json.loads(fake.requests[0][2])["workspace"], "/workspace")
        self.assertIn(b'"user_text":"hello"', fake.requests[0][2])
        self.assertIn(b'"assistant_text":"world"', fake.requests[0][2])

        session_end(
            session_id="session",
            turn_id="turn",
            completed=True,
            failed=False,
            interrupted=False,
        )
        self.assertEqual(len(fake.requests), 1)

    def test_malformed_terminal_controls_tombstone_candidate(self) -> None:
        fake = _Transport()
        post, session_end = self._callbacks(fake)
        post(session_id="session", turn_id="turn", user_message="u", assistant_response="a")
        session_end(session_id="session", turn_id="turn", completed="true", failed=False, interrupted=False)
        session_end(session_id="session", turn_id="turn", completed=True, failed=False, interrupted=False)
        self.assertEqual(fake.requests, [])

    def test_unsuccessful_terminal_controls_tombstone_candidate(self) -> None:
        fake = _Transport()
        post, session_end = self._callbacks(fake)
        outcomes = ((False, False, False), (True, True, False), (True, False, True))
        for index, values in enumerate(outcomes):
            turn = f"turn-{index}"
            post(session_id="session", turn_id=turn, user_message="u", assistant_response="a")
            session_end(
                session_id="session",
                turn_id=turn,
                completed=values[0],
                failed=values[1],
                interrupted=values[2],
            )
        self.assertEqual(fake.requests, [])

    def test_terminal_before_candidate_suppresses_later_reordered_candidate(self) -> None:
        fake = _Transport()
        post, session_end = self._callbacks(fake)
        session_end(session_id="session", turn_id="turn", completed=False, failed=False, interrupted=True)
        post(session_id="session", turn_id="turn", user_message="u", assistant_response="a")
        session_end(session_id="session", turn_id="turn", completed=True, failed=False, interrupted=False)
        self.assertEqual(fake.requests, [])

    def test_invalid_ids_and_text_are_ignored_without_request(self) -> None:
        fake = _Transport()
        post, _ = self._callbacks(fake)
        for values in (
            {"session_id": "", "turn_id": "turn", "user_message": "u", "assistant_response": "a"},
            {"session_id": "session", "turn_id": "turn", "user_message": "u\x01", "assistant_response": "a"},
            {"session_id": "session", "turn_id": "turn", "user_message": "u", "assistant_response": ""},
        ):
            post(**values)
        self.assertEqual(fake.requests, [])

    def test_full_live_capacity_refuses_new_candidate_but_evicts_terminal(self) -> None:
        fake = _Transport()
        limited_post, limited_end = self._callbacks(fake, guard_limit=1)
        limited_post(session_id="s", turn_id="live", user_message="u", assistant_response="a")
        limited_post(session_id="s", turn_id="new", user_message="u", assistant_response="a")
        limited_end(session_id="s", turn_id="live", completed=False, failed=False, interrupted=True)
        limited_post(session_id="s", turn_id="new", user_message="u", assistant_response="a")
        limited_end(session_id="s", turn_id="new", completed=True, failed=False, interrupted=False)
        self.assertEqual(len(fake.requests), 1)

    def test_finalizer_logs_transport_status_without_text(self) -> None:
        fake = _Transport()
        post, session_end = self._callbacks(fake)
        post(session_id="s", turn_id="t", user_message="private user", assistant_response="private assistant")
        from unittest.mock import patch

        with patch("integrations.hermes.postflight.log_outcome") as logged:
            session_end(session_id="s", turn_id="t", completed=True, failed=False, interrupted=False)
        self.assertEqual(logged.call_args.args, ("turn.capture", "ok"))
        self.assertNotIn("private", str(logged.call_args))

    def test_configured_hooks_register_exactly_three_public_hooks(self) -> None:
        context = _Context({})
        registered: list[str] = []

        class Registration:
            def register_hook(self, name: str, callback: Callable[..., None]) -> None:
                del callback
                registered.append(name)

        hooks_to_register = hooks.configured_hooks(context)
        self.assertEqual(
            tuple(name for name, _callback in hooks_to_register),
            ("pre_llm_call", "post_llm_call", "on_session_end"),
        )

        from integrations.hermes import register

        register(Registration())
        self.assertEqual(registered, ["pre_llm_call", "post_llm_call", "on_session_end"])


if __name__ == "__main__":
    unittest.main()
