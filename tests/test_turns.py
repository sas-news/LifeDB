from __future__ import annotations

import hashlib
import json
import unittest
from dataclasses import FrozenInstanceError


def _valid_request(**overrides: object) -> dict[str, object]:
    base: dict[str, object] = {
        "host": "opencode",
        "session_id": "sess-001",
        "turn_id": "msg-001",
        "workspace": "/srv/project",
        "user_text": "Continue the migration after validation.",
        "assistant_text": "Migration continued and validated.",
        "captured_at": "2026-09-07T10:00:00Z",
        "model": "test-model",
        "platform": "linux",
        "sensitivity": "personal",
    }
    base.update(overrides)
    return base


class TurnDomainTest(unittest.TestCase):
    def test_valid_request_parses_to_frozen_typed_value(self) -> None:
        from lifedb.turns import TurnRequest, parse_turn_request

        parsed = parse_turn_request(_valid_request())
        self.assertIsInstance(parsed, TurnRequest)
        self.assertEqual(parsed.host, "opencode")
        self.assertEqual(parsed.session_id, "sess-001")
        self.assertEqual(parsed.turn_id, "msg-001")
        with self.assertRaises(FrozenInstanceError):
            setattr(parsed, "host", "hermes")

    def test_canonical_bytes_are_stable_across_parses(self) -> None:
        from lifedb.turns import parse_turn_request

        first = parse_turn_request(_valid_request()).canonical_bytes()
        second = parse_turn_request(_valid_request()).canonical_bytes()
        self.assertEqual(first, second)
        self.assertEqual(
            hashlib.sha256(first).hexdigest(), hashlib.sha256(second).hexdigest()
        )

    def test_key_order_does_not_change_canonical_bytes(self) -> None:
        from lifedb.turns import parse_turn_bytes

        ordered = json.dumps(_valid_request(), sort_keys=True).encode("utf-8")
        reversed_keys = json.dumps(
            dict(reversed(list(_valid_request().items())))
        ).encode("utf-8")
        self.assertEqual(
            parse_turn_bytes(ordered).canonical_bytes(),
            parse_turn_bytes(reversed_keys).canonical_bytes(),
        )

    def test_unknown_host_is_rejected(self) -> None:
        from lifedb.turns import TurnValidationError, parse_turn_request

        with self.assertRaises(TurnValidationError):
            parse_turn_request(_valid_request(host="MCP"))
        with self.assertRaises(TurnValidationError):
            parse_turn_request(_valid_request(host=""))
        with self.assertRaises(TurnValidationError):
            parse_turn_request(_valid_request(host=42))

    def test_unknown_fields_are_rejected(self) -> None:
        from lifedb.turns import TurnValidationError, parse_turn_request

        with self.assertRaises(TurnValidationError):
            parse_turn_request(_valid_request(metadata={"arbitrary": True}))
        with self.assertRaises(TurnValidationError):
            parse_turn_request(_valid_request(reasoning="chain-of-thought"))

    def test_non_mapping_top_level_is_rejected(self) -> None:
        from lifedb.turns import TurnValidationError, parse_turn_request

        for value in ([], "text", None, 42):
            with self.subTest(value=value):
                with self.assertRaises(TurnValidationError):
                    parse_turn_request(value)

    def test_duplicate_json_keys_are_rejected_without_echo(self) -> None:
        from lifedb.turns import TurnValidationError, parse_turn_bytes

        marker = "secret-marker-that-must-not-be-echoed"
        payload = (
            '{"host":"opencode","host":"hermes","session_id":"s",'
            '"turn_id":"t","user_text":"%s","assistant_text":"b",'
            '"captured_at":"2026-09-07T10:00:00Z"}' % marker
        ).encode("utf-8")
        with self.assertRaises(TurnValidationError) as caught:
            parse_turn_bytes(payload)
        self.assertNotIn(marker, str(caught.exception))

    def test_empty_text_is_rejected(self) -> None:
        from lifedb.turns import TurnValidationError, parse_turn_request

        with self.assertRaises(TurnValidationError):
            parse_turn_request(_valid_request(user_text=""))
        with self.assertRaises(TurnValidationError):
            parse_turn_request(_valid_request(user_text="   "))
        with self.assertRaises(TurnValidationError):
            parse_turn_request(_valid_request(assistant_text=""))

    def test_control_characters_are_rejected(self) -> None:
        from lifedb.turns import TurnValidationError, parse_turn_request

        with self.assertRaises(TurnValidationError):
            parse_turn_request(_valid_request(session_id="a\x00b"))
        with self.assertRaises(TurnValidationError):
            parse_turn_request(_valid_request(turn_id="a\x1fb"))
        with self.assertRaises(TurnValidationError):
            parse_turn_request(_valid_request(user_text="hello\x00world"))
        with self.assertRaises(TurnValidationError):
            parse_turn_request(_valid_request(assistant_text="hello\x07world"))
        # Ordinary multi-line conversation text stays legal.
        parsed = parse_turn_request(
            _valid_request(user_text="line one\nline two\tindented")
        )
        self.assertIn("\n", parsed.user_text)

    def test_oversized_fields_are_rejected(self) -> None:
        from lifedb.turns import TurnValidationError, parse_turn_request

        with self.assertRaises(TurnValidationError):
            parse_turn_request(_valid_request(session_id="s" * 257))
        with self.assertRaises(TurnValidationError):
            parse_turn_request(_valid_request(turn_id="t" * 257))
        with self.assertRaises(TurnValidationError):
            parse_turn_request(_valid_request(workspace="/w" * 4096))
        with self.assertRaises(TurnValidationError):
            parse_turn_request(_valid_request(user_text="u" * 200_001))
        with self.assertRaises(TurnValidationError):
            parse_turn_request(_valid_request(assistant_text="a" * 200_001))
        with self.assertRaises(TurnValidationError):
            parse_turn_request(_valid_request(model="m" * 257))

    def test_invalid_timestamps_are_rejected(self) -> None:
        from lifedb.turns import TurnValidationError, parse_turn_request

        for captured in (
            "2026-09-07 10:00:00",
            "2026-09-07 10:00:00Z",
            "2026-09-07T10:00:00",
            "2026-09-07T10:00",
            "2026-09-07T10:00:00z",
            "2026-09-07T10:00:00+0000",
            "2026-09-07T10:00:00+00",
            "2026-09-07T10:00:00 ",
            "not-a-time",
            "",
            None,
            1234567890,
            "2026-13-40T99:99:99Z",
            "2026-09-07T10:00:00." + "0" * 200 + "Z",
        ):
            with self.subTest(captured=captured):
                with self.assertRaises(TurnValidationError):
                    parse_turn_request(_valid_request(captured_at=captured))

    def test_timestamp_with_offset_and_fraction_is_accepted(self) -> None:
        from lifedb.turns import parse_turn_request

        parsed = parse_turn_request(
            _valid_request(captured_at="2026-09-07T15:30:00.123+05:30")
        )
        self.assertEqual(parsed.captured_at, "2026-09-07T15:30:00.123000+05:30")

    def test_invalid_sensitivity_is_rejected(self) -> None:
        from lifedb.turns import TurnValidationError, parse_turn_request

        with self.assertRaises(TurnValidationError):
            parse_turn_request(_valid_request(sensitivity="top-secret"))
        with self.assertRaises(TurnValidationError):
            parse_turn_request(_valid_request(sensitivity=""))
        # Omission (or explicit null) is legal; the server floor owns the default.
        self.assertIsNone(parse_turn_request(_valid_request(sensitivity=None)).sensitivity)
        request = dict(_valid_request())
        del request["sensitivity"]
        self.assertIsNone(parse_turn_request(request).sensitivity)

    def test_session_label_is_namespaced_per_host(self) -> None:
        from lifedb.turns import parse_turn_request

        opencode = parse_turn_request(_valid_request(host="opencode"))
        hermes = parse_turn_request(_valid_request(host="hermes"))
        self.assertEqual(opencode.session_label, "agent:opencode:session:sess-001")
        self.assertEqual(hermes.session_label, "agent:hermes:session:sess-001")
        self.assertNotEqual(opencode.session_label, hermes.session_label)

    def test_workspace_leading_trailing_controls_rejected_before_strip(self) -> None:
        from lifedb.turns import TurnValidationError, parse_turn_request

        for workspace in (
            "  /srv/project\x00",
            "\x00/srv/project  ",
            "/srv/project\n",
            "\t/srv/project",
            "/srv/project\x7f",
        ):
            with self.subTest(workspace=repr(workspace)):
                with self.assertRaises(TurnValidationError):
                    parse_turn_request(_valid_request(workspace=workspace))

    def test_workspace_is_normalized_and_shared_across_hosts(self) -> None:
        from lifedb.turns import parse_turn_request

        opencode = parse_turn_request(_valid_request(workspace="  /srv/project  "))
        hermes = parse_turn_request(
            _valid_request(host="hermes", workspace="/srv/project")
        )
        self.assertEqual(opencode.workspace, "/srv/project")
        self.assertEqual(opencode.workspace, hermes.workspace)
        self.assertEqual(
            opencode.source_metadata()["workspace"],
            hermes.source_metadata()["workspace"],
        )
        omitted = parse_turn_request(
            {k: v for k, v in _valid_request().items() if k != "workspace"}
        )
        self.assertIsNone(omitted.workspace)
        self.assertNotIn("workspace", omitted.source_metadata())

    def test_fixed_media_metadata(self) -> None:
        from lifedb.turns import parse_turn_request

        parsed = parse_turn_request(_valid_request())
        self.assertEqual(parsed.media_type, "application/vnd.lifedb.agent-turn+json")
        self.assertEqual(parsed.filename, "turn.json")
        self.assertEqual(parsed.evidence_kind, "conversation")
        self.assertTrue(parsed.media_type.endswith("+json"))

    def test_external_id_is_deterministic_and_text_independent(self) -> None:
        from lifedb.turns import parse_turn_request

        first = parse_turn_request(_valid_request())
        altered_text = parse_turn_request(
            _valid_request(user_text="different user text", assistant_text="other")
        )
        self.assertEqual(first.external_id, altered_text.external_id)
        expected = "turn-v1:" + hashlib.sha256(
            b"opencode\x00sess-001\x00msg-001"
        ).hexdigest()
        self.assertEqual(first.external_id, expected)
        other_turn = parse_turn_request(_valid_request(turn_id="msg-002"))
        self.assertNotEqual(first.external_id, other_turn.external_id)

    def test_source_metadata_has_no_uri_account_or_device(self) -> None:
        from lifedb.turns import parse_turn_request

        parsed = parse_turn_request(_valid_request())
        self.assertEqual(parsed.source_kind, "opencode")
        metadata = parsed.source_metadata()
        self.assertEqual(metadata["session"], "agent:opencode:session:sess-001")
        for forbidden in ("uri", "account", "device"):
            self.assertNotIn(forbidden, metadata)

    def test_errors_are_sanitized_typed_values(self) -> None:
        from lifedb.turns import TurnValidationError, parse_turn_request

        marker = "note-marker-0001-without-credential-pattern"
        parsed = parse_turn_request(_valid_request(user_text=f"note {marker}"))
        self.assertIn(marker, parsed.user_text)
        with self.assertRaises(TurnValidationError) as caught:
            parse_turn_request(_valid_request(host="bogus", user_text=marker))
        self.assertNotIn(marker, str(caught.exception))
        self.assertTrue(issubclass(TurnValidationError, ValueError))

    def test_ingest_kwargs_carry_server_derived_provenance(self) -> None:
        from lifedb.turns import parse_turn_request

        parsed = parse_turn_request(_valid_request())
        kwargs = parsed.ingest_kwargs(sensitivity="personal")
        self.assertEqual(kwargs["source_kind"], "opencode")
        self.assertEqual(kwargs["media_type"], "application/vnd.lifedb.agent-turn+json")
        self.assertEqual(kwargs["filename"], "turn.json")
        self.assertEqual(kwargs["kind"], "conversation")
        self.assertEqual(kwargs["sensitivity"], "personal")
        self.assertEqual(
            kwargs["source_metadata"]["host"], "opencode"
        )
        self.assertEqual(
            kwargs["source_metadata"]["turn"], "msg-001"
        )
        self.assertEqual(kwargs["data"], parsed.canonical_bytes())
        self.assertNotIn("source_uri", kwargs)
        with self.assertRaises(ValueError):
            parsed.ingest_kwargs(sensitivity="bogus-label")


if __name__ == "__main__":
    unittest.main()
