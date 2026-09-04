from __future__ import annotations

import json
import math
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from lifedb.evidence import read_capture, read_event
from lifedb.storage import durable_write_json, strict_json_loads
from lifedb.vault import Vault


class StrictJSONTest(unittest.TestCase):
    def test_decoder_rejects_nested_duplicates_without_echoing_key(self) -> None:
        marker = "private-marker-that-must-not-be-echoed"
        payload = ('{"outer":{"%s":1,"%s":2}}' % (marker, marker)).encode("utf-8")
        with self.assertRaises(ValueError) as caught:
            strict_json_loads(payload, max_bytes=1024)
        self.assertEqual(str(caught.exception), "invalid strict JSON")
        self.assertNotIn(marker, str(caught.exception))

    def test_decoder_rejects_nonfinite_overflow_and_invalid_utf8(self) -> None:
        for payload in (
            b'{"n":NaN}',
            b'{"n":Infinity}',
            b'{"n":1e999}',
            b'"\xff"',
            b'"\\ud800"',
        ):
            with self.subTest(payload=payload):
                with self.assertRaisesRegex(ValueError, "invalid strict JSON"):
                    strict_json_loads(payload, max_bytes=1024)

    def test_decoder_enforces_byte_cap_but_leaves_top_level_type_to_caller(self) -> None:
        self.assertEqual(strict_json_loads(b"[1,2]", max_bytes=5), [1, 2])
        with self.assertRaisesRegex(ValueError, "maximum size"):
            strict_json_loads(b"[1,2]", max_bytes=4)
        with self.assertRaisesRegex(ValueError, "positive integer"):
            strict_json_loads(b"{}", max_bytes=0)

    def test_decoder_normalizes_excessive_nesting_to_stable_value_error(self) -> None:
        with mock.patch("lifedb.storage.json.loads", side_effect=RecursionError):
            with self.assertRaises(ValueError) as caught:
                strict_json_loads(b"[]", max_bytes=2)
        self.assertEqual(str(caught.exception), "invalid strict JSON")

    def test_canonical_writer_values_round_trip_through_strict_decoder(self) -> None:
        value = {"unicode": "日本語", "number": math.pi, "nested": [True, None]}
        payload = json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
        self.assertEqual(strict_json_loads(payload, max_bytes=len(payload)), value)

    def test_capture_and_event_reject_duplicate_keys_even_if_last_value_integrity_matches(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            vault = Vault(Path(temporary) / "vault")
            vault.init()
            capture = vault.ingest(b"capture", source_kind="test")
            capture_path = vault.evidence_path(capture["id"])
            assert capture_path is not None
            capture_text = capture_path.read_text(encoding="utf-8")
            capture_text = capture_text.replace(
                '  "schema": "0.2",',
                '  "schema": "private-marker",\n  "schema": "0.2",',
                1,
            )
            capture_path.chmod(0o600)
            capture_path.write_text(capture_text, encoding="utf-8")
            with self.assertRaises(ValueError) as caught_capture:
                read_capture(capture_path)
            self.assertNotIn("private-marker", str(caught_capture.exception))

            event = vault.append_event("audit-entry", actor="process:test", data={"ok": True})
            event_path = next(
                (vault.root / "evidence" / "_events").rglob(f"{event['id']}.json")
            )
            event_text = event_path.read_text(encoding="utf-8")
            event_text = event_text.replace(
                '"schema":"0.2"',
                '"schema":"private-marker","schema":"0.2"',
                1,
            )
            event_path.chmod(0o600)
            event_path.write_text(event_text, encoding="utf-8")
            with self.assertRaises(ValueError) as caught_event:
                read_event(event_path)
            self.assertNotIn("private-marker", str(caught_event.exception))

    def test_record_readers_reject_nonfinite_json_before_integrity(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "record.json"
            path.write_bytes(b'{"schema":"0.2","number":NaN}')
            with self.assertRaisesRegex(ValueError, "invalid strict JSON"):
                read_capture(path)
            with self.assertRaisesRegex(ValueError, "invalid strict JSON"):
                read_event(path)

    def test_bounded_writer_rejects_parent_symlink_without_external_write(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            boundary = base / "vault"
            external = base / "external"
            boundary.mkdir()
            external.mkdir()
            (boundary / "linked").symlink_to(external, target_is_directory=True)

            with self.assertRaisesRegex(ValueError, "real directory"):
                durable_write_json(
                    boundary / "linked" / "event.json",
                    {"safe": True},
                    exclusive=True,
                    boundary=boundary,
                )
            self.assertEqual(list(external.iterdir()), [])

            with self.assertRaisesRegex(ValueError, "inside the durable boundary"):
                durable_write_json(
                    external / "event.json",
                    {"safe": True},
                    exclusive=True,
                    boundary=boundary,
                )


if __name__ == "__main__":
    unittest.main()
