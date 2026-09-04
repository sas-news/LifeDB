from __future__ import annotations

import json
import math
import os
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest import mock

from lifedb.evidence import (
    DURABLE_RECORD_MAX_BYTES,
    EVENT_DATA_MAX_BYTES,
    iter_event_paths,
    iter_events,
    read_event,
    seal_record,
)
from lifedb.ids import new_id
from lifedb.secrets import SecretDetectedError, assert_no_credentials
from lifedb.storage import durable_write_json
from lifedb.vault import Vault


class EventSafetyTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name) / "vault"
        self.vault = Vault(self.root)
        self.vault.init()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _events(self) -> list[dict]:
        return list(iter_events(self.vault))

    def test_event_file_and_new_parent_directories_are_private(self) -> None:
        event = self.vault.append_event(
            "audit-entry",
            actor="process:test",
            category="fresh",
            data={"ok": True},
            recorded_at="2026-01-02T00:00:00Z",
        )
        path = next((self.root / "evidence" / "_events").rglob(f"{event['id']}.json"))
        self.assertEqual(path.stat().st_mode & 0o777, 0o400)
        for parent_name in ("fresh", "2026", "01", "02"):
            parent = next(parent for parent in path.parents if parent.name == parent_name)
            self.assertEqual(parent.stat().st_mode & 0o777, 0o700)

    def test_invalid_input_does_not_allocate_sequence_or_create_event_files(self) -> None:
        invalid = [
            {"actor": "bad\nactor"},
            {"actor": "x" * 257},
            {"actor": "process:test", "recorded_at": "2026-01-01T00:00:00"},
            {"actor": "process:test", "data": {"number": math.nan}},
            {"actor": "process:test", "data": {"number": math.inf}},
            {"actor": "process:test", "data": {"bad": object()}},
        ]
        for arguments in invalid:
            with self.assertRaises((TypeError, ValueError)):
                self.vault.append_event("audit-entry", **arguments)
            self.assertEqual(self._events(), [])
        self.assertEqual(list((self.root / "evidence" / "_events").rglob("*.json")), [])

    def test_oversized_and_secret_data_are_rejected_without_echoing_or_sequence_change(self) -> None:
        oversized = {"payload": "x" * EVENT_DATA_MAX_BYTES}
        with self.assertRaisesRegex(ValueError, "maximum size"):
            self.vault.append_event("audit-entry", actor="process:test", data=oversized)
        secret = "sk-proj-" + "A" * 32
        with self.assertRaises(SecretDetectedError) as caught:
            self.vault.append_event("audit-entry", actor="process:test", data={"token": secret})
        self.assertNotIn(secret, str(caught.exception))
        self.assertEqual(self._events(), [])

        event = self.vault.append_event("audit-entry", actor="process:test", data={"ok": True})
        self.assertEqual(event["sequence"], 1)

    def test_data_is_detached_and_canonicalized_before_publication(self) -> None:
        data = {"nested": {"value": "before"}}
        event = self.vault.append_event("audit-entry", actor="process:test", data=data)
        data["nested"]["value"] = "after"
        self.assertEqual(event["data"], {"nested": {"value": "before"}})
        path = next((self.root / "evidence" / "_events").rglob(f"{event['id']}.json"))
        self.assertEqual(json.loads(path.read_text(encoding="utf-8"))["data"], event["data"])

    def test_missing_observed_lifecycle_alias_projects_missing_metadata(self) -> None:
        capture = self.vault.ingest(b"payload", source_kind="test")
        observed = self.vault.append_event(
            "payload.missing-observed",
            actor="process:scanner",
            target=capture["id"],
            data={"reason": "object disappeared"},
            recorded_at="2026-01-02T00:00:00Z",
        )
        effective = self.vault.effective_evidence(capture["id"])
        assert effective is not None
        self.assertEqual(effective["payload"]["state"], "missing")
        self.assertNotIn("object", effective["payload"])
        self.assertEqual(effective["payload"]["missing_at"], observed["recorded_at"])
        self.assertEqual(effective["payload"]["missing_reason"], "object disappeared")

        restored = self.vault.append_event(
            "payload-restored",
            actor="process:scanner",
            target=capture["id"],
            data={},
            recorded_at="2026-01-02T00:00:01Z",
        )
        effective = self.vault.effective_evidence(capture["id"])
        assert effective is not None
        self.assertEqual(effective["payload"]["state"], "present")
        self.assertEqual(
            effective["payload"]["object"], f"sha256:{capture['content']['sha256']}"
        )
        self.assertEqual(restored["sequence"], 2)

    def test_failed_publication_leaves_no_final_or_partial_event(self) -> None:
        with mock.patch("lifedb.storage.os.link", side_effect=OSError("publish failed")):
            with self.assertRaisesRegex(OSError, "publish failed"):
                self.vault.append_event("audit-entry", actor="process:test", data={"ok": True})
        events_root = self.root / "evidence" / "_events"
        self.assertEqual(list(events_root.rglob("*.json")), [])
        self.assertEqual(list(events_root.rglob(".*.tmp-*")), [])
        self.assertEqual(self._events(), [])
        event = self.vault.append_event("audit-entry", actor="process:test", data={"ok": True})
        self.assertEqual(event["sequence"], 1)

    def test_runtime_marker_failure_does_not_ambiguate_durable_publication(self) -> None:
        with mock.patch("lifedb.vault.durable_touch", side_effect=OSError("runtime unavailable")):
            capture = self.vault.ingest(b"marker-failure", source_kind="test")
            event = self.vault.append_event(
                "audit-entry", actor="process:test", data={"capture": capture["id"]}
            )
        self.assertTrue(capture["id"])
        self.assertEqual(event["sequence"], 1)
        self.assertIsNotNone(self.vault.load_evidence(capture["id"]))
        self.assertEqual(len(list(iter_events(self.vault))), 1)
        # The init marker remains a dirty watermark even if the replacement
        # attempt fails; a missing marker is still safe because runtime is
        # disposable and the next rebuild scans durable state.
        self.assertTrue(self.vault.index_dirty_path.exists())

    def test_default_secret_scan_covers_the_complete_input(self) -> None:
        secret = b"sk-proj-" + b"A" * 32
        with self.assertRaises(SecretDetectedError):
            assert_no_credentials(b"x" * (8 * 1024 * 1024 + 1) + b" " + secret)

    def test_concurrent_appends_preserve_one_global_chain(self) -> None:
        def append(index: int) -> dict:
            return self.vault.append_event(
                "audit-entry", actor="process:test", data={"index": index}
            )

        with ThreadPoolExecutor(max_workers=6) as executor:
            returned = list(executor.map(append, range(18)))
        ordered = sorted(returned, key=lambda event: event["sequence"])
        self.assertEqual([event["sequence"] for event in ordered], list(range(1, 19)))
        self.assertIsNone(ordered[0]["previous_event"])
        self.assertEqual(
            [event["previous_event"] for event in ordered[1:]],
            [event["id"] for event in ordered[:-1]],
        )

    def test_deleted_event_gap_blocks_append_without_publishing(self) -> None:
        first = self.vault.append_event("audit-entry", actor="process:test", data={"n": 1})
        second = self.vault.append_event("audit-entry", actor="process:test", data={"n": 2})
        first_path = next(
            (self.root / "evidence" / "_events").rglob(f"{first['id']}.json")
        )
        first_path.unlink()
        before = list((self.root / "evidence" / "_events").rglob("*.json"))

        with self.assertRaisesRegex(ValueError, "not contiguous"):
            self.vault.append_event("audit-entry", actor="process:test", data={"n": 3})

        after = list((self.root / "evidence" / "_events").rglob("*.json"))
        self.assertEqual(after, before)
        self.assertEqual(read_event(after[0])["id"], second["id"])

    def test_verified_filtered_read_rejects_global_chain_gap(self) -> None:
        first = self.vault.append_event("audit-entry", actor="process:test", data={"n": 1})
        self.vault.append_event("audit-entry", actor="process:test", data={"n": 2})
        first_path = next(
            (self.root / "evidence" / "_events").rglob(f"{first['id']}.json")
        )
        first_path.unlink()
        with self.assertRaisesRegex(ValueError, "not contiguous"):
            list(iter_events(self.vault, event_types={"audit-entry"}, verify=True))

    def test_verified_category_filter_validates_cross_category_global_chain(self) -> None:
        self.vault.append_event("audit-entry", actor="process:test", category="first", data={"n": 1})
        wanted = self.vault.append_event("audit-entry", actor="process:test", category="second", data={"n": 2})
        selected = list(iter_events(self.vault, category="second", verify=True))
        self.assertEqual([event["id"] for event in selected], [wanted["id"]])

    def test_valid_integrity_broken_previous_chain_blocks_append(self) -> None:
        first = self.vault.append_event("audit-entry", actor="process:test", data={"n": 1})
        second = self.vault.append_event("audit-entry", actor="process:test", data={"n": 2})
        second_path = next(
            (self.root / "evidence" / "_events").rglob(f"{second['id']}.json")
        )
        forged = dict(second)
        forged["previous_event"] = new_id()
        forged = seal_record(forged)
        second_path.chmod(0o600)
        durable_write_json(second_path, forged, mode=0o400)
        self.assertNotEqual(forged["previous_event"], first["id"])

        before = set((self.root / "evidence" / "_events").rglob("*.json"))
        with self.assertRaisesRegex(ValueError, "previous_event chain is broken"):
            self.vault.append_event("audit-entry", actor="process:test", data={"n": 3})
        self.assertEqual(set((self.root / "evidence" / "_events").rglob("*.json")), before)

    def test_corrupt_existing_event_blocks_append_without_publication(self) -> None:
        event = self.vault.append_event("audit-entry", actor="process:test", data={"n": 1})
        corrupt = (
            self.root / "evidence" / "_events" / "forged" / f"{new_id()}.json"
        )
        corrupt.parent.mkdir()
        corrupt.write_bytes(b'{"schema":"0.2"')

        before = set((self.root / "evidence" / "_events").rglob("*.json"))
        with self.assertRaisesRegex(ValueError, "invalid event JSON"):
            self.vault.append_event("audit-entry", actor="process:test", data={"n": 2})
        self.assertEqual(set((self.root / "evidence" / "_events").rglob("*.json")), before)
        self.assertIn(next(path for path in before if path.name == f"{event['id']}.json"), before)

    def test_duplicate_event_id_blocks_append(self) -> None:
        event = self.vault.append_event("audit-entry", actor="process:test", data={"n": 1})
        duplicate_path = (
            self.root
            / "evidence"
            / "_events"
            / "forged"
            / "2026"
            / "01"
            / "01"
            / f"{new_id()}.json"
        )
        durable_write_json(duplicate_path, event, exclusive=True, mode=0o400)

        before = set((self.root / "evidence" / "_events").rglob("*.json"))
        with self.assertRaisesRegex(ValueError, "duplicate Event ID"):
            self.vault.append_event("audit-entry", actor="process:test", data={"n": 2})
        self.assertEqual(set((self.root / "evidence" / "_events").rglob("*.json")), before)

    def test_event_reader_rejects_fifo_and_oversized_sparse_file(self) -> None:
        events_root = self.root / "evidence" / "_events"
        fifo = events_root / "unsafe.json"
        if not hasattr(os, "mkfifo"):
            self.skipTest("FIFO creation is unavailable")
        os.mkfifo(fifo)
        with self.assertRaisesRegex(ValueError, "regular non-symlink"):
            read_event(fifo)
        fifo.unlink()

        oversized = events_root / "oversized.json"
        with oversized.open("wb") as stream:
            stream.truncate(DURABLE_RECORD_MAX_BYTES + 1)
        with self.assertRaisesRegex(ValueError, "maximum size"):
            read_event(oversized)

    def test_event_tree_symlinks_are_rejected_and_never_written_through(self) -> None:
        external = Path(self.temporary.name) / "external"
        external.mkdir()
        category = self.root / "evidence" / "_events" / "linked"
        category.symlink_to(external, target_is_directory=True)

        with self.assertRaisesRegex(ValueError, "unsafe directory"):
            list(iter_event_paths(self.vault))
        with self.assertRaises(ValueError):
            self.vault.append_event(
                "audit-entry", actor="process:test", category="linked", data={"ok": True}
            )
        self.assertEqual(list(external.iterdir()), [])

        alias = Path(self.temporary.name) / "vault-alias"
        alias.symlink_to(self.root, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, "real directories"):
            list(iter_event_paths(alias))


if __name__ == "__main__":
    unittest.main()
