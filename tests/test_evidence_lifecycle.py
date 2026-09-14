from __future__ import annotations

import json
import os
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest import mock

from lifedb.evidence import iter_capture_paths, read_capture, read_event, verify_integrity
from lifedb.ids import new_id
from lifedb.storage import durable_write_json
from lifedb.vault import ExternalIDConflictError, Vault


class EvidenceLifecycleTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name) / "vault"
        self.vault = Vault(self.root)
        self.vault.init()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_new_capture_is_v02_sealed_and_verified(self) -> None:
        record = self.vault.ingest(b"durable evidence", source_kind="test")

        self.assertEqual(record["schema"], "0.2")
        self.assertEqual(record["record_type"], "capture")
        self.assertTrue(verify_integrity(record))
        self.assertTrue(self.vault.index_dirty_path.exists())
        self.assertEqual(self.vault.load_evidence(record["id"]), record)

        path = self.vault.evidence_path(record["id"])
        assert path is not None
        changed = json.loads(path.read_text(encoding="utf-8"))
        changed["content"]["filename"] = "tampered"
        path.chmod(0o600)
        path.write_text(json.dumps(changed), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "integrity verification failed"):
            self.vault.load_evidence(record["id"])

    def test_v01_capture_remains_readable(self) -> None:
        evidence_id = new_id()
        path = self.root / "evidence" / "legacy" / "2025" / "01" / "02" / f"{evidence_id}.json"
        legacy = {"schema": "0.1", "id": evidence_id, "sealed": True, "legacy": "kept"}
        durable_write_json(path, legacy, exclusive=True)

        self.assertEqual(read_capture(path), legacy)
        self.assertEqual(self.vault.load_evidence(evidence_id), legacy)

    def test_reference_only_requires_uri_and_never_stores_object(self) -> None:
        with self.assertRaisesRegex(ValueError, "requires source_uri"):
            self.vault.ingest(b"remote", retention="reference-only")

        record = self.vault.ingest(
            b"remote",
            source_kind="web",
            source_uri="https://example.invalid/item",
            retention="reference-only",
        )
        self.assertEqual(record["payload"]["state"], "external")
        self.assertNotIn("object", record["payload"])
        self.assertFalse(self.vault.object_path(record["content"]["sha256"]).exists())

    def test_external_id_is_idempotent_under_thread_lock(self) -> None:
        def ingest(_: int) -> dict:
            return self.vault.ingest(
                b"same external item",
                source_kind="collector",
                external_id="event-42",
            )

        with ThreadPoolExecutor(max_workers=4) as executor:
            records = list(executor.map(ingest, range(8)))
        self.assertEqual(len({record["id"] for record in records}), 1)
        self.assertEqual(len(list(self.root.glob("evidence/collector/*/*/*/*.json"))), 1)

        with self.assertRaisesRegex(ValueError, "different content"):
            self.vault.ingest(
                b"changed external item",
                source_kind="collector",
                external_id="event-42",
            )

    def test_external_id_conflict_raises_typed_valueerror_subclass(self) -> None:
        self.assertTrue(issubclass(ExternalIDConflictError, ValueError))

        first = self.vault.ingest(
            b"typed conflict probe",
            source_kind="collector",
            external_id="typed-event-7",
        )
        replay = self.vault.ingest(
            b"typed conflict probe",
            source_kind="collector",
            external_id="typed-event-7",
        )
        self.assertEqual(replay["id"], first["id"])
        self.assertEqual(
            len(list(self.root.glob("evidence/collector/*/*/*/*.json"))), 1
        )

        captures_before = len(list(self.root.glob("evidence/collector/*/*/*/*.json")))
        objects_before = len(list((self.root / "objects").rglob("*")))
        with self.assertRaises(ExternalIDConflictError) as raised:
            self.vault.ingest(
                b"typed conflict probe changed",
                source_kind="collector",
                external_id="typed-event-7",
            )
        self.assertIsInstance(raised.exception, ValueError)
        self.assertNotIn("typed conflict probe changed", str(raised.exception))
        self.assertEqual(
            len(list(self.root.glob("evidence/collector/*/*/*/*.json"))),
            captures_before,
        )
        self.assertEqual(
            len(list((self.root / "objects").rglob("*"))), objects_before
        )

    def test_uuid_lookup_and_object_digest_are_strict(self) -> None:
        for invalid in ("*", "../escape", "0" * 64, new_id().upper()):
            with self.assertRaises(ValueError):
                self.vault.evidence_path(invalid)
        for digest in ("../" + "0" * 61, "A" * 64, "0" * 63, "0" * 65):
            with self.assertRaises(ValueError):
                self.vault.object_path(digest)

        reserved = self.vault.ingest(b"visible", source_kind="_events")
        self.assertIsNotNone(self.vault.evidence_path(reserved["id"]))

    def test_append_only_events_fold_into_effective_evidence(self) -> None:
        capture = self.vault.ingest(b"payload", source_kind="test")
        representation = {
            "role": "ocr",
            "object": "sha256:" + "1" * 64,
            "media_type": "text/plain",
            "created_at": "2026-01-01T00:00:00Z",
            "producer": {"by": "process:test", "version": "1"},
        }
        added = self.vault.append_event(
            "representation-added",
            actor="user:test",
            target=capture["id"],
            data={"representation": representation, "extension": {"free": True}},
            recorded_at="2026-01-01T00:00:01Z",
        )
        self.vault.append_event(
            "payload-evicted",
            actor="process:retention",
            target=capture["id"],
            data={"reason": "policy"},
            recorded_at="2026-01-01T00:00:02Z",
        )
        self.vault.append_event(
            "payload-restored",
            actor="user:test",
            target=capture["id"],
            data={},
            recorded_at="2026-01-01T00:00:03Z",
        )
        self.vault.append_event(
            "payload-redacted",
            actor="user:test",
            target=capture["id"],
            data={"reason": "owner request"},
            recorded_at="2026-01-01T00:00:04Z",
        )

        event_paths = list((self.root / "evidence" / "_events").rglob(f"{added['id']}.json"))
        self.assertEqual(len(event_paths), 1)
        self.assertIn("representation", event_paths[0].parts)
        self.assertEqual(read_event(event_paths[0]), added)
        self.assertTrue(verify_integrity(added))
        lifecycle = self.vault.events_for(capture["id"])
        self.assertEqual([event["sequence"] for event in lifecycle], [1, 2, 3, 4])
        self.assertIsNone(lifecycle[0]["previous_event"])
        self.assertEqual(
            [event["previous_event"] for event in lifecycle[1:]],
            [event["id"] for event in lifecycle[:-1]],
        )

        effective = self.vault.effective_evidence(capture["id"])
        assert effective is not None
        self.assertEqual(effective["representations"], [representation])
        self.assertEqual(effective["payload"]["state"], "redacted")
        self.assertEqual(effective["payload"]["redaction_reason"], "owner request")
        self.assertNotIn("object", effective["payload"])

        # The sealed capture itself remains unchanged.
        unchanged = self.vault.load_evidence(capture["id"])
        assert unchanged is not None
        self.assertEqual(unchanged["payload"]["state"], "present")

    def test_concurrent_events_receive_one_global_chain(self) -> None:
        capture = self.vault.ingest(b"event target", source_kind="test")

        def append(index: int) -> dict:
            return self.vault.append_event(
                "audit-entry",
                actor="process:test",
                target=capture["id"],
                data={"index": index},
            )

        with ThreadPoolExecutor(max_workers=4) as executor:
            returned = list(executor.map(append, range(8)))
        ordered = sorted(returned, key=lambda event: event["sequence"])
        self.assertEqual([event["sequence"] for event in ordered], list(range(1, 9)))
        self.assertIsNone(ordered[0]["previous_event"])
        self.assertEqual(
            [event["previous_event"] for event in ordered[1:]],
            [event["id"] for event in ordered[:-1]],
        )

    def test_exclusive_json_failure_never_exposes_final_fragment(self) -> None:
        destination = self.root / "evidence" / "failed.json"
        with mock.patch("lifedb.storage.os.link", side_effect=OSError("publish failed")):
            with self.assertRaisesRegex(OSError, "publish failed"):
                durable_write_json(destination, {"large": "x" * 10000}, exclusive=True)
        self.assertFalse(destination.exists())
        self.assertEqual(list(destination.parent.glob(f".{destination.name}.tmp-*")), [])

        durable_write_json(destination, {"complete": True}, exclusive=True)
        with self.assertRaises(FileExistsError):
            durable_write_json(destination, {"partial": True}, exclusive=True)
        self.assertEqual(json.loads(destination.read_text(encoding="utf-8")), {"complete": True})

    def test_capture_walker_rejects_root_and_nested_symlinks(self) -> None:
        capture = self.vault.ingest(b"inside", source_kind="test")
        expected = self.vault.evidence_path(capture["id"])
        assert expected is not None

        external = Path(self.temporary.name) / "external-captures"
        external.mkdir()
        external_copy = external / f"{new_id()}.json"
        external_copy.write_bytes(expected.read_bytes())
        (self.root / "evidence" / "linked").symlink_to(
            external, target_is_directory=True
        )
        with self.assertRaisesRegex(ValueError, "unsafe directory"):
            list(iter_capture_paths(self.vault))
        with self.assertRaisesRegex(ValueError, "unsafe directory"):
            self.vault.ingest(
                b"must not continue",
                source_kind="collector",
                external_id="external-unsafe-tree",
            )

        alias = Path(self.temporary.name) / "vault-alias"
        alias.symlink_to(self.root, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, "real directories"):
            list(iter_capture_paths(alias))

        fake_root = Path(self.temporary.name) / "fake-vault"
        fake_root.mkdir()
        (fake_root / "evidence").symlink_to(external, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, "real directories"):
            list(iter_capture_paths(fake_root))

    def test_capture_walker_rejects_json_special_file(self) -> None:
        if not hasattr(os, "mkfifo"):
            self.skipTest("FIFO creation is unavailable")
        fifo = self.root / "evidence" / "unsafe.json"
        os.mkfifo(fifo)
        with self.assertRaisesRegex(ValueError, "regular non-symlink"):
            list(iter_capture_paths(self.vault))


if __name__ == "__main__":
    unittest.main()
