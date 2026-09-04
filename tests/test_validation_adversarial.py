from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

from lifedb.ids import new_id
from lifedb.storage import file_lock
from lifedb.validation import validate_vault
from lifedb.vault import Vault


class ValidationAdversarialTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name) / "vault"
        Vault(self.root).init()

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_duplicate_and_oversized_json_fail_without_echoing_input(self) -> None:
        metadata = self.root / "vault.json"
        metadata.chmod(0o600)
        metadata.write_bytes(b'{"schema":"0.2","schema":"0.2","secret":"do-not-echo"}')
        report = validate_vault(self.root)
        self.assertFalse(report.valid)
        self.assertNotIn("do-not-echo", " ".join(report.errors))

        metadata.write_bytes(b"{" + b"x" * (16 * 1024 * 1024 + 1) + b"}")
        report = validate_vault(self.root)
        self.assertFalse(report.valid)

    def test_object_fifo_and_malformed_names_are_rejected_without_opening_fifo(self) -> None:
        leaf = self.root / "objects" / "sha256" / "aa" / "bb"
        leaf.mkdir(parents=True)
        os.mkfifo(leaf / ("f" * 64))
        (leaf / "not-a-digest").write_bytes(b"bytes")
        report = validate_vault(self.root)
        self.assertFalse(report.valid)
        self.assertTrue(any("non-regular" in error for error in report.errors))
        self.assertTrue(any("canonical SHA-256" in error for error in report.errors))

    def test_object_symlinks_and_policy_corruption_fail_closed(self) -> None:
        outside = Path(self.tmp.name) / "outside"
        outside.mkdir()
        os.symlink(outside, self.root / "objects" / "sha256" / "aa")
        os.symlink(outside, self.root / "objects" / "sha256" / "bb")
        leaf = self.root / "objects" / "sha256" / "cc" / "dd"
        leaf.mkdir(parents=True)
        os.symlink(outside / "missing", leaf / ("e" * 64))
        policy = self.root / "policies" / "retention.json"
        policy.chmod(0o600)
        policy.write_bytes(b'{"schema":"0.2","schema":"0.2"}')
        report = validate_vault(self.root)
        self.assertFalse(report.valid)
        self.assertTrue(any("objects" in error for error in report.errors))
        self.assertTrue(any("retention.json" in error for error in report.errors))

    def test_claim_datetime_and_numeric_values_are_strict(self) -> None:
        document_id = new_id()
        path = self.root / "canon" / "self" / "strict-claim.md"
        path.write_text(
            "---\n"
            "type: Note\n"
            "title: Strict claim\n"
            "status: stable\n"
            "x-lifedb:\n"
            "  schema: '0.2'\n"
            f"  id: {document_id}\n"
            "  kind: test\n"
            "  sensitivity: public\n"
            "  claims:\n"
            "    - id: " + new_id() + "\n"
            "      predicate: lifedb.value\n"
            f"      subject: {document_id}\n"
            "      object:\n"
            "        number: .nan\n"
            "      statement: Strict value\n"
            "      basis: declared\n"
            "      certainty: confirmed\n"
            "      state: active\n"
            "      observed_at: '2026-01-01 00:00:00+00:00'\n"
            "      valid: {}\n"
            "      evidence:\n"
            "        - id: " + new_id() + "\n"
            "          requires: record-only\n"
            "      sensitivity: public\n"
            "---\n\nstrict claim body\n",
            encoding="utf-8",
        )
        report = validate_vault(self.root)
        self.assertFalse(report.valid)
        self.assertTrue(any("observed_at" in error and "date-time" in error for error in report.errors))
        self.assertTrue(any("invalid number value" in error for error in report.errors))
        self.assertTrue(any(".valid" in error and "from and/or until" in error for error in report.errors))

    def test_public_representation_alias_of_restricted_object_is_invalid(self) -> None:
        vault = Vault(self.root)
        restricted = vault.ingest(
            b"validator restricted alias marker",
            source_kind="test",
            media_type="text/plain",
            sensitivity="restricted",
        )
        public = vault.ingest(
            b"public metadata",
            source_kind="test",
            media_type="application/octet-stream",
            sensitivity="public",
        )
        vault.append_event(
            "representation-added",
            actor="extractor:test",
            target=public["id"],
            data={
                "role": "derived-text",
                "object": restricted["payload"]["object"],
                "media_type": "text/plain",
                "created_at": "2026-09-01T00:00:00Z",
                "producer": {"by": "extractor:test", "version": "1"},
            },
            sensitivity="public",
        )
        report = validate_vault(self.root)
        self.assertFalse(report.valid)
        self.assertTrue(any("referenced below its effective sensitivity" in error for error in report.errors))

    def test_validation_is_reentrant_under_the_writer_lock(self) -> None:
        lock_path = self.root / "runtime" / "locks" / "writer.lock"
        with file_lock(lock_path, boundary=self.root):
            report = validate_vault(self.root)
        self.assertIsNotNone(report)


if __name__ == "__main__":
    unittest.main()
