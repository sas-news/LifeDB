from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from dataclasses import replace
from unittest.mock import patch

from integrations.hermes.installer import journal_io, transaction
from integrations.hermes.installer.models import Identity, InstallerError, Journal
from integrations.hermes.installer.operations import read_config
from integrations.hermes.tests.test_task14_journal_store import _journal


def _identity(kind: str = "file") -> Identity:
    return Identity(1, 2, os.geteuid(), kind, 0o600, 3, 4, "a" * 64)


class Task14AJournalTests(unittest.TestCase):
    def test_write_rejects_config_mtime_mismatch_before_temp_creation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            config = home / "config.yaml"
            config.write_bytes(b"plugins: {}\n")
            config.chmod(0o600)
            preimage = read_config(home, create=True)
            journal = Journal(home, "install", "prepared", None, None, False, True, base64.b64encode(preimage.raw).decode(), preimage.mode, "", preimage.identity, old_config_mtime_ns=preimage.mtime_ns + 1)
            with patch.object(journal_io, "_write_file", side_effect=AssertionError("slot publication must not run")):
                with self.assertRaises(InstallerError):
                    transaction.write_journal(home, journal)

    def test_write_rejects_phase_desired_hash_without_identity(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            config = home / "config.yaml"
            config.write_bytes(b"plugins: {}\n")
            config.chmod(0o600)
            preimage = read_config(home, create=True)
            journal = Journal(home, "install", "config_intent", None, None, False, True, base64.b64encode(preimage.raw).decode(), preimage.mode, "", preimage.identity, desired_config_hash="a" * 64, desired_marker_hash="b" * 64)
            with patch.object(journal_io, "_write_file", side_effect=AssertionError("slot publication must not run")):
                with self.assertRaises(InstallerError):
                    transaction.write_journal(home, journal)

    def test_write_rejects_partial_old_tree_before_temp_creation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            journal = Journal(home, "install", "prepared", None, None, True, old_tree_manifest={"plugin.yaml": _identity()})
            with patch.object(journal_io, "_write_file", side_effect=AssertionError("slot publication must not run")):
                with self.assertRaises(InstallerError):
                    transaction.write_journal(home, journal)

    def test_journal_manifest_is_immutable_and_snapshots_are_typed(self) -> None:
        journal = Journal(
            Path("/tmp/hermes"), "install", "prepared", None, None,
            config_exists=True, config_identity=_identity(),
            old_tree_manifest={"plugin.yaml": _identity()},
        )
        with self.assertRaises(TypeError):
            journal.old_tree_manifest["hooks.py"] = _identity()

    def test_journal_rejects_invalid_identity_ranges_and_hash(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            data = {
                "schema": 1, "home": str(home), "operation": "install", "phase": "prepared",
                "staging": None, "quarantine": None, "old_root_exists": False,
                "config_exists": False, "old_config_b64": "", "old_config_mode": 0o600,
                "old_config_mtime_ns": 0, "old_marker_b64": "", "config_identity": {
                    "device": 0, "inode": 2, "owner_uid": os.geteuid(), "kind": "file",
                    "mode": 0o600, "size": 0, "mtime_ns": 0, "sha256": "not-a-sha",
                }, "staging_identity": None, "quarantine_identity": None,
                "live_identity": None, "lock_identity": None, "old_tree_manifest": {},
                "desired_config_hash": "", "desired_marker_hash": "",
                "desired_config_identity": None, "desired_marker_identity": None,
                "cleanup_manifest": {}, "cleanup_deleted": [], "binary_identity": None,
            }
            path = home / transaction.JOURNAL_NAME
            path.write_text(json.dumps(data), encoding="utf-8")
            path.chmod(0o600)
            with self.assertRaises(InstallerError):
                transaction.read_journal(home)

    def test_update_path_swap_preserves_hostile_replacement(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            journal = _journal(home)
            token = transaction.write_journal(home, journal)
            hostile = home / "hostile-copy"
            swapped = False
            original_exchange = journal_io._renameat2

            def swap_before_exchange(source: Path, target: Path, flags: int) -> None:
                nonlocal swapped
                if not swapped:
                    target.replace(hostile)
                    target.write_bytes(b"HOSTILE")
                    target.chmod(0o600)
                    swapped = True
                original_exchange(source, target, flags)

            with patch.object(journal_io, "_renameat2", side_effect=swap_before_exchange):
                with self.assertRaises(InstallerError):
                    transaction.write_journal(home, journal, expected=token)
            self.assertEqual((home / transaction.JOURNAL_NAME).read_bytes(), b"HOSTILE")

    def test_create_path_swap_preserves_hostile_replacement(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            path = home / transaction.JOURNAL_NAME
            swapped = False
            original_exchange = journal_io._renameat2

            def create_after_swap(source: Path, target: Path, flags: int) -> None:
                nonlocal swapped
                if not swapped:
                    target.write_bytes(b"HOSTILE")
                    target.chmod(0o600)
                    swapped = True
                original_exchange(source, target, flags)

            with patch.object(journal_io, "_renameat2", side_effect=create_after_swap):
                transaction.write_journal(home, _journal(home))
            self.assertEqual(transaction.read_journal(home).phase, "prepared")

    def test_clear_path_swap_preserves_hostile_replacement(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            journal = _journal(home)
            token = transaction.write_journal(home, journal)
            path = home / transaction.JOURNAL_NAME
            original_exchange = journal_io._renameat2
            swapped = False

            def swap_before_clear(source: Path, target: Path, flags: int) -> None:
                nonlocal swapped
                if not swapped:
                    path.replace(home / "old-journal")
                    path.write_bytes(b"HOSTILE")
                    path.chmod(0o600)
                    swapped = True
                original_exchange(source, target, flags)

            with patch.object(journal_io, "_renameat2", side_effect=swap_before_clear):
                with self.assertRaises(InstallerError):
                    transaction.clear_journal(home, token)
            self.assertEqual(path.read_bytes(), b"HOSTILE")

    def test_journal_rejects_canonical_trailing_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            path = home / transaction.JOURNAL_NAME
            transaction.write_journal(home, _journal(home))
            path.write_bytes(path.read_bytes() + b"\n")
            path.chmod(0o600)
            with self.assertRaises(InstallerError):
                transaction.read_journal(home)

    def test_oversized_journal_is_rejected_before_publication(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            raw = b"x" * 1_048_577
            identity = Identity(1, 2, os.geteuid(), "file", 0o600, len(raw), 4, hashlib.sha256(raw).hexdigest())
            journal = Journal(home, "install", "prepared", None, None, False, True, base64.b64encode(raw).decode(), 0o600, "", identity)
            with self.assertRaises(InstallerError):
                transaction.write_journal(home, journal)
            self.assertFalse((home / transaction.JOURNAL_NAME).exists())

    def test_maximum_config_fits_bounded_journal(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            config = home / "config.yaml"
            config.write_bytes(b"plugins: {}\n#" + b"x" * (1_048_576 - len(b"plugins: {}\n#")))
            config.chmod(0o600)
            preimage = read_config(home, create=True)
            journal = replace(_journal(home), old_config_b64=base64.b64encode(preimage.raw).decode(), old_config_mode=preimage.mode, config_identity=preimage.identity, old_config_mtime_ns=preimage.mtime_ns)
            token = transaction.write_journal(home, journal)
            self.assertEqual(transaction.read_journal(home).journal_identity, token)

    def test_write_rejects_cross_field_preimage_and_empty_intent(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            journal = Journal(home, "install", "published", None, None, False, True, base64.b64encode(b"abc").decode(), 0o600, "", _identity())
            with self.assertRaises(InstallerError):
                transaction.write_journal(home, journal)
            self.assertFalse((home / transaction.JOURNAL_NAME).exists())

    def test_clear_preserves_replacement_before_final_unlink(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            token = transaction.write_journal(home, _journal(home))
            path = home / transaction.JOURNAL_NAME

            def replace_before_unlink(candidate: Path) -> None:
                path.replace(home / "old-journal")
                path.write_bytes(b"HOSTILE")
                path.chmod(0o600)

            with patch.object(journal_io, "_before_atomic_move", side_effect=replace_before_unlink):
                with self.assertRaises(InstallerError):
                    transaction.clear_journal(home, token)
            self.assertEqual(path.read_bytes(), b"HOSTILE")

    def test_clear_preserves_replacement_after_atomic_move(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            token = transaction.write_journal(home, _journal(home))
            path = home / transaction.JOURNAL_NAME

            def replace_after_move(target: Path) -> None:
                target.write_bytes(b"HOSTILE")
                target.chmod(0o600)

            with patch.object(journal_io, "_after_atomic_move", side_effect=replace_after_move):
                with self.assertRaises(InstallerError):
                    transaction.clear_journal(home, token)
            self.assertEqual(path.read_bytes(), b"HOSTILE")

    def test_clear_fails_closed_without_renameat2(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            token = transaction.write_journal(home, _journal(home))
            path = home / transaction.JOURNAL_NAME
            original = path.read_bytes()
            with patch.object(journal_io, "_renameat2", side_effect=OSError(38, "not supported")):
                with self.assertRaises(InstallerError):
                    transaction.clear_journal(home, token)
            self.assertEqual(path.read_bytes(), original)
            self.assertEqual(len(list(home.glob(".lifedb-clear-*"))), 0)

    def test_clear_fsync_failure_retains_private_expected_inode(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            token = transaction.write_journal(home, _journal(home))
            with patch.object(journal_io, "fsync_path", side_effect=OSError("fsync unavailable")):
                with self.assertRaises(InstallerError):
                    transaction.clear_journal(home, token)
            self.assertIsNone(transaction.read_journal(home))

    def test_fsync_uncertainty_retains_readable_published_record(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            journal = _journal(home)
            token = transaction.write_journal(home, journal)
            with patch.object(journal_io, "fsync_path", side_effect=OSError("fsync unavailable")):
                with self.assertRaises(InstallerError) as raised:
                    transaction.write_journal(home, journal, expected=token)
            self.assertEqual(type(raised.exception).__name__, "JournalDurabilityUncertain")
            self.assertEqual(transaction.read_journal(home).phase, journal.phase)
            self.assertEqual(raised.exception.identity, transaction.read_journal(home).journal_identity)


if __name__ == "__main__":
    unittest.main()
