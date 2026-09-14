from __future__ import annotations

import base64
from dataclasses import replace
import hashlib
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from integrations.hermes.installer import journal_io, journal_syscalls, transaction
from integrations.hermes.installer.models import Identity, InstallerError, Journal, JournalDurabilityUncertain
from integrations.hermes.installer.source import OWNED_FILES


def _identity(raw: bytes = b"old", *, kind: str = "file", mode: int = 0o600) -> Identity:
    return Identity(1, len(raw) + 10, os.geteuid(), kind, mode, len(raw), 4, hashlib.sha256(raw).hexdigest())


def _journal(home: Path, phase: str = "prepared") -> Journal:
    raw = b"old"
    marker = b"marker"
    tree = {name: _identity(name.encode()) for name in OWNED_FILES}
    tree[".lifedb-owner.json"] = _identity(marker)
    return Journal(
        home, "disable", phase, None, None,
        old_root_exists=True,
        config_exists=True,
        old_config_b64=base64.b64encode(raw).decode("ascii"),
        old_config_mode=0o600,
        old_marker_b64=base64.b64encode(marker).decode("ascii"),
        old_marker_mode=0o600,
        old_marker_mtime_ns=4,
        config_identity=_identity(raw),
        old_config_mtime_ns=4,
        live_identity=_identity(b"live", kind="directory", mode=0o700),
        lock_identity=_identity(b"lock"),
        binary_identity=_identity(b"binary", mode=0o700),
        old_tree_manifest=tree,
        old_marker_exists=True,
        old_marker_identity=_identity(marker),
        old_live_identity=_identity(b"live", kind="directory", mode=0o700),
    )


class Task14JournalStoreTests(unittest.TestCase):
    def test_create_update_read_clear_is_strict_cas(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            first = transaction.write_journal(home, _journal(home))
            second = transaction.write_journal(home, replace(_journal(home), phase="prepared"), expected=first)
            self.assertNotEqual(first, second)
            self.assertEqual(transaction.read_journal(home).phase, "prepared")
            transaction.clear_journal(home, second)
            self.assertIsNone(transaction.read_journal(home))

    def test_create_with_active_record_rejects_missing_expected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            transaction.write_journal(home, _journal(home))
            with self.assertRaises(InstallerError):
                transaction.write_journal(home, _journal(home))

    def test_stale_expected_identity_rejects_without_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            expected = transaction.write_journal(home, _journal(home))
            stale = _identity(b"stale")
            before = (home / transaction.JOURNAL_NAME).read_bytes()
            with self.assertRaises(InstallerError):
                transaction.write_journal(home, _journal(home), expected=stale)
            self.assertEqual((home / transaction.JOURNAL_NAME).read_bytes(), before)
            self.assertEqual(transaction.read_journal(home).journal_identity, expected)

    def test_update_then_clear_does_not_recreate_a_third_carrier(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            token = transaction.write_journal(home, _journal(home))
            token = transaction.write_journal(home, replace(_journal(home), phase="prepared"), expected=token)
            transaction.clear_journal(home, token)
            store = home / journal_io.STORE_NAME
            self.assertEqual(sorted(item.name for item in store.iterdir()), ["data-0", "data-1", "pointer-0", "pointer-1"])
            self.assertFalse((home / transaction.JOURNAL_NAME).exists())

    def test_missing_and_duplicate_pointer_envelopes_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            transaction.write_journal(home, _journal(home))
            path = home / transaction.JOURNAL_NAME
            raw = path.read_bytes()
            path.write_bytes(raw.replace(b'"schema":1', b'"schema":1,"schema":1'))
            with self.assertRaises(InstallerError):
                transaction.read_journal(home)

    def test_pointer_trailing_bytes_are_not_canonical(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            transaction.write_journal(home, _journal(home))
            path = home / transaction.JOURNAL_NAME
            path.write_bytes(path.read_bytes() + b"\n")
            path.chmod(0o600)
            with self.assertRaises(InstallerError):
                transaction.read_journal(home)

    def test_store_rejects_extra_and_nonregular_entries(self) -> None:
        for kind in ("extra", "symlink", "fifo", "socket"):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as directory:
                home = Path(directory)
                transaction.write_journal(home, _journal(home))
                path = home / journal_io.STORE_NAME / kind
                if kind == "extra":
                    path.write_bytes(b"x")
                elif kind == "symlink":
                    path.symlink_to(home)
                elif kind == "fifo":
                    os.mkfifo(path)
                else:
                    import socket
                    sock = socket.socket(socket.AF_UNIX)
                    try:
                        sock.bind(str(path))
                        with self.assertRaises(InstallerError):
                            transaction.read_journal(home)
                    finally:
                        sock.close()
                    continue
                with self.assertRaises(InstallerError):
                    transaction.read_journal(home)

    def test_read_missing_state_is_mutation_free(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            self.assertIsNone(transaction.read_journal(home))
            self.assertEqual(list(home.iterdir()), [])

    def test_non_linux_create_does_not_create_store(self) -> None:
        with tempfile.TemporaryDirectory() as directory, patch.object(journal_io.sys, "platform", "darwin"):
            home = Path(directory)
            with self.assertRaises(InstallerError):
                transaction.write_journal(home, _journal(home))
            self.assertEqual(list(home.iterdir()), [])

    def test_unsupported_rename_fails_before_publication(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            with patch.object(journal_io, "_renameat2", side_effect=OSError(38, "not supported")):
                with self.assertRaises(InstallerError):
                    transaction.write_journal(home, _journal(home))
            self.assertFalse((home / transaction.JOURNAL_NAME).exists())

    def test_public_replacement_before_publish_is_preserved(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            path = home / transaction.JOURNAL_NAME
            original = journal_io._renameat2

            def replace_public(source: Path, target: Path, flags: int) -> None:
                if target != path:
                    original(source, target, flags)
                    return
                target.write_bytes(b"HOSTILE")
                target.chmod(0o600)
                raise OSError(17, "exists")

            with patch.object(journal_io, "_renameat2", side_effect=replace_public):
                with self.assertRaises(InstallerError):
                    transaction.write_journal(home, _journal(home))
            self.assertEqual(path.read_bytes(), b"HOSTILE")

    def test_clear_public_replacement_after_move_is_preserved(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            token = transaction.write_journal(home, _journal(home))
            path = home / transaction.JOURNAL_NAME

            def replace_after_move(_: Path) -> None:
                path.write_bytes(b"HOSTILE")
                path.chmod(0o600)

            with patch.object(journal_io, "_after_atomic_move", side_effect=replace_after_move):
                with self.assertRaises(InstallerError):
                    transaction.clear_journal(home, token)
            self.assertEqual(path.read_bytes(), b"HOSTILE")

    def test_fsync_uncertainty_reports_public_or_moved_pointer_identity(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            token = transaction.write_journal(home, _journal(home))
            with patch.object(journal_io, "fsync_path", side_effect=OSError("fsync")):
                with self.assertRaises(JournalDurabilityUncertain) as raised:
                    transaction.write_journal(home, _journal(home), expected=token)
            self.assertEqual(raised.exception.identity, journal_io._read_identity(home / transaction.JOURNAL_NAME))

    def test_clear_fsync_uncertainty_reports_the_moved_carrier(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            token = transaction.write_journal(home, _journal(home))
            with patch.object(journal_io, "fsync_path", side_effect=OSError("clear fsync")):
                with self.assertRaises(JournalDurabilityUncertain) as raised:
                    transaction.clear_journal(home, token)
            self.assertFalse((home / transaction.JOURNAL_NAME).exists())
            identities = [journal_io._read_identity(home / journal_io.STORE_NAME / name) for name in journal_io.CARRIERS]
            self.assertIn(raised.exception.identity, identities)

    def test_no_unlink_is_used_by_journal_store(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            token = transaction.write_journal(home, _journal(home))
            with patch.object(Path, "unlink", side_effect=AssertionError("journal store must not unlink")):
                transaction.clear_journal(home, token)

    def test_more_than_one_hundred_twenty_mixed_cycles_keep_fixed_paths(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            token: Identity | None = None
            for cycle in range(150):
                created = transaction.write_journal(home, replace(_journal(home), phase="prepared"), expected=token)
                token = transaction.write_journal(home, replace(_journal(home), phase="prepared"), expected=created)
                transaction.clear_journal(home, token)
                token = None
            self.assertEqual(len(list(home.iterdir())), 1)
            self.assertEqual(len(list((home / journal_io.STORE_NAME).iterdir())), 4)


if __name__ == "__main__":
    unittest.main()
