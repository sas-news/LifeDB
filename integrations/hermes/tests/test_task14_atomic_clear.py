from __future__ import annotations

import os
from pathlib import Path
import socket
import tempfile
import unittest
from unittest.mock import patch

from integrations.hermes.installer import journal_io, transaction
from integrations.hermes.installer.models import Identity, InstallerError, JournalDurabilityUncertain
from integrations.hermes.tests.test_task14_journal_store import _journal as store_journal


class AtomicClearTests(unittest.TestCase):
    def _journal(self, home: Path) -> tuple[Path, Identity]:
        identity = transaction.write_journal(home, store_journal(home))
        return home / transaction.JOURNAL_NAME, identity

    def test_fifo_refused_without_blocking(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            path = home / transaction.JOURNAL_NAME
            os.mkfifo(path, 0o600)
            with self.assertRaises(InstallerError):
                transaction.clear_journal(home, _identity())

    def test_dangling_symlink_is_not_absent(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            path = home / transaction.JOURNAL_NAME
            path.symlink_to(home / "missing")
            with self.assertRaises(InstallerError):
                transaction.clear_journal(home, _identity())
            self.assertTrue(path.is_symlink())

    def test_directory_and_socket_are_refused(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            path = home / transaction.JOURNAL_NAME
            path.mkdir(mode=0o700)
            with self.assertRaises(InstallerError):
                transaction.clear_journal(home, _identity())
            path.rmdir()
            server = socket.socket(socket.AF_UNIX)
            try:
                server.bind(str(path))
                with self.assertRaises(InstallerError):
                    transaction.clear_journal(home, _identity())
            finally:
                server.close()

    def test_success_is_atomic_and_reuses_fixed_store(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            path, identity = self._journal(home)
            transaction.clear_journal(home, identity)
            self.assertFalse(_present(path))
            store = home / journal_io.STORE_NAME
            self.assertEqual(sorted(path.name for path in store.iterdir()), ["data-0", "data-1", "pointer-0", "pointer-1"])
            self.assertEqual(transaction.read_journal(home), None)

    def test_replacement_before_claim_is_preserved(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            path, identity = self._journal(home)

            def replace(_: Path) -> None:
                path.replace(home / "old")
                path.write_bytes(b"HOSTILE")
                path.chmod(0o600)

            with patch.object(journal_io, "_before_atomic_move", side_effect=replace):
                with self.assertRaises(InstallerError):
                    transaction.clear_journal(home, identity)
            self.assertEqual(path.read_bytes(), b"HOSTILE")

    def test_wrong_expected_identity_does_not_claim(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            path, _ = self._journal(home)
            with self.assertRaises(InstallerError):
                transaction.clear_journal(home, _identity())
            self.assertTrue(_present(path))

    def test_store_symlink_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            path = home / journal_io.STORE_NAME
            path.symlink_to(home)
            with self.assertRaises(InstallerError):
                transaction.write_journal(home, store_journal(home))

    def test_malformed_pointer_is_not_clean(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            identity = transaction.write_journal(home, store_journal(home))
            (home / transaction.JOURNAL_NAME).write_bytes(b"broken")
            with self.assertRaises(InstallerError):
                transaction.read_journal(home)
            self.assertTrue(_present(home / transaction.JOURNAL_NAME))
            self.assertIsNotNone(identity)

    def test_selected_slot_identity_mismatch_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            transaction.write_journal(home, store_journal(home))
            slot = home / journal_io.STORE_NAME / journal_io.SLOTS[0]
            slot.write_bytes(b"changed")
            slot.chmod(0o600)
            with self.assertRaises(InstallerError):
                transaction.read_journal(home)

    def test_fsync_failure_keeps_tombstone_and_reports_uncertainty(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            path, identity = self._journal(home)
            with patch.object(journal_io, "fsync_path", side_effect=OSError("uncertain")):
                with self.assertRaises(JournalDurabilityUncertain) as raised:
                    transaction.clear_journal(home, identity)
            self.assertEqual(raised.exception.identity, identity)
            self.assertFalse(_present(path))
            store = home / journal_io.STORE_NAME
            self.assertTrue(all(_present(store / name) for name in journal_io.CARRIERS))

    def test_unsupported_platform_fails_before_claim(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            path, identity = self._journal(home)
            with patch.object(journal_io.sys, "platform", "darwin"):
                with self.assertRaises(InstallerError):
                    transaction.clear_journal(home, identity)
            self.assertTrue(_present(path))

    def test_repeated_invocation_requires_current_identity(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            path, identity = self._journal(home)
            transaction.clear_journal(home, identity)
            with self.assertRaises(InstallerError):
                transaction.clear_journal(home, identity)

    def test_one_hundred_write_clear_cycles_keep_constant_paths(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            for _ in range(101):
                journal = store_journal(home)
                identity = transaction.write_journal(home, journal)
                self.assertIsNotNone(transaction.read_journal(home))
                transaction.clear_journal(home, identity)
            self.assertEqual(len(list(home.iterdir())), 1)
            self.assertEqual(len(list((home / journal_io.STORE_NAME).iterdir())), 4)


def _identity() -> Identity:
    return Identity(1, 2, os.geteuid(), "file", 0o600, 0, 0, "a" * 64)


def _present(path: Path) -> bool:
    try:
        path.lstat()
    except FileNotFoundError:
        return False
    return True


if __name__ == "__main__":
    unittest.main()
