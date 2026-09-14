from __future__ import annotations

import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from integrations.hermes.installer import journal_io, journal_syscalls, transaction
from integrations.hermes.installer.models import Identity, InstallerError, JournalDurabilityUncertain
from integrations.hermes.tests.test_task14_journal_store import _identity, _journal


class Task14JournalStoreEdgeTests(unittest.TestCase):
    def test_partial_private_bootstrap_is_completed_without_extra_names(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            store = home / journal_io.STORE_NAME
            store.mkdir(mode=0o700)
            for name in ("data-0", "data-1", "pointer-0"):
                descriptor = os.open(store / name, os.O_RDWR | os.O_CREAT | os.O_EXCL, 0o600)
                os.close(descriptor)
            transaction.write_journal(home, _journal(home))
            self.assertEqual(sorted(item.name for item in store.iterdir()), ["data-0", "data-1", "pointer-1"])
            self.assertTrue((home / transaction.JOURNAL_NAME).is_file())

    def test_selected_slot_path_swap_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            transaction.write_journal(home, _journal(home))
            selected = home / journal_io.STORE_NAME / journal_io.SLOTS[0]
            selected.replace(selected.with_name("selected-hostile"))
            selected.write_bytes(b"hostile")
            selected.chmod(0o600)
            with self.assertRaises(InstallerError):
                transaction.read_journal(home)

    def test_update_public_replacement_is_preserved(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            token = transaction.write_journal(home, _journal(home))
            path = home / transaction.JOURNAL_NAME
            original = journal_io._renameat2
            swapped = False

            def replace_before_exchange(source: Path, target: Path, flags: int) -> None:
                nonlocal swapped
                if flags == journal_io.RENAME_EXCHANGE and not swapped:
                    path.replace(home / "old-public")
                    path.write_bytes(b"HOSTILE")
                    path.chmod(0o600)
                    swapped = True
                original(source, target, flags)

            with patch.object(journal_io, "_renameat2", side_effect=replace_before_exchange):
                with self.assertRaises(InstallerError):
                    transaction.write_journal(home, _journal(home), expected=token)
            self.assertEqual(path.read_bytes(), b"HOSTILE")

    def test_moved_carrier_identity_mismatch_is_restored(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            token = transaction.write_journal(home, _journal(home))
            original = journal_io._read_identity
            wrong = _identity(b"wrong")

            def mismatch(path: Path) -> Identity:
                if path.name in journal_io.CARRIERS and not (home / transaction.JOURNAL_NAME).exists():
                    return wrong
                return original(path)

            with patch.object(journal_io, "_read_identity", side_effect=mismatch):
                with self.assertRaises(InstallerError):
                    transaction.clear_journal(home, token)
            self.assertTrue((home / transaction.JOURNAL_NAME).exists())

    def test_slot_fsync_failure_prevents_publication(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            journal_io._store(home, bootstrap=True)
            with patch.object(journal_syscalls.os, "fsync", side_effect=OSError("slot fsync")):
                with self.assertRaises(InstallerError):
                    transaction.write_journal(home, _journal(home))
            self.assertFalse((home / transaction.JOURNAL_NAME).exists())

    def test_repeated_reads_do_not_leak_descriptors(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            transaction.write_journal(home, _journal(home))
            before = len(os.listdir("/proc/self/fd"))
            for _ in range(100):
                self.assertIsNotNone(transaction.read_journal(home))
            self.assertEqual(len(os.listdir("/proc/self/fd")), before)

    def test_fsync_uncertainty_reports_moved_carrier(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            token = transaction.write_journal(home, _journal(home))
            with patch.object(journal_io, "fsync_path", side_effect=OSError("clear fsync")):
                with self.assertRaises(JournalDurabilityUncertain) as raised:
                    transaction.clear_journal(home, token)
            identities = [journal_io._read_identity(home / journal_io.STORE_NAME / name) for name in journal_io.CARRIERS]
            self.assertIn(raised.exception.identity, identities)
