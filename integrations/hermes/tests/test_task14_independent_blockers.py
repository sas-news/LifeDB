from __future__ import annotations

import base64
from dataclasses import replace
import hashlib
import os
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch

from integrations.hermes.installer import journal_io, journal_store, journal_syscalls, transaction
from integrations.hermes.installer.journal_schema import _JSON, decode_value, identity_data
from integrations.hermes.installer.models import Identity, InstallerError, JournalDurabilityUncertain
from integrations.hermes.tests.test_task14_journal_store import _identity, _journal
from integrations.hermes.tests.test_task14_schema_contract import _file, _intended, _observed, _record


def _fresh_commit() -> dict[str, _JSON]:
    data = _record(operation="install", phase="committed")
    data.update({
        "old_root_exists": False,
        "config_exists": False,
        "old_config_b64": "",
        "old_config_mode": 0,
        "old_config_mtime_ns": 0,
        "old_marker_exists": False,
        "old_marker_b64": "",
        "old_marker_mode": 0,
        "old_marker_mtime_ns": 0,
        "old_tree_manifest": {},
        "cleanup_manifest": {},
        "old_live_identity": None,
        "config_identity": None,
        "old_marker_identity": None,
        "live_identity": identity_data(_identity(b"live", kind="directory", mode=0o700)),
        "staging": None,
        "staging_identity": None,
        "quarantine": None,
        "quarantine_identity": None,
    })
    _intended(data)
    _observed(data)
    return data


class Task14IndependentBlockerTests(unittest.TestCase):
    def test_fresh_install_commit_is_representable(self) -> None:
        decode_value(_fresh_commit(), Path("/tmp/hermes"))

    def test_disable_commit_rejects_missing_old_root(self) -> None:
        data = _record(operation="disable", phase="committed", old_root_exists=False, old_tree_manifest={}, old_live_identity=None, old_marker_exists=False, old_marker_b64="", old_marker_identity=None, config_exists=False, config_identity=None, old_config_b64="", old_config_mode=0, old_config_mtime_ns=0)
        _intended(data)
        _observed(data)
        with self.assertRaises(InstallerError):
            decode_value(data, Path("/tmp/hermes"))

    def test_fresh_install_rejects_quarantine_before_old_root_exists(self) -> None:
        data = _record(operation="install", phase="prepared", old_root_exists=False, quarantine="plugins/.lifedb-quarantine-x", quarantine_identity=identity_data(_identity(b"q", kind="directory", mode=0o700)))
        with self.assertRaises(InstallerError):
            decode_value(data, Path("/tmp/hermes"))

    def test_fresh_install_rejects_cleanup_state(self) -> None:
        data = _fresh_commit()
        data["phase"] = "cleanup_pending"
        data["cleanup_manifest"] = {"plugin.yaml": identity_data(_file(b"old"))}
        with self.assertRaises(InstallerError):
            decode_value(data, Path("/tmp/hermes"))

    def test_old_marker_identity_binds_size_and_mtime(self) -> None:
        data = _record()
        forged = _file(b"old-marker", mtime_ns=9)
        forged = Identity(forged.device, forged.inode, forged.owner_uid, forged.kind, forged.mode, forged.size + 1, forged.mtime_ns, forged.sha256)
        data["old_marker_identity"] = identity_data(forged)
        data["old_tree_manifest"][".lifedb-owner.json"] = identity_data(forged)
        with self.assertRaises(InstallerError):
            decode_value(data, Path("/tmp/hermes"))

    def test_same_token_concurrent_writers_have_one_winner(self) -> None:
        for _ in range(50):
            with tempfile.TemporaryDirectory() as directory:
                home = Path(directory)
                token = transaction.write_journal(home, _journal(home))
                barrier = threading.Barrier(2)
                results: list[Identity | InstallerError] = []

                def run(phase: str) -> None:
                    barrier.wait(timeout=5)
                    results.append(_run_update(home, token, phase))

                threads = [threading.Thread(target=run, args=("prepared",)) for _ in range(2)]
                for thread in threads:
                    thread.start()
                for thread in threads:
                    thread.join(timeout=10)
                self.assertEqual(sum(isinstance(result, Identity) for result in results), 1)
                self.assertEqual(sum(isinstance(result, InstallerError) for result in results), 1)
                self.assertIsNotNone(transaction.read_journal(home))

    def test_identity_rejects_same_size_mutation_during_hash(self) -> None:
        with tempfile.NamedTemporaryFile(mode="wb", delete=False) as handle:
            handle.write(b"a" * 100)
            path = Path(handle.name)
        try:
            original = os.pread
            mutated = False

            def mutate(descriptor: int, size: int, offset: int) -> bytes:
                nonlocal mutated
                raw = original(descriptor, size, offset)
                if not mutated:
                    mutated = True
                    replacement = os.open(path, os.O_RDWR)
                    try:
                        os.pwrite(replacement, b"b" * 100, 0)
                    finally:
                        os.close(replacement)
                return raw

            with patch.object(journal_syscalls.os, "pread", side_effect=mutate):
                with self.assertRaises(InstallerError):
                    journal_syscalls.read_identity(path)
        finally:
            path.unlink()

    def test_identity_rejects_truncate_during_hash(self) -> None:
        with tempfile.NamedTemporaryFile(mode="wb", delete=False) as handle:
            handle.write(b"a" * 100)
            path = Path(handle.name)
        try:
            original = os.pread
            changed = False

            def truncate(descriptor: int, size: int, offset: int) -> bytes:
                nonlocal changed
                raw = original(descriptor, size, offset)
                if not changed:
                    changed = True
                    replacement = os.open(path, os.O_RDWR)
                    try:
                        os.ftruncate(replacement, 50)
                    finally:
                        os.close(replacement)
                return raw

            with patch.object(journal_syscalls.os, "pread", side_effect=truncate):
                with self.assertRaises(InstallerError):
                    journal_syscalls.read_identity(path)
        finally:
            path.unlink()

    def test_identity_rejects_extend_during_hash(self) -> None:
        with tempfile.NamedTemporaryFile(mode="wb", delete=False) as handle:
            handle.write(b"a" * 100)
            path = Path(handle.name)
        try:
            original = os.pread
            changed = False

            def extend(descriptor: int, size: int, offset: int) -> bytes:
                nonlocal changed
                raw = original(descriptor, size, offset)
                if not changed:
                    changed = True
                    replacement = os.open(path, os.O_RDWR)
                    try:
                        os.ftruncate(replacement, 150)
                    finally:
                        os.close(replacement)
                return raw

            with patch.object(journal_syscalls.os, "pread", side_effect=extend):
                with self.assertRaises(InstallerError):
                    journal_syscalls.read_identity(path)
        finally:
            path.unlink()

    def test_bootstrap_fsync_failure_closes_descriptor(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            before = len(os.listdir("/proc/self/fd"))
            with patch.object(journal_store.os, "fsync", side_effect=OSError("bootstrap fsync")):
                with self.assertRaises(InstallerError):
                    transaction.write_journal(home, _journal(home))
            self.assertEqual(len(os.listdir("/proc/self/fd")), before)

    def test_publication_fsyncs_store_and_home(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            calls: list[Path] = []

            def record(path: Path) -> None:
                calls.append(path)

            with patch.object(journal_io, "fsync_path", side_effect=record):
                transaction.write_journal(home, _journal(home))
            self.assertIn(home, calls)
            self.assertIn(home / journal_io.STORE_NAME, calls)

    def test_each_publication_directory_fsync_failure_is_uncertain(self) -> None:
        for failed_directory in ("store", "home"):
            with tempfile.TemporaryDirectory() as directory:
                home = Path(directory)
                token = transaction.write_journal(home, _journal(home))

                def fail_selected(path: Path) -> None:
                    if failed_directory == "store" and path == home / journal_io.STORE_NAME or failed_directory == "home" and path == home:
                        raise OSError(failed_directory)

                with patch.object(journal_io, "fsync_path", side_effect=fail_selected):
                    with self.assertRaises(JournalDurabilityUncertain) as raised:
                        transaction.write_journal(home, replace(_journal(home), phase="prepared"), expected=token)
                self.assertEqual(raised.exception.identity, journal_io._read_identity(home / transaction.JOURNAL_NAME))

    def test_clear_replacement_during_fsync_is_uncertain(self) -> None:
        for replacement_call in (1, 2):
            with tempfile.TemporaryDirectory() as directory:
                home = Path(directory)
                token = transaction.write_journal(home, _journal(home))
                path = home / transaction.JOURNAL_NAME
                calls = 0

                def recreate(_: Path) -> None:
                    nonlocal calls
                    calls += 1
                    if calls == replacement_call:
                        path.write_bytes(b"replacement")
                        path.chmod(0o600)

                with patch.object(journal_io, "fsync_path", side_effect=recreate):
                    with self.assertRaises(JournalDurabilityUncertain):
                        transaction.clear_journal(home, token)
                self.assertTrue(path.exists())

    def test_update_identity_mismatch_is_typed_uncertainty(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            token = transaction.write_journal(home, _journal(home))
            original = journal_io._read_identity
            wrong = _identity(b"wrong")
            renamed = False
            original_rename = journal_io._renameat2

            def mark_exchange(source: Path, target: Path, flags: int) -> None:
                nonlocal renamed
                original_rename(source, target, flags)
                if flags == journal_io.RENAME_EXCHANGE:
                    renamed = True

            def mismatch(path: Path) -> Identity:
                if renamed and path.name in journal_io.CARRIERS:
                    return wrong
                return original(path)

            with patch.object(journal_io, "_renameat2", side_effect=mark_exchange), patch.object(journal_io, "_read_identity", side_effect=mismatch):
                with self.assertRaises(JournalDurabilityUncertain):
                    transaction.write_journal(home, replace(_journal(home), phase="prepared"), expected=token)


def _run_update(home: Path, token: Identity, phase: str) -> Identity | InstallerError:
    try:
        return transaction.write_journal(home, replace(_journal(home), phase=phase), expected=token)
    except InstallerError as error:
        return error


if __name__ == "__main__":
    unittest.main()
