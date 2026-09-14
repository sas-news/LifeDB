from __future__ import annotations

from pathlib import Path
from dataclasses import replace
import tempfile
import unittest
import json
import os
import stat
from unittest.mock import patch

from integrations.hermes.installer.models import InstallerError
from integrations.hermes.installer.identity import path_identity
from integrations.hermes.installer.recovery import recover
from integrations.hermes.installer.transaction import Journal, read_journal, write_journal, clear_journal
from integrations.hermes.installer.source import OWNED_FILES, hashes
from integrations.hermes.installer.process import child_env
from integrations.hermes.installer.core import _read_config
from integrations.hermes.tests.test_task14_journal_store import _journal


class TransactionRecoveryTests(unittest.TestCase):
    def test_journal_round_trip_has_fixed_phase_and_owned_paths(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            journal = _journal(home)
            write_journal(home, journal)
            self.assertEqual(read_journal(home).phase, journal.phase)

    def test_recovery_rejects_hostile_journal_path(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            journal = Journal(home=home, operation="install", phase="prepared", staging="../outside", quarantine=None)
            with self.assertRaises(InstallerError):
                write_journal(home, journal)
            self.assertFalse((home / ".lifedb-transaction.json").exists())
            self.assertFalse((home.parent / "outside").exists())

    def test_journal_rejects_bool_and_noncanonical_base64(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            data = {"schema": True, "home": str(home), "operation": "install", "phase": "prepared", "staging": None, "quarantine": None, "old_root_exists": False, "config_exists": True, "old_config_b64": "not-base64", "old_config_mode": 0o600, "old_marker_b64": "", "config_identity": None, "staging_identity": None, "quarantine_identity": None, "live_identity": None, "lock_identity": None, "old_tree_manifest": [], "desired_config_hash": "", "desired_marker_hash": ""}
            (home / ".lifedb-transaction.json").write_text(json.dumps(data), encoding="utf-8")
            (home / ".lifedb-transaction.json").chmod(0o600)
            with self.assertRaises(InstallerError):
                read_journal(home)

    def test_journal_preimage_fields_are_serialized(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            journal = _journal(home)
            write_journal(home, journal)
            self.assertEqual(set(read_journal(home).old_tree_manifest), set(_journal(home).old_tree_manifest))

    def test_journal_update_requires_exact_compare_and_swap_identity(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            config = home / "config.yaml"
            config.write_bytes(b"plugins: {}\n")
            config.chmod(0o600)
            identity = path_identity(config)
            journal = replace(_journal(home), config_identity=identity, old_config_b64="cGx1Z2luczoge30K", old_config_mtime_ns=identity.mtime_ns)
            token = write_journal(home, journal)
            replacement = home / ".lifedb-transaction.json"
            replacement.replace(home / ".replacement")
            (home / ".lifedb-transaction.json").write_bytes(b"hostile")
            with self.assertRaises(InstallerError):
                write_journal(home, journal, expected=token)
            self.assertEqual((home / ".lifedb-transaction.json").read_bytes(), b"hostile")

    def test_clear_requires_exact_identity_and_preserves_replacement(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            journal = _journal(home)
            token = write_journal(home, journal)
            path = home / ".lifedb-transaction.json"
            path.replace(home / ".old")
            path.write_bytes(b"hostile")
            with self.assertRaises(InstallerError):
                clear_journal(home, token)
            self.assertEqual(path.read_bytes(), b"hostile")

    def test_broken_journal_is_visible_to_read_only_check(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            (home / ".lifedb-transaction.json").symlink_to(home / "missing")
            with self.assertRaises(InstallerError):
                read_journal(home)

    def test_recovery_refuses_hostile_quarantine_directory(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory); plugins = home / "plugins"; plugins.mkdir()
            quarantine = plugins / ".lifedb-quarantine-hostile"; quarantine.mkdir(); (quarantine / "hostile").write_text("keep")
            expected = plugins / ".expected"; expected.mkdir(); expected_identity = path_identity(expected, directory=True); expected.rmdir()
            write_journal(home, replace(_journal(home), operation="uninstall", phase="quarantined", quarantine=quarantine.relative_to(home).as_posix(), quarantine_identity=expected_identity, live_identity=None))
            with self.assertRaises(InstallerError):
                recover(home)
            self.assertTrue((quarantine / "hostile").exists())

    def test_journal_accepts_explicit_boundary_intent_phases(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            journal = _journal(home)
            write_journal(home, journal)
            self.assertEqual(read_journal(home).phase, "prepared")

    def test_empty_config_is_distinct_from_absent_config(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory); path = home / "config.yaml"; path.write_bytes(b""); path.chmod(0o600)
            loaded = _read_config(home, create=True)
            self.assertEqual(len(loaded), 6)
            self.assertTrue(loaded[0])

    def test_clear_journal_requires_recorded_identity(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory); journal = _journal(home); write_journal(home, journal)
            replacement = home / ".lifedb-transaction.json"; replacement.rename(home / ".replacement")
            (home / ".lifedb-transaction.json").write_bytes(b"hostile")
            with self.assertRaises(InstallerError):
                __import__("integrations.hermes.installer.transaction", fromlist=["clear_journal"]).clear_journal(home, journal)
            self.assertEqual((home / ".lifedb-transaction.json").read_bytes(), b"hostile")

    def test_source_hashes_reject_symlink_owned_file(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in OWNED_FILES:
                (root / name).write_bytes(b"x")
            (root / "hooks.py").unlink(); (root / "hooks.py").symlink_to(root / "plugin.yaml")
            with self.assertRaises(InstallerError):
                hashes(root)

    def test_child_environment_does_not_inherit_arbitrary_path(self) -> None:
        with patch.dict(os.environ, {"PATH": "/hostile"}):
            self.assertNotEqual(child_env(Path("/isolated"))["PATH"], "/hostile")

    def test_core_orchestration_has_split_size_budget(self) -> None:
        path = Path(__file__).parents[1] / "installer" / "core.py"
        pure = sum(1 for line in path.read_text(encoding="utf-8").splitlines() if line.strip() and not line.lstrip().startswith("#"))
        self.assertLess(pure, 220)


if __name__ == "__main__":
    unittest.main()
