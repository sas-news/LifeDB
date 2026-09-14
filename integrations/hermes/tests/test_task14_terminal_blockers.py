from __future__ import annotations

from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from integrations.hermes.installer import journal_io, transaction
from integrations.hermes.installer.models import Identity, InstallerError, JournalDurabilityUncertain
from integrations.hermes.tests.test_task14_journal_store import _identity, _journal
from integrations.hermes.tests.test_task14_independent_blockers import _fresh_commit
from integrations.hermes.installer.journal_schema import decode_value, identity_data


class Task14TerminalBlockerTests(unittest.TestCase):
    def test_fresh_install_quarantined_phase_requires_old_root(self) -> None:
        data = _fresh_commit()
        data["phase"] = "quarantined"
        data["staging"] = "plugins/.lifedb-staging-x"
        data["staging_identity"] = identity_data(_identity(b"stage", kind="directory", mode=0o700))
        with self.assertRaises(InstallerError):
            decode_value(data, Path("/tmp/hermes"))

    def test_bootstrap_retry_resyncs_store_and_home_after_failure(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            with patch.object(journal_io, "fsync_path", side_effect=OSError("bootstrap")):
                with self.assertRaises(InstallerError):
                    journal_io._store(home, bootstrap=True)
            calls: list[Path] = []
            with patch.object(journal_io, "fsync_path", side_effect=calls.append):
                journal_io._store(home, bootstrap=True)
            self.assertEqual(calls, [home / journal_io.STORE_NAME, home])

    def test_clear_restoration_failure_reports_moved_identity(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            token = transaction.write_journal(home, _journal(home))
            public = home / transaction.JOURNAL_NAME
            original_identity = journal_io._read_identity
            original_rename = journal_io._renameat2
            wrong = _identity(b"wrong")
            moved = False

            def rename(source: Path, target: Path, flags: int) -> None:
                nonlocal moved
                if moved and source.name in journal_io.CARRIERS and target == public:
                    raise OSError("restore failed")
                original_rename(source, target, flags)
                if source == public and target.name in journal_io.CARRIERS:
                    moved = True

            def mismatch(path: Path) -> Identity:
                if moved and path.name in journal_io.CARRIERS and not public.exists():
                    return wrong
                return original_identity(path)

            with patch.object(journal_io, "_renameat2", side_effect=rename), patch.object(journal_io, "_read_identity", side_effect=mismatch):
                with self.assertRaises(JournalDurabilityUncertain) as raised:
                    transaction.clear_journal(home, token)
            self.assertEqual(raised.exception.identity, wrong)
            self.assertFalse(public.exists())


if __name__ == "__main__":
    unittest.main()
