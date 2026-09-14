from __future__ import annotations

from dataclasses import replace
import multiprocessing
from pathlib import Path
import tempfile
import unittest

from integrations.hermes.installer import transaction
from integrations.hermes.installer.models import Identity, InstallerError
from integrations.hermes.tests.test_task14_journal_store import _journal


def _process_update(home: str, token: Identity, gate: multiprocessing.synchronize.Barrier, results: multiprocessing.queues.Queue[bool]) -> None:
    gate.wait()
    try:
        transaction.write_journal(Path(home), replace(_journal(Path(home)), phase="prepared"), expected=token)
    except InstallerError:
        results.put(False)
    else:
        results.put(True)


class Task14ProcessCASTests(unittest.TestCase):
    def test_same_token_processes_have_one_winner(self) -> None:
        context = multiprocessing.get_context("fork")
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            token = transaction.write_journal(home, _journal(home))
            gate = context.Barrier(2)
            results = context.Queue()
            processes = [context.Process(target=_process_update, args=(str(home), token, gate, results)) for _ in range(2)]
            for process in processes:
                process.start()
            for process in processes:
                process.join(10)
            outcomes = [results.get(timeout=2) for _ in processes]
            self.assertEqual(outcomes.count(True), 1)
            self.assertEqual(outcomes.count(False), 1)
            self.assertIsNotNone(transaction.read_journal(home))


if __name__ == "__main__":
    unittest.main()
