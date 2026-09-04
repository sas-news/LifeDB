from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import yaml

from lifedb.candidates import CandidateStore
import lifedb.canon as canon_module
from lifedb.canon import CanonStore, CanonTransactionError
from lifedb.ids import new_id
from lifedb.validation import validate_vault
from lifedb.vault import Vault
from lifedb.evidence import iter_events


class CanonRecoveryTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name) / "vault"
        self.vault = Vault(self.root)
        self.vault.init()
        self.evidence = self.vault.ingest(b"recovery evidence", source_kind="recovery")
        self.document_id = new_id()
        self.path = self.root / "canon" / "self" / "recovery.md"
        self.path.write_text(
            "---\n"
            + yaml.safe_dump(
                {
                    "type": "Profile",
                    "x-lifedb": {
                        "schema": "0.1",
                        "id": self.document_id,
                        "sensitivity": "personal",
                        "claims": [],
                    },
                },
                sort_keys=False,
            )
            + "---\n# Recovery\n",
            encoding="utf-8",
        )

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def claim(self) -> dict:
        return {
            "predicate": "lifedb.recovery",
            "object": {"text": "works"},
            "statement": "Recovery works.",
            "basis": "declared",
            "certainty": "confirmed",
            "observed_at": "2026-09-01T00:00:00Z",
            "evidence": [self.evidence["id"]],
        }

    def test_after_phase_recovers_commit_and_candidate_terminal(self) -> None:
        candidates = CandidateStore(self.vault)
        candidate = candidates.create(self.document_id, self.claim(), actor="agent:test")
        original_append = self.vault.append_event

        def interrupt_before_commit(event_type, **kwargs):
            if event_type == "canon.change-committed":
                raise SystemExit("simulated process death")
            return original_append(event_type, **kwargs)

        self.vault.append_event = interrupt_before_commit
        with self.assertRaises(SystemExit):
            candidates.promote(candidate["id"], actor="agent:test")
        self.vault.append_event = original_append
        transaction_id = next(
            event["target"]
            for event in iter_events(self.vault)
            if event["event_type"] == "canon.change-prepared"
        )

        report = CanonStore(self.vault).recover_interrupted()
        self.assertEqual(report["recovered_committed"], [transaction_id])
        self.assertEqual(report["candidates_reconciled"], [candidate["id"]])
        self.assertEqual(CandidateStore(self.vault).get(candidate["id"])["status"], "promoted")
        self.assertTrue(validate_vault(self.root).valid)
        self.assertEqual(CanonStore(self.vault).recover_interrupted()["recovered_committed"], [])

    def test_before_phase_recovers_abort_without_replacing_bytes(self) -> None:
        candidates = CandidateStore(self.vault)
        candidate = candidates.create(self.document_id, self.claim(), actor="agent:test")
        with mock.patch.object(canon_module, "_atomic_replace", side_effect=SystemExit):
            with self.assertRaises(SystemExit):
                candidates.promote(candidate["id"], actor="agent:test")
        transaction_id = next(
            event["target"]
            for event in iter_events(self.vault)
            if event["event_type"] == "canon.change-prepared"
        )

        report = CanonStore(self.vault).recover_interrupted()
        self.assertEqual(report["recovered_aborted"], [transaction_id])
        self.assertEqual(CandidateStore(self.vault).get(candidate["id"])["status"], "pending")
        self.assertTrue(validate_vault(self.root).valid)

    def test_conflict_is_unresolved_and_never_overwritten(self) -> None:
        candidates = CandidateStore(self.vault)
        candidate = candidates.create(self.document_id, self.claim(), actor="agent:test")
        original_append = self.vault.append_event

        def interrupt_before_commit(event_type, **kwargs):
            if event_type == "canon.change-committed":
                raise SystemExit("simulated process death")
            return original_append(event_type, **kwargs)

        self.vault.append_event = interrupt_before_commit
        with self.assertRaises(SystemExit):
            candidates.promote(candidate["id"], actor="agent:test")
        self.vault.append_event = original_append
        transaction_id = next(
            event["target"]
            for event in iter_events(self.vault)
            if event["event_type"] == "canon.change-prepared"
        )
        self.path.write_bytes(self.path.read_bytes() + b"manual edit\n")
        changed = self.path.read_bytes()
        report = CanonStore(self.vault).recover_interrupted()
        self.assertFalse(report["recovered_committed"])
        self.assertFalse(report["recovered_aborted"])
        self.assertTrue(report["unresolved"])
        self.assertEqual(self.path.read_bytes(), changed)

    def test_duplicate_committed_promotions_are_ambiguous_and_not_reconciled(self) -> None:
        candidates = CandidateStore(self.vault)
        candidate = candidates.create(self.document_id, self.claim(), actor="agent:test")
        original_append = self.vault.append_event

        def interrupt_before_terminal(event_type, **kwargs):
            if event_type == "candidate.promoted":
                raise SystemExit("simulated process death")
            return original_append(event_type, **kwargs)

        self.vault.append_event = interrupt_before_terminal
        with self.assertRaises(SystemExit):
            candidates.promote(candidate["id"], actor="agent:test")
        self.vault.append_event = original_append
        transaction_id = next(
            event["target"]
            for event in iter_events(self.vault)
            if event["event_type"] == "canon.change-committed"
        )
        commit = next(
            event for event in self.vault.events_for(transaction_id)
            if event["event_type"] == "canon.change-committed"
        )
        # Simulate a duplicated terminal record and a crash before the
        # Candidate terminal was durably appended.
        self.vault.append_event(
            "canon.change-committed",
            actor="fault-injector",
            data=commit["data"],
            target=transaction_id,
            sensitivity=commit["sensitivity"],
        )
        report = CanonStore(self.vault).recover_interrupted()
        self.assertNotIn(candidate["id"], report["candidates_reconciled"])
        self.assertEqual(
            len([item for item in report["unresolved"] if item.get("target") == candidate["id"]]),
            1,
        )
        self.assertEqual(
            [event["event_type"] for event in self.vault.events_for(candidate["id"])],
            ["candidate.created"],
        )

    def test_directory_fsync_uncertainty_recovers_as_commit(self) -> None:
        candidates = CandidateStore(self.vault)
        candidate = candidates.create(self.document_id, self.claim(), actor="agent:test")
        before = self.path.read_bytes()
        original_fsync = canon_module.os.fsync

        def fail_canon_directory_fsync(descriptor: int) -> None:
            try:
                target = os.readlink(f"/proc/self/fd/{descriptor}")
            except OSError:
                target = ""
            if target == str(self.path.parent):
                raise OSError("directory fsync injection")
            original_fsync(descriptor)

        with mock.patch.object(canon_module.os, "fsync", side_effect=fail_canon_directory_fsync):
            with self.assertRaises(CanonTransactionError):
                CanonStore(self.vault).promote(candidate, actor="agent:test")
        self.assertNotEqual(self.path.read_bytes(), before)
        prepared = [
            event
            for event in iter_events(self.vault)
            if event["event_type"] == "canon.change-prepared"
        ]
        self.assertEqual(len(prepared), 1)
        transaction_id = prepared[0]["target"]
        self.assertEqual(CanonStore(self.vault).recover_interrupted()["recovered_committed"], [transaction_id])
        self.assertEqual(CanonStore(self.vault).recover_interrupted()["recovered_committed"], [])

    def test_incomplete_compensation_leaves_prepared_only(self) -> None:
        candidates = CandidateStore(self.vault)
        candidate = candidates.create(self.document_id, self.claim(), actor="agent:test")
        before = self.path.read_bytes()
        original_append = self.vault.append_event
        original_replace = canon_module._atomic_replace
        replace_calls = 0

        def fail_commit(event_type, **kwargs):
            if event_type == "canon.change-committed":
                raise OSError("commit injection")
            return original_append(event_type, **kwargs)

        def fail_compensation(path, data, **kwargs):
            nonlocal replace_calls
            replace_calls += 1
            if replace_calls == 2:
                raise OSError("compensation injection")
            return original_replace(path, data, **kwargs)

        self.vault.append_event = fail_commit
        with mock.patch.object(canon_module, "_atomic_replace", side_effect=fail_compensation):
            with self.assertRaises(CanonTransactionError):
                CanonStore(self.vault).promote(candidate, actor="agent:test")
        self.assertNotEqual(self.path.read_bytes(), before)
        event_types = [event["event_type"] for event in iter_events(self.vault)]
        self.assertIn("canon.change-prepared", event_types)
        self.assertNotIn("canon.change-aborted", event_types)

    def test_rollback_directory_fsync_uncertainty_recovers_as_commit(self) -> None:
        candidates = CandidateStore(self.vault)
        candidate = candidates.create(self.document_id, self.claim(), actor="agent:test")
        promoted = candidates.promote(candidate["id"], actor="agent:test")
        transaction_id = promoted["transaction_id"]
        before = self.path.read_bytes()
        original_fsync = canon_module.os.fsync

        def fail_canon_directory_fsync(descriptor: int) -> None:
            try:
                target = os.readlink(f"/proc/self/fd/{descriptor}")
            except OSError:
                target = ""
            if target == str(self.path.parent):
                raise OSError("directory fsync injection")
            original_fsync(descriptor)

        with mock.patch.object(canon_module.os, "fsync", side_effect=fail_canon_directory_fsync):
            with self.assertRaises(CanonTransactionError):
                CanonStore(self.vault).rollback(transaction_id, actor="agent:test")
        self.assertNotEqual(self.path.read_bytes(), before)
        prepared = [
            event
            for event in iter_events(self.vault)
            if event["event_type"] == "canon.rollback-prepared"
        ]
        self.assertEqual(len(prepared), 1)
        rollback_id = prepared[0]["target"]
        self.assertEqual(CanonStore(self.vault).recover_interrupted()["recovered_committed"], [rollback_id])
        self.assertEqual(CanonStore(self.vault).recover_interrupted()["recovered_committed"], [])


if __name__ == "__main__":
    unittest.main()
