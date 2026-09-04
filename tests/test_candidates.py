from __future__ import annotations

import tempfile
import threading
import unittest
from copy import deepcopy
from pathlib import Path

import yaml

from lifedb.candidates import CandidateStateError, CandidateStore
from lifedb.canon import (
    CanonIntegrityError,
    CanonNotFoundError,
    CanonTransactionError,
    ConcurrentCanonChangeError,
)
from lifedb.ids import is_uuid7, new_id
from lifedb.markdown import parse_markdown
from lifedb.validation import validate_vault
from lifedb.vault import Vault


class CandidateCanonTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name) / "vault"
        self.vault = Vault(self.root)
        self.vault.init()
        self.evidence = self.vault.ingest(
            "explicit source statement".encode(),
            source_kind="candidate-test",
            media_type="text/plain",
            filename="source.txt",
            sensitivity="personal",
        )
        self.store = CandidateStore(self.vault)

    def tearDown(self):
        self.temporary.cleanup()

    def claim(self, **changes):
        value = {
            "predicate": "lifedb.prefers",
            "object": {"text": "fast tools"},
            "statement": "Prefers fast tools.",
            "basis": "declared",
            "certainty": "confirmed",
            "observed_at": "2026-09-01T09:00:00+09:00",
            "evidence": [{"id": self.evidence["id"], "requires": "raw"}],
            "valid": {"from": "2026-09-01"},
            "sensitivity": "personal",
            "supersedes": [],
        }
        value.update(changes)
        return value

    def write_document(
        self,
        *,
        name: str = "subject.md",
        document_id: str | None = None,
        claims: list | None = None,
        sensitivity: str = "personal",
    ) -> tuple[Path, str, str]:
        semantic_id = document_id or new_id()
        body = "\n# Subject\n\nBody formatting must remain byte-for-byte intact.  \n"
        frontmatter = {
            "type": "Profile",
            "title": "Subject",
            "future-okf-field": {"nested": ["preserve", 7]},
            "x-lifedb": {
                "schema": "0.1",
                "id": semantic_id,
                "kind": "test-subject",
                "sensitivity": sensitivity,
                "future-extension": {"keep": True},
                "claims": deepcopy(claims or []),
            },
        }
        rendered = (
            "---\n"
            + yaml.safe_dump(frontmatter, allow_unicode=True, sort_keys=False)
            + "---\n"
            + body
        )
        path = self.root / "canon" / "self" / name
        path.write_text(rendered, encoding="utf-8")
        return path, semantic_id, body

    def test_candidate_state_is_projected_from_append_only_events(self):
        _, document_id, _ = self.write_document()
        candidate = self.store.create(
            target_document_id=document_id,
            claim=self.claim(evidence=[self.evidence["id"]]),
            actor="agent:test",
        )

        self.assertTrue(is_uuid7(candidate["id"]))
        self.assertEqual(candidate["status"], "pending")
        # Legacy bare Evidence IDs are made explicit before the creation event.
        self.assertEqual(
            candidate["claim"]["evidence"],
            [{"id": self.evidence["id"], "requires": "raw"}],
        )
        self.assertEqual([item["id"] for item in self.store.list(status="pending")], [candidate["id"]])

        rejected = self.store.reject(candidate["id"], actor="human:test", reason="not durable")
        self.assertEqual(rejected["status"], "rejected")
        self.assertEqual(rejected["resolution"]["reason"], "not durable")
        with self.assertRaises(CandidateStateError):
            self.store.promote(candidate["id"], actor="agent:test")

    def test_projection_uses_global_sequence_when_wall_clock_moves_backwards(self):
        _, document_id, _ = self.write_document()
        candidate = self.store.create(
            target_document_id=document_id,
            claim=self.claim(),
            actor="agent:test",
        )
        self.vault.append_event(
            "candidate.rejected",
            actor="human:test",
            data={"candidate_id": candidate["id"], "reason": "clock-regression"},
            target=candidate["id"],
            sensitivity="personal",
            recorded_at="2000-01-01T00:00:00Z",
        )

        candidate_events = [
            event
            for event in self.store._all_events()
            if event.get("target") == candidate["id"]
        ]
        self.assertEqual(
            [event["event_type"] for event in candidate_events],
            ["candidate.created", "candidate.rejected"],
        )
        self.assertLess(candidate_events[0]["sequence"], candidate_events[1]["sequence"])
        projected = self.store.get(candidate["id"])
        self.assertEqual(projected["status"], "rejected")
        self.assertEqual(projected["reason"], "clock-regression")

    def test_promotion_preserves_unknown_fields_and_body_and_is_reversible(self):
        path, document_id, body = self.write_document()
        exact_before = path.read_bytes()
        candidate = self.store.create(
            target_document_id=document_id,
            claim=self.claim(),
            actor="agent:test",
        )

        promoted = self.store.promote(candidate["id"], actor="agent:test")
        self.assertEqual(promoted["status"], "promoted")
        claim_id = promoted["resolution"]["claim_id"]
        transaction_id = promoted["resolution"]["transaction_id"]
        self.assertTrue(is_uuid7(claim_id))

        document = parse_markdown(path)
        self.assertEqual(document.body, body)
        self.assertEqual(document.frontmatter["future-okf-field"], {"nested": ["preserve", 7]})
        extension = document.frontmatter["x-lifedb"]
        self.assertEqual(extension["future-extension"], {"keep": True})
        self.assertEqual(len(extension["claims"]), 1)
        claim = extension["claims"][0]
        self.assertEqual(claim["id"], claim_id)
        self.assertEqual(claim["subject"], document_id)
        self.assertEqual(claim["state"], "active")
        self.assertEqual(
            claim["evidence"],
            [{"id": self.evidence["id"], "requires": "raw"}],
        )

        audit = self.vault.events_for(transaction_id)
        self.assertEqual(
            [event["event_type"] for event in audit],
            ["canon.change-prepared", "canon.change-committed"],
        )
        transaction = audit[-1]["data"]
        for field in ("actor", "candidate", "claim", "before", "after", "path"):
            self.assertIn(field, transaction)
        for field in ("before", "after"):
            digest = transaction[field].removeprefix("sha256:")
            self.assertTrue(self.vault.object_path(digest).is_file())

        rollback = self.store.rollback(transaction_id, actor="human:test")
        self.assertEqual(rollback["rollback_of"], transaction_id)
        self.assertEqual(path.read_bytes(), exact_before)
        rollback_events = self.vault.events_for(rollback["transaction_id"])
        self.assertEqual(
            [event["event_type"] for event in rollback_events],
            ["canon.rollback-prepared", "canon.rollback-committed"],
        )

    def test_rollback_reopens_candidate_for_repromotion(self):
        _, document_id, _ = self.write_document(name="repromote.md")
        candidate = self.store.create(document_id, self.claim(), actor="agent:test")
        first = self.store.promote(candidate["id"], actor="agent:test")

        rollback = self.store.rollback(first["transaction_id"], actor="human:test")

        self.assertEqual(self.store.get(candidate["id"])["status"], "pending")
        self.assertEqual(
            [event["event_type"] for event in self.vault.events_for(candidate["id"])],
            ["candidate.created", "candidate.promoted", "candidate.reopened"],
        )
        second = self.store.promote(candidate["id"], actor="agent:test")
        self.assertNotEqual(second["transaction_id"], first["transaction_id"])
        self.assertTrue(validate_vault(self.root).valid)

    def test_supersession_only_updates_named_claims(self):
        old_claim_id = new_id()
        untouched_claim_id = new_id()
        document_id = new_id()
        old_claim = {
            "id": old_claim_id,
            "subject": document_id,
            "predicate": "lifedb.prefers",
            "object": {"text": "slow tools"},
            "statement": "Prefers slow tools.",
            "basis": "declared",
            "certainty": "confirmed",
            "state": "active",
            "observed_at": "2025-01-01T00:00:00Z",
            "evidence": [{"id": self.evidence["id"], "requires": "raw"}],
            "unknown-claim-field": {"retain": True},
        }
        untouched_claim = {
            **deepcopy(old_claim),
            "id": untouched_claim_id,
            "predicate": "lifedb.uses",
            "statement": "Uses an editor.",
        }
        path, _, _ = self.write_document(
            document_id=document_id,
            claims=[old_claim, untouched_claim],
        )
        untouched_before = deepcopy(untouched_claim)
        candidate = self.store.create(
            target_document_id=document_id,
            claim=self.claim(supersedes=[old_claim_id]),
            actor="agent:test",
        )
        promoted = self.store.promote(candidate["id"], actor="agent:test")
        claims = parse_markdown(path).frontmatter["x-lifedb"]["claims"]

        updated_old = next(item for item in claims if item["id"] == old_claim_id)
        self.assertEqual(updated_old["state"], "superseded")
        self.assertEqual(updated_old["superseded_by"], [promoted["resolution"]["claim_id"]])
        self.assertEqual(updated_old["unknown-claim-field"], {"retain": True})
        self.assertEqual(next(item for item in claims if item["id"] == untouched_claim_id), untouched_before)
        self.assertEqual(claims[-1]["supersedes"], [old_claim_id])

    def test_validation_rejects_bad_claims_and_inconsistent_references(self):
        _, document_id, _ = self.write_document()
        invalid_claims = [
            self.claim(predicate="Upper.Case"),
            self.claim(object={"text": "x", "boolean": True}),
            self.claim(observed_at="2026-09-01T09:00:00"),
            self.claim(evidence=[]),
            self.claim(evidence=[{"id": self.evidence["id"], "requires": "unknown"}]),
            self.claim(valid={"from": "2026-09-02", "until": "2026-09-01"}),
            self.claim(valid={"from": "2026-09-01", "until": "2026-09-02T00:00:00Z"}),
            self.claim(valid={}),
            self.claim(object={"uri": "https://user:password@example.com/private"}),
        ]
        for claim in invalid_claims:
            with self.subTest(claim=claim), self.assertRaises(ValueError):
                self.store.create(
                    target_document_id=document_id,
                    claim=claim,
                    actor="agent:test",
                )

        with self.assertRaises(CanonNotFoundError):
            self.store.create(
                target_document_id=document_id,
                claim=self.claim(evidence=[{"id": new_id(), "requires": "raw"}]),
                actor="agent:test",
            )

        _, other_document_id, _ = self.write_document(name="other.md")
        foreign_claim_id = new_id()
        foreign_claim = {
            "id": foreign_claim_id,
            "subject": other_document_id,
            "predicate": "lifedb.uses",
            "object": {"text": "foreign"},
            "statement": "Foreign Claim.",
            "basis": "declared",
            "certainty": "confirmed",
            "state": "active",
            "observed_at": "2026-01-01T00:00:00Z",
            "evidence": [{"id": self.evidence["id"], "requires": "raw"}],
        }
        # Recreate the other file with an actual foreign Claim.
        self.write_document(
            name="other.md",
            document_id=other_document_id,
            claims=[foreign_claim],
        )
        with self.assertRaises(CanonIntegrityError):
            self.store.create(
                target_document_id=document_id,
                claim=self.claim(supersedes=[foreign_claim_id]),
                actor="agent:test",
            )

    def test_evidence_requirements_use_effective_state(self):
        _, document_id, _ = self.write_document()
        self.vault.append_event(
            "payload-evicted",
            actor="policy:test",
            target=self.evidence["id"],
            data={"reason": "test eviction"},
        )
        with self.assertRaises(CanonIntegrityError):
            self.store.create(
                target_document_id=document_id,
                claim=self.claim(evidence=[self.evidence["id"]]),
                actor="agent:test",
            )

        record_only = self.store.create(
            target_document_id=document_id,
            claim=self.claim(
                evidence=[{"id": self.evidence["id"], "requires": "record-only"}]
            ),
            actor="agent:test",
        )
        self.assertEqual(record_only["status"], "pending")

        representation_digest, _ = self.vault.store_object(b"recognized text")
        self.vault.append_event(
            "representation-added",
            actor="extractor:test",
            target=self.evidence["id"],
            data={
                "role": "ocr",
                "object": f"sha256:{representation_digest}",
                "media_type": "text/plain",
                "created_at": "2026-09-01T00:00:00Z",
                "producer": {"by": "extractor:test", "version": "1"},
            },
        )
        representation = self.store.create(
            target_document_id=document_id,
            claim=self.claim(
                evidence=[
                    {"id": self.evidence["id"], "requires": "representation:ocr"}
                ]
            ),
            actor="agent:test",
        )
        self.assertEqual(representation["status"], "pending")

    def test_evidence_events_cannot_be_cited_below_their_effective_sensitivity(self):
        _, document_id, _ = self.write_document()
        self.vault.append_event(
            "representation.added",
            actor="extractor:test",
            target=self.evidence["id"],
            sensitivity="sensitive",
            data={
                "role": "summary",
                "object": self.evidence["payload"]["object"],
                "media_type": "text/plain",
                "created_at": "2026-09-01T00:00:00Z",
                "producer": {"by": "extractor:test", "version": "1"},
            },
        )

        with self.assertRaisesRegex(CanonIntegrityError, "lower than Evidence"):
            self.store.create(
                target_document_id=document_id,
                claim=self.claim(
                    evidence=[
                        {"id": self.evidence["id"], "requires": "representation:summary"}
                    ],
                    sensitivity="personal",
                ),
                actor="agent:test",
            )

        candidate = self.store.create(
            target_document_id=document_id,
            claim=self.claim(
                evidence=[
                    {"id": self.evidence["id"], "requires": "representation:summary"}
                ],
                sensitivity="sensitive",
            ),
            actor="agent:test",
            sensitivity="sensitive",
        )
        self.assertEqual(candidate["sensitivity"], "sensitive")

    def test_failed_commit_restores_original_and_leaves_candidate_pending(self):
        path, document_id, _ = self.write_document()
        before = path.read_bytes()
        candidate = self.store.create(
            target_document_id=document_id,
            claim=self.claim(),
            actor="agent:test",
        )
        original_append = self.vault.append_event

        def fail_commit(event_type, **kwargs):
            if event_type == "canon.change-committed":
                raise OSError("simulated durable event failure")
            return original_append(event_type, **kwargs)

        self.vault.append_event = fail_commit  # type: ignore[method-assign]
        with self.assertRaises(CanonTransactionError):
            self.store.promote(candidate["id"], actor="agent:test")
        self.assertEqual(path.read_bytes(), before)
        self.assertEqual(self.store.get(candidate["id"])["status"], "pending")

    def test_rollback_refuses_to_overwrite_a_later_change(self):
        path, document_id, _ = self.write_document()
        candidate = self.store.create(
            target_document_id=document_id,
            claim=self.claim(),
            actor="agent:test",
        )
        promoted = self.store.promote(candidate["id"], actor="agent:test")
        transaction_id = promoted["resolution"]["transaction_id"]
        later_bytes = path.read_bytes() + b"\nExternal edit.\n"
        path.write_bytes(later_bytes)

        with self.assertRaises(ConcurrentCanonChangeError):
            self.store.rollback(transaction_id, actor="human:test")
        self.assertEqual(path.read_bytes(), later_bytes)

    def test_rollback_retry_fails_closed_after_current_bytes_drift(self):
        path, document_id, _ = self.write_document()
        candidate = self.store.create(document_id, self.claim(), actor="agent:test")
        promoted = self.store.promote(candidate["id"], actor="agent:test")
        transaction_id = promoted["transaction_id"]
        self.store.rollback(transaction_id, actor="human:test")
        path.write_bytes(path.read_bytes() + b"\nManual edit after rollback.\n")
        with self.assertRaises(ConcurrentCanonChangeError):
            self.store.rollback(transaction_id, actor="human:test")

    def test_concurrent_terminal_commands_create_only_one_promotion(self):
        path, document_id, _ = self.write_document()
        candidate = self.store.create(
            target_document_id=document_id,
            claim=self.claim(),
            actor="agent:test",
        )
        barrier = threading.Barrier(2)
        outcomes: list[str] = []

        def promote():
            barrier.wait()
            try:
                self.store.promote(candidate["id"], actor="agent:test")
            except CandidateStateError:
                outcomes.append("already-terminal")
            else:
                outcomes.append("promoted")

        threads = [threading.Thread(target=promote) for _ in range(2)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=3)
        self.assertTrue(all(not thread.is_alive() for thread in threads))
        self.assertCountEqual(outcomes, ["promoted", "already-terminal"])
        claims = parse_markdown(path).frontmatter["x-lifedb"]["claims"]
        self.assertEqual(len(claims), 1)


if __name__ == "__main__":
    unittest.main()
