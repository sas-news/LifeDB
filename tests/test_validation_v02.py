from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from lifedb.evidence import seal_record
from lifedb.secrets import SecretDetectedError
from lifedb.storage import durable_write_json
from lifedb.ids import new_id
from lifedb.retention import RetentionManager
from lifedb.validation import validate_vault
from lifedb.vault import Vault


class ValidationV02Test(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name) / "vault"
        self.vault = Vault(self.root)
        self.metadata = self.vault.init()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _use_zero_day_grace(self) -> None:
        policy_path = self.root / "policies" / "retention.json"
        policy = json.loads(policy_path.read_text(encoding="utf-8"))
        policy["grace_days"] = 0
        policy_path.write_text(json.dumps(policy), encoding="utf-8")

    def _append_aborted_retention(
        self,
        plan: dict,
        candidate: dict,
        *,
        sensitivity: str = "personal",
    ) -> str:
        transaction_id = new_id()
        manifest = {
            "plan": plan["id"],
            "confirmation": plan["confirmation"],
            "candidates": [candidate],
        }
        evidence_id = candidate["evidence"][0]
        self.vault.append_event(
            "retention.apply-prepared",
            actor="human:test",
            target=transaction_id,
            sensitivity=sensitivity,
            data=manifest,
        )
        self.vault.append_event(
            "payload.evicted",
            actor="human:test",
            target=evidence_id,
            sensitivity=sensitivity,
            data={
                "transaction_id": transaction_id,
                "plan": plan["id"],
                "object": candidate["object"],
                "payload": {"reason": "validation fixture"},
            },
        )
        self.vault.append_event(
            "payload.restored",
            actor="process:test",
            target=evidence_id,
            sensitivity=sensitivity,
            data={
                "transaction_id": transaction_id,
                "plan": plan["id"],
                "object": candidate["object"],
                "payload": {"reason": "validation fixture"},
            },
        )
        self.vault.append_event(
            "retention.apply-aborted",
            actor="process:test",
            target=transaction_id,
            sensitivity=sensitivity,
            data={
                **manifest,
                "restored": True,
                "restored_evidence": [evidence_id],
            },
        )
        return transaction_id

    def test_fresh_vault_installs_self_describing_schemas(self) -> None:
        self.assertEqual(self.metadata["schema"], "0.2")
        self.assertTrue((self.root / "schemas" / "evidence-event.schema.json").is_file())
        report = validate_vault(self.root)
        self.assertTrue(report.valid, report.as_dict())

    def test_real_schema_and_integrity_validation_both_run(self) -> None:
        record = self.vault.ingest(b"schema check", source_kind="test")
        path = self.vault.evidence_path(record["id"])
        assert path is not None
        malformed = dict(record)
        malformed["producer"] = {"by": "process:test"}
        malformed = seal_record(malformed)
        path.chmod(0o600)
        durable_write_json(path, malformed)

        report = validate_vault(self.root)
        self.assertFalse(report.valid)
        self.assertTrue(any("version" in error for error in report.errors), report.as_dict())

        tampered = json.loads(path.read_text(encoding="utf-8"))
        tampered["content"]["filename"] = "changed-without-reseal"
        durable_write_json(path, tampered)
        report = validate_vault(self.root)
        self.assertTrue(any("integrity" in error for error in report.errors), report.as_dict())

    def test_event_chain_gap_is_detected_even_with_valid_record_integrity(self) -> None:
        record = self.vault.ingest(b"event target", source_kind="test")
        event = self.vault.append_event(
            "audit.entry", actor="process:test", target=record["id"], data={}
        )
        paths = list((self.root / "evidence" / "_events").rglob(f"{event['id']}.json"))
        self.assertEqual(len(paths), 1)
        changed = dict(event)
        changed["sequence"] = 2
        changed = seal_record(changed)
        paths[0].chmod(0o600)
        durable_write_json(paths[0], changed)

        report = validate_vault(self.root)
        self.assertFalse(report.valid)
        self.assertTrue(any("contiguous" in error for error in report.errors), report.as_dict())

    def test_retention_change_event_must_match_effective_class(self) -> None:
        record = self.vault.ingest(b"retention consistency", source_kind="test")
        self.vault.append_event(
            "retention.changed",
            actor="human:test",
            target=record["id"],
            data={"from": "grace", "to": "durable", "reason": "incorrect source class"},
        )

        report = validate_vault(self.root)
        self.assertFalse(report.valid, report.as_dict())
        self.assertTrue(any("effective retention class" in error for error in report.errors), report.as_dict())

    def test_secret_guard_runs_before_any_object_or_capture_is_written(self) -> None:
        before_objects = list((self.root / "objects").rglob("*"))
        before_captures = list((self.root / "evidence").glob("**/*.json"))
        with self.assertRaises(SecretDetectedError):
            self.vault.ingest(
                b"Authorization: Bearer abcdefghijklmnopqrstuvwxyz123456",
                source_kind="test",
            )
        self.assertEqual(
            [path for path in (self.root / "objects").rglob("*") if path.is_file()],
            [path for path in before_objects if path.is_file()],
        )
        self.assertEqual(list((self.root / "evidence").glob("**/*.json")), before_captures)

    def test_reference_only_rejects_relative_source_uri(self) -> None:
        with self.assertRaisesRegex(ValueError, "absolute URI"):
            self.vault.ingest(
                b"not retained",
                source_kind="web",
                source_uri="relative/page.html",
                retention="reference-only",
            )

    def test_retention_abort_requires_exact_payload_restoration(self) -> None:
        self._use_zero_day_grace()
        record = self.vault.ingest(b"abort restoration proof", retention="grace")
        manager = RetentionManager(self.vault)
        plan = manager.preview()
        transaction_id = new_id()
        self.vault.append_event(
            "retention.apply-prepared",
            actor="human:test",
            target=transaction_id,
            data={"plan": plan["id"], "confirmation": plan["confirmation"], "candidates": plan["candidates"]},
        )
        candidate = plan["candidates"][0]
        self.vault.append_event(
            "payload.evicted",
            actor="human:test",
            target=record["id"],
            data={
                "transaction_id": transaction_id,
                "plan": plan["id"],
                "object": candidate["object"],
                "payload": {"reason": "injected"},
            },
        )
        self.vault.append_event(
            "retention.apply-aborted",
            actor="process:test",
            target=transaction_id,
            data={
                "plan": plan["id"],
                "confirmation": plan["confirmation"],
                "candidates": plan["candidates"],
                "restored": True,
                "restored_evidence": [record["id"]],
            },
        )
        report = validate_vault(self.root)
        self.assertFalse(report.valid, report.as_dict())
        self.assertTrue(any("restoration" in error or "restored" in error for error in report.errors), report.as_dict())

    def test_retention_restore_cannot_downgrade_history_sensitivity(self) -> None:
        self._use_zero_day_grace()
        record = self.vault.ingest(b"sensitivity restoration proof", retention="grace", sensitivity="public")
        manager = RetentionManager(self.vault)
        plan = manager.preview()
        transaction_id = new_id()
        candidate = plan["candidates"][0]
        manifest = {"plan": plan["id"], "confirmation": plan["confirmation"], "candidates": plan["candidates"]}
        self.vault.append_event("retention.apply-prepared", actor="human:test", target=transaction_id, data=manifest)
        self.vault.append_event(
            "payload.evicted", actor="human:test", target=record["id"], sensitivity="restricted",
            data={"transaction_id": transaction_id, "plan": plan["id"], "object": candidate["object"], "payload": {}},
        )
        self.vault.append_event(
            "payload.restored", actor="process:test", target=record["id"], sensitivity="public",
            data={"transaction_id": transaction_id, "plan": plan["id"], "object": candidate["object"], "payload": {}},
        )
        self.vault.append_event(
            "retention.apply-aborted", actor="process:test", target=transaction_id,
            data={**manifest, "restored": True, "restored_evidence": [record["id"]]},
        )
        report = validate_vault(self.root)
        self.assertFalse(report.valid, report.as_dict())
        self.assertTrue(any("lower retention restoration sensitivity" in error for error in report.errors), report.as_dict())

    def test_multiple_retention_transactions_keep_commit_and_abort_terminals_separate(self) -> None:
        self._use_zero_day_grace()
        first = self.vault.ingest(b"committed transaction", source_kind="screen", retention="grace")
        manager = RetentionManager(self.vault)
        committed_plan = manager.preview()
        manager.apply(
            committed_plan["id"],
            confirmation=committed_plan["confirmation"],
            actor="human:test",
        )

        second = self.vault.ingest(b"aborted transaction", source_kind="screen", retention="grace")
        aborted_plan = manager.preview()
        second_candidate = next(
            candidate for candidate in aborted_plan["candidates"]
            if second["id"] in candidate["evidence"]
        )
        self._append_aborted_retention(aborted_plan, second_candidate)

        report = validate_vault(self.root)
        self.assertTrue(report.valid, report.as_dict())

    def test_multiple_aborted_retention_transactions_do_not_cross_associate(self) -> None:
        self._use_zero_day_grace()
        first = self.vault.ingest(b"first aborted transaction", source_kind="screen", retention="grace")
        manager = RetentionManager(self.vault)
        first_plan = manager.preview()
        first_candidate = next(
            candidate for candidate in first_plan["candidates"]
            if first["id"] in candidate["evidence"]
        )
        self._append_aborted_retention(first_plan, first_candidate)

        second = self.vault.ingest(b"second aborted transaction", source_kind="screen", retention="grace")
        second_plan = manager.preview()
        second_candidate = next(
            candidate for candidate in second_plan["candidates"]
            if second["id"] in candidate["evidence"]
        )
        self._append_aborted_retention(second_plan, second_candidate)

        report = validate_vault(self.root)
        self.assertTrue(report.valid, report.as_dict())

    def test_retention_abort_rejects_restore_before_eviction(self) -> None:
        self._use_zero_day_grace()
        record = self.vault.ingest(b"reverse lifecycle order", source_kind="screen", retention="grace")
        plan = RetentionManager(self.vault).preview()
        candidate = next(item for item in plan["candidates"] if record["id"] in item["evidence"])
        transaction_id = new_id()
        manifest = {
            "plan": plan["id"],
            "confirmation": plan["confirmation"],
            "candidates": [candidate],
        }
        for event_type, data in (
            (
                "retention.apply-prepared",
                manifest,
            ),
            (
                "payload.restored",
                {
                    "transaction_id": transaction_id,
                    "plan": plan["id"],
                    "object": candidate["object"],
                    "payload": {},
                },
            ),
            (
                "payload.evicted",
                {
                    "transaction_id": transaction_id,
                    "plan": plan["id"],
                    "object": candidate["object"],
                    "payload": {},
                },
            ),
            (
                "retention.apply-aborted",
                {
                    **manifest,
                    "restored": True,
                    "restored_evidence": [record["id"]],
                },
            ),
        ):
            target = transaction_id if event_type.startswith("retention.") else record["id"]
            self.vault.append_event(
                event_type,
                actor="process:test",
                target=target,
                sensitivity="personal",
                data=data,
            )

        report = validate_vault(self.root)
        self.assertFalse(report.valid, report.as_dict())
        self.assertTrue(
            any("must follow its corresponding eviction" in error for error in report.errors),
            report.as_dict(),
        )


if __name__ == "__main__":
    unittest.main()
