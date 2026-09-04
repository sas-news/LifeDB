from __future__ import annotations

import json
import os
import shutil
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest import mock

import lifedb.retention as retention_module
from lifedb.retention import RetentionError, RetentionManager, StaleRetentionPreview, _parse_time
from lifedb.evidence import iter_events
from lifedb.storage import DurablePublicationUncertain
from lifedb.validation import validate_vault
from lifedb.vault import Vault
from lifedb.ids import new_id


class RetentionTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name) / "vault"
        self.vault = Vault(self.root)
        self.vault.init()
        policy_path = self.root / "policies" / "retention.json"
        policy = json.loads(policy_path.read_text(encoding="utf-8"))
        policy["grace_days"] = 0
        policy_path.write_text(json.dumps(policy), encoding="utf-8")
        self.manager = RetentionManager(self.vault)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_preview_is_dry_run_and_exact_apply_evicts_without_mutating_capture(self) -> None:
        record = self.vault.ingest(
            b"temporary passive capture", source_kind="screen", retention="grace"
        )
        object_path = self.vault.object_path(record["content"]["sha256"])
        plan = self.manager.preview(now=datetime.now(timezone.utc))
        self.assertEqual([item["object"] for item in plan["candidates"]], [record["payload"]["object"]])
        self.assertTrue(object_path.exists(), "preview must never delete")

        result = self.manager.apply(
            plan["id"], confirmation=plan["confirmation"], actor="human:owner"
        )
        self.assertEqual(result["objects_evicted"], 1)
        self.assertFalse(object_path.exists())
        self.assertEqual(self.vault.load_evidence(record["id"])["payload"]["state"], "present")
        self.assertEqual(self.vault.effective_evidence(record["id"])["payload"]["state"], "evicted")
        report = validate_vault(self.root)
        self.assertTrue(report.valid, report.as_dict())

    def test_lifecycle_history_sensitivity_is_carried_to_retention_events(self) -> None:
        record = self.vault.ingest(
            b"public capture with restricted lifecycle history",
            source_kind="screen",
            retention="grace",
            sensitivity="public",
        )
        representation = self.vault.ingest(
            b"restricted derived representation",
            source_kind="derived",
            retention="durable",
            sensitivity="restricted",
        )
        self.vault.append_event(
            "representation-added",
            actor="extractor:test",
            target=record["id"],
            sensitivity="restricted",
            data={
                "role": "private-derived",
                "object": representation["payload"]["object"],
                "media_type": "text/plain",
                "created_at": "2026-09-01T00:00:00Z",
                "producer": {"by": "extractor:test", "version": "1"},
            },
        )
        plan = self.manager.preview(now=datetime.now(timezone.utc))
        result = self.manager.apply(
            plan["id"], confirmation=plan["confirmation"], actor="human:owner"
        )
        events = list(iter_events(self.vault, verify=True))
        transaction_events = [
            event for event in events
            if event.get("target") == result["transaction_id"]
            or event.get("data", {}).get("transaction_id") == result["transaction_id"]
        ]
        self.assertTrue(transaction_events)
        self.assertTrue(all(event["sensitivity"] == "restricted" for event in transaction_events))

    def test_uncertain_payload_publication_keeps_quarantine_for_recovery(self) -> None:
        record = self.vault.ingest(b"uncertain payload publication", source_kind="screen", retention="grace")
        object_path = self.vault.object_path(record["content"]["sha256"])
        plan = self.manager.preview(now=datetime.now(timezone.utc))
        original_append = self.vault.append_event
        raised = False

        def append(event_type: str, **kwargs):
            nonlocal raised
            if event_type == "payload.evicted" and not raised:
                raised = True
                raise DurablePublicationUncertain(object_path)
            return original_append(event_type, **kwargs)

        with mock.patch.object(self.vault, "append_event", side_effect=append):
            with self.assertRaises(DurablePublicationUncertain):
                self.manager.apply(plan["id"], confirmation=plan["confirmation"], actor="human:owner")
        self.assertFalse(object_path.exists())
        quarantine = self.root / "quarantine" / "retention"
        self.assertTrue(any(path.is_dir() for path in quarantine.iterdir()))
        self.assertFalse(any(event["event_type"] == "retention.apply-aborted" for event in iter_events(self.vault)))
        recovered = self.manager.recover_interrupted()
        self.assertEqual(len(recovered["recovered"]), 1)
        self.assertTrue(object_path.exists())

    def test_post_rename_parent_fsync_is_durable_uncertain_and_recoverable(self) -> None:
        record = self.vault.ingest(
            b"uncertain rename durability", source_kind="screen", retention="grace"
        )
        object_path = self.vault.object_path(record["content"]["sha256"])
        plan = self.manager.preview(now=datetime.now(timezone.utc))
        original_replace = retention_module.os.replace
        original_fsync_directory = retention_module.fsync_directory
        renamed = False

        def mark_rename(*args, **kwargs):
            nonlocal renamed
            result = original_replace(*args, **kwargs)
            if (
                len(args) >= 2
                and isinstance(args[0], str)
                and isinstance(args[1], str)
                and len(args[0]) == 64
                and len(args[1]) == 64
            ):
                renamed = True
            return result

        def fail_after_rename(path):
            if renamed and isinstance(path, int):
                raise OSError("injected parent fsync failure")
            return original_fsync_directory(path)

        with mock.patch.object(retention_module.os, "replace", side_effect=mark_rename):
            with mock.patch.object(
                retention_module, "fsync_directory", side_effect=fail_after_rename
            ):
                with self.assertRaises(DurablePublicationUncertain):
                    self.manager.apply(
                        plan["id"], confirmation=plan["confirmation"], actor="human:owner"
                    )
        self.assertFalse(object_path.exists())
        self.assertFalse(
            any(event["event_type"] == "retention.apply-aborted" for event in iter_events(self.vault))
        )
        recovered = self.manager.recover_interrupted()
        self.assertEqual(recovered["recovered"], [next(
            event["target"]
            for event in iter_events(self.vault)
            if event["event_type"] == "retention.apply-prepared"
        )])
        self.assertTrue(object_path.exists())

    def test_shared_durable_reference_blocks_grace_eviction(self) -> None:
        grace = self.vault.ingest(b"deduplicated", source_kind="screen", retention="grace")
        self.vault.ingest(b"deduplicated", source_kind="manual", retention="durable")
        plan = self.manager.preview()
        self.assertEqual(plan["candidates"], [])
        blocked = next(item for item in plan["blocked"] if item["object"] == grace["payload"]["object"])
        self.assertTrue(any("durable" in reason for reason in blocked["reasons"]))

    def test_explicit_class_change_is_append_only_and_projects_change_time(self) -> None:
        record = self.vault.ingest(b"change class", source_kind="screen", retention="durable")
        capture_before = self.vault.load_evidence(record["id"])
        event = self.manager.change(
            record["id"], "grace", actor="human:owner", reason="reviewed for expiry"
        )

        self.assertEqual(event["event_type"], "retention.changed")
        self.assertEqual(
            event["data"],
            {"from": "durable", "to": "grace", "reason": "reviewed for expiry"},
        )
        effective = self.vault.effective_evidence(record["id"])
        assert effective is not None
        self.assertEqual(effective["payload"]["retention"], "grace")
        self.assertEqual(effective["payload"]["changed_at"], event["recorded_at"])
        self.assertEqual(self.vault.load_evidence(record["id"]), capture_before)
        self.assertEqual(len(self.manager.preview()["candidates"]), 1)

    def test_class_change_uses_effective_current_class_and_rejects_reference_only(self) -> None:
        record = self.vault.ingest(b"multiple changes", retention="durable")
        self.manager.change(record["id"], "grace", actor="human:owner", reason="first")
        self.manager.change(record["id"], "derivative-only", actor="human:owner", reason="second")
        effective = self.vault.effective_evidence(record["id"])
        assert effective is not None
        self.assertEqual(effective["payload"]["retention"], "derivative-only")

        external = self.vault.ingest(
            b"external", source_uri="https://example.invalid/item", retention="reference-only"
        )
        with self.assertRaises(RetentionError):
            self.manager.change(external["id"], "grace", actor="human:owner", reason="convert")

    def test_policy_holds_reject_malformed_references(self) -> None:
        policy_path = self.root / "policies" / "retention.json"
        policy = json.loads(policy_path.read_text(encoding="utf-8"))
        policy["holds"] = {"evidence": ["not-an-evidence-id"], "objects": []}
        policy_path.write_text(json.dumps(policy), encoding="utf-8")
        with self.assertRaises(RetentionError):
            self.manager.preview()

        policy["holds"] = {"evidence": [], "objects": ["sha256:BAD"]}
        policy_path.write_text(json.dumps(policy), encoding="utf-8")
        with self.assertRaises(RetentionError):
            self.manager.preview()

    def test_derivative_only_requires_a_retained_representation(self) -> None:
        record = self.vault.ingest(
            b"raw image", source_kind="web", retention="derivative-only", media_type="image/png"
        )
        plan = self.manager.preview()
        self.assertEqual(plan["candidates"], [])

        digest, _ = self.vault.store_object(b"description")
        self.vault.append_event(
            "representation.added",
            actor="process:test",
            target=record["id"],
            data={
                "role": "visual-description",
                "object": f"sha256:{digest}",
                "media_type": "text/plain",
                "created_at": "2026-09-01T00:00:00Z",
                "producer": {"by": "process:test", "version": "1"},
            },
        )
        plan = self.manager.preview()
        self.assertEqual(len(plan["candidates"]), 1)

    def test_apply_fails_closed_when_preview_is_stale(self) -> None:
        self.vault.ingest(b"temporary", source_kind="screen", retention="grace")
        plan = self.manager.preview()
        self.vault.append_event("audit.changed", actor="process:test", data={})
        with self.assertRaises(StaleRetentionPreview):
            self.manager.apply(
                plan["id"], confirmation=plan["confirmation"], actor="human:owner"
            )

    def test_confirmation_must_match_exact_preview(self) -> None:
        plan = self.manager.preview()
        with self.assertRaisesRegex(Exception, "confirmation"):
            self.manager.apply(plan["id"], confirmation="sha256:" + "0" * 64, actor="human:owner")

    def test_recovery_restores_a_prepared_only_quarantined_object(self) -> None:
        record = self.vault.ingest(b"recover me", source_kind="screen", retention="grace")
        plan = self.manager.preview()
        transaction_id = new_id()
        self.vault.append_event(
            "retention.apply-prepared",
            actor="human:owner",
            target=transaction_id,
            data={
                "plan": plan["id"],
                "confirmation": plan["confirmation"],
                "candidates": plan["candidates"],
            },
        )
        digest = record["content"]["sha256"]
        source = self.vault.object_path(digest)
        quarantined = self.root / "quarantine" / "retention" / transaction_id / digest
        quarantined.parent.mkdir(parents=True, exist_ok=True)
        os.replace(source, quarantined)

        result = self.manager.recover_interrupted()
        self.assertEqual(result["recovered"], [transaction_id])
        self.assertTrue(source.exists())
        self.assertFalse(quarantined.exists())
        self.assertEqual(self.vault.effective_evidence(record["id"])["payload"]["state"], "present")

    def test_recovery_uses_durable_manifest_after_runtime_reset(self) -> None:
        record = self.vault.ingest(b"runtime reset recovery", source_kind="screen", retention="grace")
        plan = self.manager.preview()
        transaction_id = new_id()
        self.vault.append_event(
            "retention.apply-prepared",
            actor="human:owner",
            target=transaction_id,
            data={
                "plan": plan["id"],
                "confirmation": plan["confirmation"],
                "candidates": plan["candidates"],
            },
        )
        digest = record["content"]["sha256"]
        source = self.vault.object_path(digest)
        quarantined = self.root / "quarantine" / "retention" / transaction_id / digest
        quarantined.parent.mkdir(parents=True, exist_ok=True)
        os.replace(source, quarantined)
        self.vault.append_event(
            "payload.evicted",
            actor="human:owner",
            target=record["id"],
            data={
                "transaction_id": transaction_id,
                "plan": plan["id"],
                "object": f"sha256:{digest}",
                "payload": {"reason": "interrupted test"},
            },
        )

        # Both the preview and the entire disposable runtime may disappear
        # before the next process starts.  The signed prepared event remains
        # the recovery authority and must be sufficient by itself.
        (self.root / "runtime" / "retention" / f"{plan['id']}.json").unlink()
        shutil.rmtree(self.root / "runtime")

        result = self.manager.recover_interrupted()
        self.assertEqual(result["recovered"], [transaction_id])
        self.assertTrue(source.exists())
        self.assertFalse(quarantined.exists())
        self.assertEqual(self.vault.effective_evidence(record["id"])["payload"]["state"], "present")
        events = list(iter_events(self.vault, verify=True))
        self.assertTrue(any(
            event["event_type"] == "payload.restored" and event.get("target") == record["id"]
            for event in events
        ))
        self.assertTrue(any(
            event["event_type"] == "retention.apply-aborted" and event.get("target") == transaction_id
            for event in events
        ))
        self.assertEqual(self.manager.recover_interrupted()["recovered"], [])

    def test_recovery_cleans_committed_residue_without_runtime_plan(self) -> None:
        record = self.vault.ingest(b"committed residue cleanup", source_kind="screen", retention="grace")
        plan = self.manager.preview()
        transaction_id = new_id()
        manifest = {
            "plan": plan["id"],
            "confirmation": plan["confirmation"],
            "candidates": plan["candidates"],
        }
        self.vault.append_event(
            "retention.apply-prepared", actor="human:owner", target=transaction_id, data=manifest
        )
        digest = record["content"]["sha256"]
        source = self.vault.object_path(digest)
        quarantined = self.root / "quarantine" / "retention" / transaction_id / digest
        quarantined.parent.mkdir(parents=True, exist_ok=True)
        os.replace(source, quarantined)
        self.vault.append_event(
            "payload.evicted",
            actor="human:owner",
            target=record["id"],
            data={
                "transaction_id": transaction_id,
                "plan": plan["id"],
                "object": f"sha256:{digest}",
                "payload": {"reason": "test"},
            },
        )
        self.vault.append_event(
            "retention.apply-committed",
            actor="human:owner",
            target=transaction_id,
            data={**manifest, "freed_bytes": plan["estimated_bytes"]},
        )
        (self.root / "runtime" / "retention" / f"{plan['id']}.json").unlink()

        result = self.manager.recover_interrupted()
        self.assertEqual(result["cleaned"], [transaction_id])
        self.assertFalse(quarantined.exists())
        self.assertFalse(source.exists())

    def test_recovery_requires_exact_plan_confirmation(self) -> None:
        record = self.vault.ingest(b"missing confirmation", source_kind="screen", retention="grace")
        plan = self.manager.preview()
        transaction_id = new_id()
        self.vault.append_event(
            "retention.apply-prepared",
            actor="human:owner",
            target=transaction_id,
            data={"plan": plan["id"], "candidates": plan["candidates"]},
        )
        digest = record["content"]["sha256"]
        source = self.vault.object_path(digest)
        quarantined = self.root / "quarantine" / "retention" / transaction_id / digest
        quarantined.parent.mkdir(parents=True, exist_ok=True)
        os.replace(source, quarantined)

        result = self.manager.recover_interrupted()
        self.assertEqual(result["unresolved"], [transaction_id])
        # Missing/incorrect confirmation is ambiguous: recovery must not
        # rename either copy or append a terminal event.
        self.assertFalse(source.exists())
        self.assertTrue(quarantined.exists())
        self.assertFalse(
            any(
                event["event_type"] == "retention.apply-aborted"
                and event.get("target") == transaction_id
                for event in iter_events(self.vault)
            )
        )

    def test_preview_rejects_runtime_aliases_without_external_writes(self) -> None:
        outside = Path(self.temporary.name) / "outside-runtime"
        outside.mkdir()
        runtime = self.root / "runtime"
        saved_runtime = Path(self.temporary.name) / "runtime-saved"
        runtime.rename(saved_runtime)
        runtime.symlink_to(outside, target_is_directory=True)
        with self.assertRaises(RetentionError):
            self.manager.preview()
        self.assertEqual(list(outside.iterdir()), [])

    def test_runtime_parent_swap_cannot_redirect_retention_writes(self) -> None:
        outside = Path(self.temporary.name) / "outside-runtime-swap"
        outside.mkdir()
        runtime = self.root / "runtime"
        saved_runtime = Path(self.temporary.name) / "runtime-swap-saved"
        original_open = retention_module._open_fixed_directory
        swapped = False

        def open_then_swap(path: Path, **kwargs):
            nonlocal swapped
            descriptor = original_open(path, **kwargs)
            if path == runtime and not swapped:
                swapped = True
                runtime.rename(saved_runtime)
                runtime.symlink_to(outside, target_is_directory=True)
            return descriptor

        with mock.patch.object(retention_module, "_open_fixed_directory", side_effect=open_then_swap):
            with self.assertRaises(RetentionError):
                self.manager.preview()
        self.assertEqual(list(outside.iterdir()), [])

    def test_preview_rejects_retention_directory_alias_without_external_writes(self) -> None:
        outside = Path(self.temporary.name) / "outside-retention"
        outside.mkdir()
        retention_dir = self.root / "runtime" / "retention"
        retention_dir.symlink_to(outside, target_is_directory=True)
        with self.assertRaises(RetentionError):
            self.manager.preview()
        self.assertEqual(list(outside.iterdir()), [])

    def test_retention_time_parser_requires_strict_rfc3339(self) -> None:
        self.assertIsNotNone(_parse_time("2026-09-02T12:34:56Z"))
        self.assertIsNotNone(_parse_time("2026-09-02T12:34:56.123456+09:00"))
        for malformed in (
            "",
            "2026-09-02 12:34:56Z",
            "2026-09-02T12:34:56",
            "2026-09-02t12:34:56Z",
            "2026-09-02T12:34:56+99:00",
        ):
            with self.subTest(value=malformed):
                self.assertIsNone(_parse_time(malformed))

    def test_recovery_does_not_restore_for_mismatched_eviction_manifest(self) -> None:
        record = self.vault.ingest(b"mismatched eviction", source_kind="screen", retention="grace")
        plan = self.manager.preview()
        transaction_id = new_id()
        self.vault.append_event(
            "retention.apply-prepared",
            actor="human:owner",
            target=transaction_id,
            data={
                "plan": plan["id"],
                "confirmation": plan["confirmation"],
                "candidates": plan["candidates"],
            },
        )
        digest = record["content"]["sha256"]
        source = self.vault.object_path(digest)
        quarantined = self.root / "quarantine" / "retention" / transaction_id / digest
        quarantined.parent.mkdir(parents=True, exist_ok=True)
        os.replace(source, quarantined)
        self.vault.append_event(
            "payload.evicted",
            actor="human:owner",
            target=record["id"],
            data={
                "transaction_id": transaction_id,
                "plan": plan["id"],
                "object": "sha256:" + "0" * 64,
                "payload": {"reason": "mismatched manifest"},
            },
        )

        result = self.manager.recover_interrupted()
        self.assertEqual(result["recovered"], [transaction_id])
        self.assertTrue(source.exists())
        effective = self.vault.effective_evidence(record["id"])
        assert effective is not None
        self.assertEqual(effective["payload"]["state"], "evicted")

    def test_preview_blocks_corrupt_raw_and_corrupt_derivative(self) -> None:
        raw = self.vault.ingest(b"raw image", source_kind="web", retention="derivative-only")
        derivative_digest, derivative_path = self.vault.store_object(b"description")
        self.vault.append_event(
            "representation.added", actor="process:test", target=raw["id"], data={
                "role": "caption", "object": f"sha256:{derivative_digest}"
            }
        )
        derivative_path.chmod(0o600)
        derivative_path.write_bytes(b"corrupt")
        raw_path = self.vault.object_path(raw["content"]["sha256"])
        raw_path.chmod(0o600)
        raw_path.write_bytes(b"corrupt raw")
        plan = self.manager.preview()
        blocked = next(item for item in plan["blocked"] if item["object"] == raw["payload"]["object"])
        self.assertTrue(any("digest" in reason or "invalid" in reason for reason in blocked["reasons"]))

    def test_recovery_reports_both_missing_without_guessing(self) -> None:
        record = self.vault.ingest(b"both missing", retention="grace")
        plan = self.manager.preview()
        transaction_id = new_id()
        self.vault.append_event(
            "retention.apply-prepared", actor="human:owner", target=transaction_id,
            data={
                "plan": plan["id"],
                "confirmation": plan["confirmation"],
                "candidates": plan["candidates"],
            },
        )
        self.vault.object_path(record["content"]["sha256"]).unlink()
        result = self.manager.recover_interrupted()
        self.assertEqual(result["unresolved"], [transaction_id])
        self.assertFalse(any(event["event_type"] == "retention.apply-aborted" for event in iter_events(self.vault)))

    def test_recovery_rejects_duplicate_prepare_and_duplicate_terminal(self) -> None:
        record = self.vault.ingest(b"duplicate manifest", retention="grace")
        plan = self.manager.preview()
        transaction_id = new_id()
        prepared_data = {
            "plan": plan["id"], "confirmation": plan["confirmation"],
            "candidates": plan["candidates"],
        }
        self.vault.append_event("retention.apply-prepared", actor="human:owner", target=transaction_id, data=prepared_data)
        self.vault.append_event("retention.apply-prepared", actor="human:owner", target=transaction_id, data=prepared_data)
        result = self.manager.recover_interrupted()
        self.assertEqual(result["unresolved"], [transaction_id])

        terminal_id = new_id()
        self.vault.append_event("retention.apply-prepared", actor="human:owner", target=terminal_id, data=prepared_data)
        committed_data = {
            "plan": plan["id"], "confirmation": prepared_data["confirmation"],
            "candidates": plan["candidates"], "freed_bytes": plan["estimated_bytes"],
        }
        self.vault.append_event("retention.apply-committed", actor="human:owner", target=terminal_id, data=committed_data)
        self.vault.append_event("retention.apply-committed", actor="human:owner", target=terminal_id, data=committed_data)
        result = self.manager.recover_interrupted()
        self.assertIn(terminal_id, result["unresolved"])

    def test_recovery_validates_both_copies_and_is_idempotent(self) -> None:
        record = self.vault.ingest(b"both copies", retention="grace")
        plan = self.manager.preview()
        transaction_id = new_id()
        self.vault.append_event(
            "retention.apply-prepared", actor="human:owner", target=transaction_id,
            data={
                "plan": plan["id"],
                "confirmation": plan["confirmation"],
                "candidates": plan["candidates"],
            },
        )
        digest = record["content"]["sha256"]
        quarantine = self.root / "quarantine" / "retention" / transaction_id / digest
        quarantine.parent.mkdir(parents=True)
        shutil.copyfile(self.vault.object_path(digest), quarantine)
        result = self.manager.recover_interrupted()
        self.assertEqual(result["recovered"], [transaction_id])
        self.assertTrue(self.vault.object_path(digest).exists())
        self.assertFalse(quarantine.exists())
        self.assertEqual(self.manager.recover_interrupted()["recovered"], [])

    def test_recovery_rejects_symlink_quarantine(self) -> None:
        record = self.vault.ingest(b"symlink quarantine", retention="grace")
        plan = self.manager.preview()
        transaction_id = new_id()
        self.vault.append_event(
            "retention.apply-prepared", actor="human:owner", target=transaction_id,
            data={
                "plan": plan["id"],
                "confirmation": plan["confirmation"],
                "candidates": plan["candidates"],
            },
        )
        quarantine_parent = self.root / "quarantine" / "retention"
        quarantine_parent.mkdir(parents=True, exist_ok=True)
        outside = Path(self.temporary.name) / "outside"
        outside.mkdir()
        os.symlink(outside, quarantine_parent / transaction_id)
        result = self.manager.recover_interrupted()
        self.assertEqual(result["unresolved"], [transaction_id])
        self.assertTrue(self.vault.object_path(record["content"]["sha256"]).exists())

    def test_recovery_rejects_unlisted_quarantine_entries_without_touching_them(self) -> None:
        record = self.vault.ingest(b"manifest extra", retention="grace")
        plan = self.manager.preview()
        transaction_id = new_id()
        self.vault.append_event(
            "retention.apply-prepared", actor="human:owner", target=transaction_id,
            data={
                "plan": plan["id"],
                "confirmation": plan["confirmation"],
                "candidates": plan["candidates"],
            },
        )
        digest = record["content"]["sha256"]
        source = self.vault.object_path(digest)
        quarantine_root = self.root / "quarantine" / "retention" / transaction_id
        quarantine_root.mkdir(parents=True, exist_ok=True)
        os.replace(source, quarantine_root / digest)
        extra = quarantine_root / ("f" * 64)
        extra.write_bytes(b"unlisted")

        result = self.manager.recover_interrupted()
        self.assertEqual(result["unresolved"], [transaction_id])
        self.assertFalse(source.exists())
        self.assertTrue((quarantine_root / digest).exists())
        self.assertTrue(extra.exists())

    def test_recovery_refuses_parent_symlink_before_compensation(self) -> None:
        record = self.vault.ingest(b"parent alias", retention="grace")
        plan = self.manager.preview()
        transaction_id = new_id()
        self.vault.append_event(
            "retention.apply-prepared", actor="human:owner", target=transaction_id,
            data={
                "plan": plan["id"],
                "confirmation": plan["confirmation"],
                "candidates": plan["candidates"],
            },
        )
        digest = record["content"]["sha256"]
        source = self.vault.object_path(digest)
        quarantine = self.root / "quarantine" / "retention" / transaction_id / digest
        quarantine.parent.mkdir(parents=True, exist_ok=True)
        os.replace(source, quarantine)

        object_prefix = self.root / "objects" / "sha256" / digest[:2]
        (object_prefix / digest[2:4]).rmdir()
        object_prefix.rmdir()
        outside = Path(self.temporary.name) / "outside-object-parent"
        outside.mkdir()
        object_prefix.symlink_to(outside, target_is_directory=True)
        result = self.manager.recover_interrupted()
        self.assertEqual(result["unresolved"], [transaction_id])
        self.assertFalse((outside / digest[2:4] / digest).exists())
        self.assertTrue(quarantine.exists())

    def test_commit_append_failure_is_compensated_and_terminal(self) -> None:
        record = self.vault.ingest(b"commit append failure", retention="grace")
        plan = self.manager.preview()
        original_append = self.vault.append_event

        def fail_commit(event_type: str, *args, **kwargs):
            if event_type == "retention.apply-committed":
                raise OSError("injected commit append failure")
            return original_append(event_type, *args, **kwargs)

        with mock.patch.object(self.vault, "append_event", side_effect=fail_commit):
            with self.assertRaisesRegex(RetentionError, "compensated"):
                self.manager.apply(
                    plan["id"], confirmation=plan["confirmation"], actor="human:owner"
                )

        digest = record["content"]["sha256"]
        self.assertTrue(self.vault.object_path(digest).exists())
        self.assertFalse(
            any((self.root / "quarantine" / "retention").rglob(digest))
        )
        effective = self.vault.effective_evidence(record["id"])
        assert effective is not None
        self.assertEqual(effective["payload"]["state"], "present")
        self.assertTrue(
            any(event["event_type"] == "retention.apply-aborted" for event in iter_events(self.vault))
        )
        self.assertEqual(self.manager.recover_interrupted()["unresolved"], [])

    def test_post_rename_failure_is_tracked_and_compensated(self) -> None:
        record = self.vault.ingest(b"post rename failure", retention="grace")
        plan = self.manager.preview()
        original_digest = retention_module._streaming_digest
        calls = 0

        def fail_after_rename(*args, **kwargs):
            nonlocal calls
            calls += 1
            # apply() rechecks the plan (1), validates source before rename
            # (2), then validates the quarantine destination (3).
            if calls == 3:
                raise RetentionError("injected post-rename verification failure")
            return original_digest(*args, **kwargs)

        with mock.patch("lifedb.retention._streaming_digest", side_effect=fail_after_rename):
            with self.assertRaisesRegex(RetentionError, "compensated"):
                self.manager.apply(
                    plan["id"], confirmation=plan["confirmation"], actor="human:owner"
                )

        digest = record["content"]["sha256"]
        self.assertTrue(self.vault.object_path(digest).exists())
        effective = self.vault.effective_evidence(record["id"])
        assert effective is not None
        self.assertEqual(effective["payload"]["state"], "present")
        self.assertEqual(self.manager.recover_interrupted()["unresolved"], [])

    def test_incomplete_compensation_keeps_prepared_transaction_recoverable(self) -> None:
        record = self.vault.ingest(b"incomplete compensation", retention="grace")
        plan = self.manager.preview()
        original_digest = retention_module._streaming_digest
        calls = 0

        def fail_twice(*args, **kwargs):
            nonlocal calls
            calls += 1
            # Fail post-rename verification and the first compensation read.
            if calls in {3, 4}:
                raise RetentionError("injected repeated digest failure")
            return original_digest(*args, **kwargs)

        with mock.patch("lifedb.retention._streaming_digest", side_effect=fail_twice):
            with self.assertRaisesRegex(RetentionError, "recovery is required"):
                self.manager.apply(
                    plan["id"], confirmation=plan["confirmation"], actor="human:owner"
                )

        digest = record["content"]["sha256"]
        self.assertFalse(self.vault.object_path(digest).exists())
        self.assertFalse(
            any(event["event_type"] == "retention.apply-aborted" for event in iter_events(self.vault))
        )
        recovered = self.manager.recover_interrupted()
        self.assertEqual(len(recovered["recovered"]), 1)
        self.assertTrue(self.vault.object_path(digest).exists())


if __name__ == "__main__":
    unittest.main()
