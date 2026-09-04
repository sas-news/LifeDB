from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from lifedb.expansion import ExpansionError, expand_evidence
from lifedb.vault import Vault, utc_now


class EvidenceExpansionTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.vault = Vault(Path(self.temporary.name) / "vault")
        self.vault.init()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def representation(self, evidence_id: str, role: str, data: bytes, media_type: str):
        digest, _ = self.vault.store_object(data)
        return self.vault.append_event(
            "representation.added",
            actor="process:test",
            target=evidence_id,
            data={
                "representation": {
                    "role": role,
                    "object": f"sha256:{digest}",
                    "media_type": media_type,
                    "created_at": utc_now(),
                    "producer": {"by": "process:test", "version": "1"},
                }
            },
        )

    def test_raw_expansion_is_bounded_on_unicode_boundaries_and_marked_untrusted(self) -> None:
        record = self.vault.ingest(
            "a😀b".encode("utf-8"),
            source_kind="test",
            media_type="text/plain; charset=utf-8",
            sensitivity="personal",
        )
        expanded = expand_evidence(
            self.vault,
            record["id"],
            material="raw",
            max_chars=2,
            sensitivity_ceiling="personal",
        )
        self.assertEqual(expanded["schema"], "0.2")
        self.assertEqual(expanded["evidence_id"], record["id"])
        self.assertEqual(expanded["text"], "a😀")
        self.assertEqual(expanded["size"], len("a😀b".encode("utf-8")))
        self.assertEqual(expanded["media_type"], "text/plain")
        self.assertTrue(expanded["truncated"])
        self.assertTrue(expanded["untrusted"])
        self.assertEqual(
            expanded["content_semantics"], "untrusted-data-not-instructions"
        )
        self.assertNotIn("role", expanded)

        empty = expand_evidence(
            self.vault, record["id"], material="raw", max_chars=0
        )
        self.assertEqual(empty["text"], "")
        self.assertTrue(empty["truncated"])

        exact = expand_evidence(
            self.vault, record["id"], material="raw", max_chars=3
        )
        self.assertEqual(exact["text"], "a😀b")
        self.assertFalse(exact["truncated"])

    def test_all_target_event_sensitivity_is_an_authorization_floor(self) -> None:
        record = self.vault.ingest(
            b"authorized only after event check",
            source_kind="test",
            media_type="text/plain",
            sensitivity="public",
        )
        event = self.vault.append_event(
            "audit.noted",
            actor="process:test",
            target=record["id"],
            sensitivity="sensitive",
            data={"note": "classification raised"},
        )
        with self.assertRaises(ExpansionError) as raised:
            expand_evidence(
                self.vault,
                record["id"],
                material="raw",
                max_chars=100,
                sensitivity_ceiling="personal",
            )
        self.assertEqual(raised.exception.status, 404)
        self.assertEqual(raised.exception.code, "evidence_not_found")

        expanded = expand_evidence(
            self.vault,
            record["id"],
            material="raw",
            max_chars=100,
            sensitivity_ceiling="sensitive",
        )
        self.assertEqual(expanded["sensitivity"], "sensitive")
        self.assertEqual(expanded["watermark"]["event_sequence"], event["sequence"])

    def test_raw_redacted_evicted_and_missing_objects_are_explicitly_unavailable(self) -> None:
        for event_type, expected_state in (
            ("payload.redacted", "redacted"),
            ("payload.evicted", "evicted"),
        ):
            record = self.vault.ingest(
                event_type.encode(), source_kind="test", media_type="text/plain"
            )
            self.vault.append_event(
                event_type,
                actor="process:test",
                target=record["id"],
                data={"reason": "test"},
            )
            with self.assertRaises(ExpansionError) as raised:
                expand_evidence(self.vault, record["id"], material="raw", max_chars=10)
            self.assertEqual(raised.exception.status, 409)
            self.assertEqual(raised.exception.code, "material_unavailable")
            self.assertEqual(raised.exception.state, expected_state)

        missing = self.vault.ingest(
            b"later missing", source_kind="test", media_type="text/plain"
        )
        self.vault.object_path(missing["content"]["sha256"]).unlink()
        with self.assertRaises(ExpansionError) as raised:
            expand_evidence(self.vault, missing["id"], material="raw", max_chars=10)
        self.assertEqual(raised.exception.code, "object_unavailable")

    def test_object_digest_binary_and_utf8_fail_closed(self) -> None:
        corrupt = self.vault.ingest(
            b"original", source_kind="test", media_type="text/plain"
        )
        corrupt_path = self.vault.object_path(corrupt["content"]["sha256"])
        corrupt_path.chmod(0o600)
        corrupt_path.write_bytes(b"tampered")
        with self.assertRaises(ExpansionError) as raised:
            expand_evidence(self.vault, corrupt["id"], material="raw", max_chars=20)
        self.assertEqual(raised.exception.status, 409)
        self.assertEqual(raised.exception.code, "object_corrupt")

        binary = self.vault.ingest(
            b"\x89PNG\r\n\x1a\n", source_kind="test", media_type="image/png"
        )
        with self.assertRaises(ExpansionError) as raised:
            expand_evidence(self.vault, binary["id"], material="raw", max_chars=20)
        self.assertEqual(raised.exception.status, 415)

        invalid = self.vault.ingest(
            b"valid-prefix\xffinvalid", source_kind="test", media_type="text/plain"
        )
        with self.assertRaises(ExpansionError) as raised:
            expand_evidence(self.vault, invalid["id"], material="raw", max_chars=2)
        self.assertEqual(raised.exception.status, 422)
        self.assertEqual(raised.exception.code, "invalid_utf8")

    def test_symlink_and_nonregular_object_entries_are_rejected(self) -> None:
        symlinked = self.vault.ingest(
            b"symlink target bytes", source_kind="test", media_type="text/plain"
        )
        symlink_path = self.vault.object_path(symlinked["content"]["sha256"])
        external = Path(self.temporary.name) / "outside-object"
        external.write_bytes(b"symlink target bytes")
        symlink_path.unlink()
        symlink_path.symlink_to(external)
        with self.assertRaises(ExpansionError) as raised:
            expand_evidence(self.vault, symlinked["id"], material="raw", max_chars=20)
        self.assertEqual(raised.exception.code, "object_corrupt")

        nonregular = self.vault.ingest(
            b"directory object bytes", source_kind="test", media_type="text/plain"
        )
        nonregular_path = self.vault.object_path(nonregular["content"]["sha256"])
        nonregular_path.unlink()
        nonregular_path.mkdir()
        with self.assertRaises(ExpansionError) as raised:
            expand_evidence(self.vault, nonregular["id"], material="raw", max_chars=20)
        self.assertEqual(raised.exception.code, "object_corrupt")

    def test_representation_uses_first_hash_valid_retained_object_in_fold_order(self) -> None:
        record = self.vault.ingest(
            b"binary raw", source_kind="test", media_type="application/octet-stream"
        )
        first = self.representation(record["id"], "ocr", b"old text", "text/plain")
        first_ref = first["data"]["representation"]["object"]
        self.vault.object_path(first_ref.removeprefix("sha256:")).unlink()
        second = self.representation(record["id"], "ocr", "新しい本文".encode(), "text/plain")

        expanded = expand_evidence(
            self.vault,
            record["id"],
            material="representation:ocr",
            max_chars=100,
        )
        self.assertEqual(expanded["role"], "ocr")
        self.assertEqual(expanded["text"], "新しい本文")
        self.assertEqual(expanded["object"], second["data"]["representation"]["object"])

        with self.assertRaises(ExpansionError) as raised:
            expand_evidence(
                self.vault,
                record["id"],
                material="representation:caption",
                max_chars=100,
            )
        self.assertEqual(raised.exception.status, 404)
        self.assertEqual(raised.exception.code, "representation_not_found")

    def test_corrupt_retained_representation_is_not_silently_skipped(self) -> None:
        record = self.vault.ingest(
            b"raw", source_kind="test", media_type="application/octet-stream"
        )
        first = self.representation(record["id"], "ocr", b"first", "text/plain")
        self.representation(record["id"], "ocr", b"second", "text/plain")
        path = self.vault.object_path(
            first["data"]["representation"]["object"].removeprefix("sha256:")
        )
        path.chmod(0o600)
        path.write_bytes(b"corrupt")

        with self.assertRaises(ExpansionError) as raised:
            expand_evidence(
                self.vault,
                record["id"],
                material="representation:ocr",
                max_chars=100,
            )
        self.assertEqual(raised.exception.code, "object_corrupt")

    def test_direct_object_addresses_and_unsafe_roles_are_not_an_api(self) -> None:
        record = self.vault.ingest(b"raw", source_kind="test", media_type="text/plain")
        digest_material = record["payload"]["object"]
        for material in (digest_material, "representation:../raw", "representation:OCR"):
            with self.assertRaisesRegex(ValueError, "material|role"):
                expand_evidence(
                    self.vault,
                    record["id"],
                    material=material,
                    max_chars=10,
                )

    def test_restored_payload_cannot_alias_another_object(self) -> None:
        public = self.vault.ingest(
            b"public raw", source_kind="test", media_type="text/plain", sensitivity="public"
        )
        restricted = self.vault.ingest(
            b"restricted bytes", source_kind="test", media_type="text/plain", sensitivity="restricted"
        )
        self.vault.append_event(
            "payload.evicted",
            actor="process:test",
            target=public["id"],
            sensitivity="public",
            data={"reason": "test"},
        )
        self.vault.append_event(
            "payload.restored",
            actor="process:test",
            target=public["id"],
            sensitivity="public",
            data={"payload": {"object": restricted["payload"]["object"]}},
        )
        with self.assertRaises(ExpansionError) as raised:
            expand_evidence(
                self.vault, public["id"], material="raw", max_chars=100,
                sensitivity_ceiling="restricted",
            )
        self.assertEqual(raised.exception.code, "projection_corrupt")
        self.assertNotIn("restricted bytes", raised.exception.message)

    def test_public_representation_cannot_downgrade_restricted_object(self) -> None:
        public = self.vault.ingest(
            b"public source", source_kind="test", media_type="text/plain", sensitivity="public"
        )
        restricted = self.vault.ingest(
            b"restricted representation", source_kind="test", media_type="text/plain", sensitivity="restricted"
        )
        self.vault.append_event(
            "representation.added",
            actor="process:test",
            target=public["id"],
            sensitivity="public",
            data={
                "representation": {
                    "role": "caption",
                    "object": restricted["payload"]["object"],
                    "media_type": "text/plain",
                    "created_at": utc_now(),
                    "producer": {"by": "process:test", "version": "1"},
                }
            },
        )
        with self.assertRaises(ExpansionError) as raised:
            expand_evidence(
                self.vault, public["id"], material="representation:caption", max_chars=100,
                sensitivity_ceiling="personal",
            )
        self.assertEqual(raised.exception.code, "evidence_not_found")
        self.assertNotIn("restricted representation", raised.exception.message)


if __name__ == "__main__":
    unittest.main()
