from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

import yaml

import lifedb.index as index_module
from lifedb.ids import new_id
from lifedb.index import MAX_TEXT_OBJECT_BYTES, _read_text_object, index_watermark, rebuild_index, search
from lifedb.vault import Vault


class IndexV02Test(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name) / "vault"
        self.vault = Vault(self.root)
        self.vault.init()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _write_canon(
        self,
        filename: str,
        *,
        document_id: str | None = None,
        title: str,
        description: str = "",
        tags: list[str] | None = None,
        body: str = "",
        sensitivity: str = "personal",
        claims: list[dict] | None = None,
        document_type: str = "Profile",
    ) -> str:
        semantic_id = document_id or new_id()
        frontmatter = {
            "type": document_type,
            "title": title,
            "description": description,
            "tags": tags or [],
            "status": "stable",
            "x-lifedb": {
                "schema": "0.2",
                "id": semantic_id,
                "kind": "test",
                "sensitivity": sensitivity,
                "claims": claims or [],
            },
        }
        rendered = (
            "---\n"
            + yaml.safe_dump(frontmatter, allow_unicode=True, sort_keys=False)
            + "---\n\n"
            + body
            + "\n"
        )
        path = self.root / "canon" / "self" / filename
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(rendered, encoding="utf-8")
        return semantic_id

    def _metadata(self) -> dict[str, str]:
        connection = sqlite3.connect(self.vault.index_path)
        try:
            return dict(connection.execute("SELECT key, value FROM metadata"))
        finally:
            connection.close()

    def test_rebuild_metadata_watermark_and_dirty_lifecycle(self) -> None:
        self.assertTrue(self.vault.index_dirty_path.exists())
        report = rebuild_index(self.vault)
        self.assertFalse(self.vault.index_dirty_path.exists())
        metadata = self._metadata()
        self.assertEqual(metadata["schema"], "0.2")
        self.assertEqual(metadata["built_at"], report["built_at"])
        self.assertEqual(metadata["durable_sequence"], "0")
        self.assertEqual(metadata["indexed_sequence"], "0")
        self.assertRegex(metadata["source_fingerprint"], r"^[0-9a-f]{64}$")
        self.assertEqual(
            index_watermark(self.vault),
            {"durable_sequence": 0, "indexed_sequence": 0, "dirty": False},
        )

        event = self.vault.append_event(
            "audit-entry",
            actor="process:test",
            data={"note": "events are watermarks, not search documents"},
        )
        self.assertTrue(index_watermark(self.vault)["dirty"])
        results = search(self.vault, "memory")
        self.assertTrue(results)
        self.assertEqual(
            index_watermark(self.vault),
            {
                "durable_sequence": event["sequence"],
                "indexed_sequence": event["sequence"],
                "dirty": False,
            },
        )

    def test_search_rebuilds_after_unmarked_source_fingerprint_change(self) -> None:
        rebuild_index(self.vault)
        previous_fingerprint = self._metadata()["source_fingerprint"]
        semantic_id = self._write_canon(
            "fingerprint.md",
            title="Fingerprint Sentinel",
            body="unmarkedsourceanchor",
            sensitivity="public",
        )
        self.assertFalse(self.vault.index_dirty_path.exists())
        self.assertTrue(index_watermark(self.vault)["dirty"])

        matches = search(self.vault, "unmarkedsourceanchor", sensitivity_ceiling="public")
        self.assertEqual([item["source_id"] for item in matches], [semantic_id])
        self.assertFalse(index_watermark(self.vault)["dirty"])
        self.assertNotEqual(self._metadata()["source_fingerprint"], previous_fingerprint)

    def test_failed_atomic_replace_preserves_old_index_and_dirty_marker(self) -> None:
        rebuild_index(self.vault)
        before = hashlib.sha256(self.vault.index_path.read_bytes()).hexdigest()
        self.vault.mark_index_dirty(reason="test-failure")
        with mock.patch("lifedb.index.os.replace", side_effect=OSError("publish failed")):
            with self.assertRaisesRegex(OSError, "publish failed"):
                rebuild_index(self.vault)
        self.assertEqual(hashlib.sha256(self.vault.index_path.read_bytes()).hexdigest(), before)
        self.assertTrue(self.vault.index_dirty_path.exists())
        self.assertEqual(list((self.root / "runtime").glob("index-*.sqlite3")), [])

    def test_runtime_parent_swap_during_rebuild_fails_closed(self) -> None:
        """A runtime moved after validation must not redirect SQLite output."""
        runtime = self.root / "runtime"
        detached = self.root.parent / "detached-runtime"
        outside = self.root.parent / "outside-runtime"
        outside.mkdir()
        sentinel = outside / "sentinel"
        sentinel.write_text("untouched", encoding="utf-8")
        calls = 0
        original_fingerprint = index_module._source_fingerprint

        def swap_after_first_fingerprint(vault: Vault) -> str:
            nonlocal calls
            value = original_fingerprint(vault)
            calls += 1
            if calls == 1:
                runtime.rename(detached)
                os.symlink(outside, runtime, target_is_directory=True)
            return value

        try:
            with mock.patch.object(
                index_module, "_source_fingerprint", side_effect=swap_after_first_fingerprint
            ), self.assertRaisesRegex(OSError, "runtime"):
                rebuild_index(self.vault)
        finally:
            if runtime.is_symlink():
                runtime.unlink()
            if detached.exists():
                detached.rename(runtime)
        self.assertEqual(sentinel.read_text(encoding="utf-8"), "untouched")
        self.assertFalse((outside / "index.sqlite3").exists())
        self.assertFalse((outside / "index.dirty").exists())

    def test_runtime_symlink_cannot_inject_external_index_or_dirty_marker(self) -> None:
        runtime = self.root / "runtime"
        outside = self.root.parent / "external-runtime"
        outside.mkdir()
        connection = sqlite3.connect(outside / "index.sqlite3")
        try:
            connection.execute("CREATE TABLE metadata (key TEXT, value TEXT)")
            connection.execute("INSERT INTO metadata VALUES ('schema', 'attacker')")
            connection.commit()
        finally:
            connection.close()
        (outside / "index.dirty").write_text("attacker", encoding="utf-8")
        detached = self.root.parent / "runtime-for-symlink-test"
        runtime.rename(detached)
        os.symlink(outside, runtime, target_is_directory=True)
        try:
            self.assertEqual(index_module._read_index_metadata(self.vault), {})
            self.assertTrue(index_module.index_watermark(self.vault)["dirty"])
        finally:
            runtime.unlink()
            detached.rename(runtime)

    def test_search_runtime_symlink_cannot_create_external_writer_lock(self) -> None:
        """The search lock itself must not follow a replaced runtime."""
        runtime = self.root / "runtime"
        outside = self.root.parent / "external-runtime-lock"
        outside.mkdir()
        detached = self.root.parent / "runtime-for-lock-symlink-test"
        runtime.rename(detached)
        os.symlink(outside, runtime, target_is_directory=True)
        try:
            with self.assertRaises(ValueError):
                search(self.vault, "memory")
            self.assertFalse((outside / "locks" / "writer.lock").exists())
        finally:
            runtime.unlink()
            detached.rename(runtime)

    def test_corrupt_gigabyte_sparse_index_is_rebuilt_without_reading_it(self) -> None:
        """Corrupt projection input is rejected by SQLite without byte-copying it."""
        self.vault.ingest(
            b"sparse-index-rebuild-anchor",
            source_kind="test",
            media_type="text/plain",
            sensitivity="public",
        )
        rebuild_index(self.vault)
        with self.vault.index_path.open("r+b") as stream:
            stream.truncate(1024 * 1024 * 1024)
            stream.seek(0)
            stream.write(b"corrupt-index")
        self.assertTrue(index_watermark(self.vault)["dirty"])
        report = rebuild_index(self.vault)
        self.assertEqual(report["evidence"], 1)
        self.assertFalse(index_watermark(self.vault)["dirty"])
        self.assertTrue(
            any(item["source_id"] for item in search(
                self.vault, "sparse-index-rebuild-anchor", sensitivity_ceiling="public"
            ))
        )

    @unittest.skipUnless(
        os.name == "posix" and os.path.isdir("/proc/self/fd"),
        "descriptor-pinned SQLite URI is only available on procfs hosts",
    )
    def test_search_uses_descriptor_pinned_connection_not_runtime_byte_copy(self) -> None:
        self.vault.ingest(
            b"descriptor-pinned-search-anchor",
            source_kind="test",
            media_type="text/plain",
            sensitivity="public",
        )
        rebuild_index(self.vault)
        uris: list[str] = []
        original_uri = index_module._descriptor_sqlite_uri

        def capture_uri(descriptor: int, *, writable: bool) -> str:
            value = original_uri(descriptor, writable=writable)
            uris.append(value)
            return value

        with mock.patch.object(index_module, "_descriptor_sqlite_uri", side_effect=capture_uri) as uri:
            results = search(self.vault, "descriptor-pinned-search-anchor", sensitivity_ceiling="public")
        self.assertTrue(results)
        self.assertTrue(uri.called)
        self.assertIn("/proc/self/fd/", uris[-1])

    def test_canon_structured_fields_effective_sensitivity_and_graph(self) -> None:
        evidence = self.vault.ingest(
            b"claim support",
            source_kind="test",
            media_type="text/plain",
            sensitivity="public",
        )
        target_id = self._write_canon(
            "target.md",
            title="Referenced Concept",
            body="target-only-body",
            sensitivity="public",
        )
        concept_id = new_id()
        text_claim_id = new_id()
        ref_claim_id = new_id()
        claims = [
            {
                "id": text_claim_id,
                "subject": concept_id,
                "predicate": "lifedb.prefers",
                "object": {"text": "hyperfasteditor"},
                "statement": "Chooses the auroraworkflow editor.",
                "basis": "declared",
                "certainty": "confirmed",
                "state": "disputed",
                "observed_at": "2026-09-01T00:00:00Z",
                "evidence": [{"id": evidence["id"], "requires": "record-only"}],
                "sensitivity": "sensitive",
                "supersedes": [],
            },
            {
                "id": ref_claim_id,
                "subject": concept_id,
                "predicate": "lifedb.uses",
                "object": {"ref": target_id},
                "statement": "Uses the referenced concept.",
                "basis": "observed",
                "certainty": "probable",
                "state": "active",
                "observed_at": "2026-09-01T00:00:00Z",
                "evidence": [{"id": evidence["id"], "requires": "raw"}],
                "supersedes": [],
            },
        ]
        self._write_canon(
            "structured.md",
            document_id=concept_id,
            title="CelestialWorkbench",
            description="descriptionanchor",
            tags=["taganchor"],
            body="bodyanchor",
            sensitivity="public",
            claims=claims,
        )
        report = rebuild_index(self.vault)
        self.assertEqual(report["claims"], 2)

        self.assertFalse(
            any(
                item["source_id"] == concept_id
                for item in search(self.vault, "bodyanchor", sensitivity_ceiling="personal")
            )
        )
        for query in (
            "CelestialWorkbench",
            "descriptionanchor",
            "taganchor",
            "bodyanchor",
            "prefers",
            "auroraworkflow",
            "hyperfasteditor",
        ):
            with self.subTest(query=query):
                results = search(self.vault, query, sensitivity_ceiling="sensitive")
                match = next(item for item in results if item["source_id"] == concept_id)
                self.assertEqual(match["sensitivity"], "sensitive")
                self.assertIs(match["untrusted"], True)
                self.assertIsInstance(match["score"], float)

        connection = sqlite3.connect(self.vault.index_path)
        try:
            concept = connection.execute(
                "SELECT id, sensitivity FROM concepts WHERE id = ?", (concept_id,)
            ).fetchone()
            claim_rows = connection.execute(
                "SELECT id, object_type, object_value, sensitivity FROM claims "
                "WHERE concept_id = ? ORDER BY id",
                (concept_id,),
            ).fetchall()
            evidence_edges = connection.execute(
                "SELECT claim_id, evidence_id, requirement FROM claim_evidence "
                "WHERE claim_id IN (?, ?) ORDER BY claim_id",
                (text_claim_id, ref_claim_id),
            ).fetchall()
            ref_edge = connection.execute(
                "SELECT edge_type, target_id, target_kind FROM claim_edges WHERE claim_id = ?",
                (ref_claim_id,),
            ).fetchone()
            body = connection.execute(
                "SELECT body FROM documents WHERE source_kind = 'canon' AND source_id = ?",
                (concept_id,),
            ).fetchone()[0]
        finally:
            connection.close()
        self.assertEqual(concept, (concept_id, "sensitive"))
        self.assertEqual(len(claim_rows), 2)
        self.assertEqual({row[1] for row in claim_rows}, {"text", "ref"})
        self.assertEqual({row[3] for row in claim_rows}, {"public", "sensitive"})
        self.assertEqual(
            {(row[1], row[2]) for row in evidence_edges},
            {(evidence["id"], "record-only"), (evidence["id"], "raw")},
        )
        self.assertEqual(ref_edge, ("object-ref", target_id, "concept"))
        self.assertIn("[claim state=disputed]", body)

    def test_effective_evidence_raw_representations_and_reference_metadata(self) -> None:
        evicted = self.vault.ingest(
            b"evictedrawuniqueneedle",
            source_kind="test",
            media_type="text/plain",
            filename="evicted.txt",
            sensitivity="public",
        )
        representation_digest, _ = self.vault.store_object(b"retainedrepresentationneedle")
        self.vault.append_event(
            "representation-added",
            actor="extractor:test",
            target=evicted["id"],
            data={
                "role": "ocr",
                "object": f"sha256:{representation_digest}",
                "media_type": "application/json",
                "created_at": "2026-09-01T00:00:00Z",
                "producer": {"by": "extractor:test", "version": "1"},
            },
            sensitivity="public",
        )
        self.vault.append_event(
            "payload-evicted",
            actor="process:retention",
            target=evicted["id"],
            data={"reason": "test"},
            sensitivity="public",
        )
        reference = self.vault.ingest(
            b"referencebytesmustnotappear",
            source_kind="web",
            source_uri="https://example.invalid/rare-reference-anchor",
            media_type="application/octet-stream",
            filename="remote.bin",
            retention="reference-only",
            sensitivity="public",
        )
        present_json = self.vault.ingest(
            b'{"presentjsonneedle":true}',
            source_kind="test",
            media_type="application/json",
            sensitivity="public",
        )
        binary = self.vault.ingest(
            b"binaryrawmustnotappear",
            source_kind="test",
            media_type="application/octet-stream",
            sensitivity="public",
        )

        report = rebuild_index(self.vault)
        self.assertEqual(report["evidence"], 4)
        self.assertFalse(
            any(item["source_id"] == evicted["id"] for item in search(self.vault, "evictedrawuniqueneedle"))
        )
        self.assertTrue(
            any(
                item["source_id"] == evicted["id"]
                for item in search(self.vault, "retainedrepresentationneedle", sensitivity_ceiling="public")
            )
        )
        self.assertTrue(
            any(
                item["source_id"] == reference["id"]
                for item in search(self.vault, "rare-reference-anchor", sensitivity_ceiling="public")
            )
        )
        self.assertFalse(
            any(
                item["source_id"] == reference["id"]
                for item in search(self.vault, "referencebytesmustnotappear", sensitivity_ceiling="public")
            )
        )
        self.assertTrue(
            any(
                item["source_id"] == present_json["id"]
                for item in search(self.vault, "presentjsonneedle", sensitivity_ceiling="public")
            )
        )
        self.assertFalse(
            any(
                item["source_id"] == binary["id"]
                for item in search(self.vault, "binaryrawmustnotappear", sensitivity_ceiling="public")
            )
        )

    def test_lifecycle_event_raises_effective_evidence_sensitivity(self) -> None:
        capture = self.vault.ingest(
            b"non-text raw",
            source_kind="test",
            media_type="application/octet-stream",
            sensitivity="public",
        )
        digest, _ = self.vault.store_object(b"restrictedrepresentationanchor")
        self.vault.append_event(
            "representation-added",
            actor="extractor:test",
            target=capture["id"],
            data={
                "role": "caption",
                "object": f"sha256:{digest}",
                "media_type": "text/plain",
                "created_at": "2026-09-01T00:00:00Z",
                "producer": {"by": "extractor:test", "version": "1"},
            },
            sensitivity="restricted",
        )
        rebuild_index(self.vault)

        self.assertFalse(
            any(
                item["source_id"] == capture["id"]
                for item in search(
                    self.vault,
                    "restrictedrepresentationanchor",
                    sensitivity_ceiling="personal",
                )
            )
        )
        authorized = search(
            self.vault,
            "restrictedrepresentationanchor",
            sensitivity_ceiling="restricted",
        )
        match = next(item for item in authorized if item["source_id"] == capture["id"])
        self.assertEqual(match["sensitivity"], "restricted")

    def test_public_representation_cannot_alias_restricted_object(self) -> None:
        restricted = self.vault.ingest(
            b"cross object restricted marker",
            source_kind="test",
            media_type="text/plain",
            sensitivity="restricted",
        )
        public = self.vault.ingest(
            b"public capture metadata",
            source_kind="test",
            media_type="application/octet-stream",
            sensitivity="public",
        )
        self.vault.append_event(
            "representation-added",
            actor="extractor:test",
            target=public["id"],
            data={
                "role": "derived-text",
                "object": restricted["payload"]["object"],
                "media_type": "text/plain",
                "created_at": "2026-09-01T00:00:00Z",
                "producer": {"by": "extractor:test", "version": "1"},
            },
            sensitivity="public",
        )
        rebuild_index(self.vault)

        self.assertFalse(
            any(
                item["source_id"] == public["id"]
                for item in search(
                    self.vault,
                    "cross object restricted marker",
                    sensitivity_ceiling="public",
                )
            )
        )
        authorized = search(
            self.vault,
            "cross object restricted marker",
            sensitivity_ceiling="restricted",
        )
        match = next(item for item in authorized if item["source_id"] == public["id"])
        self.assertEqual(match["sensitivity"], "restricted")

    def test_any_target_event_raises_effective_search_sensitivity(self) -> None:
        record = self.vault.ingest(
            b"generic target event marker",
            source_kind="test",
            media_type="text/plain",
            sensitivity="public",
        )
        self.vault.append_event(
            "audit.noted",
            actor="process:test",
            target=record["id"],
            data={"note": "sensitive audit state"},
            sensitivity="restricted",
        )
        rebuild_index(self.vault)

        self.assertFalse(
            any(
                item["source_id"] == record["id"]
                for item in search(
                    self.vault,
                    "generic target event marker",
                    sensitivity_ceiling="public",
                )
            )
        )
        match = next(
            item
            for item in search(
                self.vault,
                "generic target event marker",
                sensitivity_ceiling="restricted",
            )
            if item["source_id"] == record["id"]
        )
        self.assertEqual(match["sensitivity"], "restricted")

    def test_search_holds_writer_lock_across_watermark_and_query(self) -> None:
        record = self.vault.ingest(
            b"search snapshot marker",
            source_kind="test",
            media_type="text/plain",
            sensitivity="personal",
        )
        rebuild_index(self.vault)
        original_watermark = index_module.index_watermark
        watermark_checked = threading.Event()
        release_watermark = threading.Event()
        writer_started = threading.Event()
        writer_finished = threading.Event()

        def paused_watermark(vault):
            value = original_watermark(vault)
            if not value["dirty"]:
                watermark_checked.set()
                self.assertTrue(release_watermark.wait(2))
            return value

        def append_restricted_event() -> None:
            writer_started.set()
            self.vault.append_event(
                "audit.noted",
                actor="process:test",
                target=record["id"],
                data={},
                sensitivity="restricted",
            )
            writer_finished.set()

        result: list[list[dict]] = []
        with mock.patch.object(index_module, "index_watermark", side_effect=paused_watermark):
            search_thread = threading.Thread(
                target=lambda: result.append(search(self.vault, "search snapshot marker"))
            )
            search_thread.start()
            self.assertTrue(watermark_checked.wait(2))
            writer_thread = threading.Thread(target=append_restricted_event)
            writer_thread.start()
            self.assertTrue(writer_started.wait(2))
            self.assertFalse(writer_finished.wait(0.1))
            release_watermark.set()
            search_thread.join(2)
            writer_thread.join(2)

        self.assertFalse(search_thread.is_alive())
        self.assertFalse(writer_thread.is_alive())
        self.assertEqual([item["source_id"] for item in result[0]], [record["id"]])
        self.assertEqual(result[0][0]["sensitivity"], "personal")
        self.assertTrue(original_watermark(self.vault)["dirty"])

    def test_sql_sensitivity_filter_unknown_labels_and_input_validation(self) -> None:
        restricted_ids = {
            self.vault.ingest(
                b"authorizationneedle",
                source_kind="test",
                media_type="text/plain",
                sensitivity="restricted",
            )["id"]
            for _ in range(5)
        }
        public = self.vault.ingest(
            b"authorizationneedle",
            source_kind="test",
            media_type="text/plain",
            sensitivity="public",
        )
        unknown_document = self._write_canon(
            "unknown.md",
            title="UnknownSensitivityNeedle",
            body="unknownsensitivitybody",
            sensitivity="future-secret-label",
        )
        malformed_document = self._write_canon(
            "malformed.md",
            title="MalformedSensitivityNeedle",
            body="malformedsensitivitybody",
            sensitivity=["future-secret-label"],  # type: ignore[arg-type]
        )
        rebuild_index(self.vault)

        public_results = search(
            self.vault,
            "authorizationneedle",
            limit=1,
            sensitivity_ceiling="public",
        )
        self.assertEqual([item["source_id"] for item in public_results], [public["id"]])
        restricted_results = search(
            self.vault,
            "authorizationneedle",
            limit=10,
            sensitivity_ceiling="restricted",
        )
        self.assertTrue(restricted_ids.issubset({item["source_id"] for item in restricted_results}))
        self.assertFalse(
            any(
                item["source_id"] == unknown_document
                for item in search(
                    self.vault,
                    "UnknownSensitivityNeedle",
                    sensitivity_ceiling="restricted",
                )
            )
        )
        self.assertFalse(
            any(
                item["source_id"] == malformed_document
                for item in search(
                    self.vault,
                    "MalformedSensitivityNeedle",
                    sensitivity_ceiling="restricted",
                )
            )
        )

        invalid_calls = [
            {"query": "", "limit": 1, "sensitivity_ceiling": "public"},
            {"query": "x", "limit": 0, "sensitivity_ceiling": "public"},
            {"query": "x", "limit": 101, "sensitivity_ceiling": "public"},
            {"query": "x", "limit": True, "sensitivity_ceiling": "public"},
            {"query": "x", "limit": 1, "sensitivity_ceiling": "top-secret"},
        ]
        for arguments in invalid_calls:
            with self.subTest(arguments=arguments), self.assertRaises(ValueError):
                search(self.vault, **arguments)

    def test_japanese_bigram_fallback_is_searchable(self) -> None:
        record = self.vault.ingest(
            "AIが記憶ツールを呼ばなくても自動検索する。".encode(),
            source_kind="test",
            media_type="text/plain",
            sensitivity="public",
        )
        rebuild_index(self.vault)
        # The query's Japanese concepts need not be one exact contiguous phrase.
        results = search(self.vault, "記憶の自動検索", sensitivity_ceiling="public")
        self.assertTrue(any(item["source_id"] == record["id"] for item in results))

    def test_superseded_and_retracted_claim_values_are_graph_only(self) -> None:
        evidence = self.vault.ingest(
            b"public claim support",
            source_kind="test",
            media_type="text/plain",
            sensitivity="public",
        )
        concept_id = new_id()
        old_claim_id = new_id()
        retracted_claim_id = new_id()
        current_claim_id = new_id()
        claims = []
        for claim_id, state, value in (
            (old_claim_id, "superseded", "supersededclaimneedle"),
            (retracted_claim_id, "retracted", "retractedclaimneedle"),
            (current_claim_id, "active", "activeclaimneedle"),
        ):
            claims.append(
                {
                    "id": claim_id,
                    "subject": concept_id,
                    "predicate": "lifedb.test-value",
                    "object": {"text": value},
                    "statement": f"Statement {value}",
                    "basis": "declared",
                    "certainty": "confirmed",
                    "state": state,
                    "observed_at": "2026-09-01T00:00:00Z",
                    "sensitivity": "public",
                    "evidence": [{"id": evidence["id"], "requires": "record-only"}],
                }
            )
        self._write_canon(
            "claim-states.md",
            document_id=concept_id,
            title="Claim state sentinel",
            body="claim-state-body",
            sensitivity="public",
            claims=claims,
        )
        rebuild_index(self.vault)

        for query in ("supersededclaimneedle", "retractedclaimneedle"):
            self.assertFalse(
                any(item["source_id"] == concept_id for item in search(self.vault, query))
            )
        self.assertTrue(
            any(item["source_id"] == concept_id for item in search(self.vault, "activeclaimneedle"))
        )
        connection = sqlite3.connect(self.vault.index_path)
        try:
            rows = connection.execute(
                "SELECT id, state FROM claims WHERE concept_id = ? ORDER BY id", (concept_id,)
            ).fetchall()
            body = connection.execute(
                "SELECT body FROM documents WHERE source_id = ?", (concept_id,)
            ).fetchone()[0]
        finally:
            connection.close()
        self.assertEqual({row[0] for row in rows}, {old_claim_id, retracted_claim_id, current_claim_id})
        self.assertNotIn("supersededclaimneedle", body)
        self.assertNotIn("retractedclaimneedle", body)
        self.assertIn("[claim state=active]", body)

    def test_claim_evidence_lifecycle_sensitivity_covers_document_and_claim_rows(self) -> None:
        evidence = self.vault.ingest(
            b"claim evidence bytes",
            source_kind="test",
            media_type="text/plain",
            sensitivity="public",
        )
        self.vault.append_event(
            "retention-changed",
            actor="process:test",
            target=evidence["id"],
            data={"to": "durable"},
            sensitivity="restricted",
        )
        concept_id = new_id()
        claim_id = new_id()
        self._write_canon(
            "evidence-sensitive.md",
            document_id=concept_id,
            title="Evidence sensitivity sentinel",
            body="evidence-sensitive-body",
            sensitivity="personal",
            claims=[
                {
                    "id": claim_id,
                    "subject": concept_id,
                    "predicate": "lifedb.supported-by",
                    "object": {"text": "evidence-sensitive-claim"},
                    "statement": "Evidence sensitive claim",
                    "basis": "observed",
                    "certainty": "confirmed",
                    "state": "active",
                    "observed_at": "2026-09-01T00:00:00Z",
                    "sensitivity": "personal",
                    "evidence": [{"id": evidence["id"], "requires": "record-only"}],
                }
            ],
        )
        rebuild_index(self.vault)
        self.assertFalse(any(item["source_id"] == concept_id for item in search(
            self.vault, "evidence-sensitive-claim", sensitivity_ceiling="personal"
        )))
        match = next(item for item in search(
            self.vault, "evidence-sensitive-claim", sensitivity_ceiling="restricted"
        ) if item["source_id"] == concept_id)
        self.assertEqual(match["sensitivity"], "restricted")
        connection = sqlite3.connect(self.vault.index_path)
        try:
            self.assertEqual(
                connection.execute("SELECT sensitivity FROM concepts WHERE id = ?", (concept_id,)).fetchone()[0],
                "restricted",
            )
            self.assertEqual(
                connection.execute("SELECT sensitivity FROM claims WHERE id = ?", (claim_id,)).fetchone()[0],
                "restricted",
            )
        finally:
            connection.close()

    def test_large_text_object_read_is_bounded(self) -> None:
        digest = "a" * 64
        path = self.vault.object_path(digest)
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("wb") as stream:
            stream.truncate(MAX_TEXT_OBJECT_BYTES * 2)
        text = _read_text_object(self.vault, f"sha256:{digest}")
        self.assertLessEqual(len(text.encode("utf-8")), MAX_TEXT_OBJECT_BYTES)

    def test_malformed_and_duplicate_concepts_are_not_indexed(self) -> None:
        duplicate_id = new_id()
        self._write_canon(
            "duplicate-a.md",
            document_id=duplicate_id,
            title="Duplicate A",
            body="duplicate-a-body",
            sensitivity="public",
        )
        self._write_canon(
            "duplicate-b.md",
            document_id=duplicate_id,
            title="Duplicate B",
            body="duplicate-b-body",
            sensitivity="public",
        )
        invalid_id = self._write_canon(
            "invalid-id.md",
            document_id="not-a-uuid",
            title="Invalid ID",
            body="invalid-id-body",
            sensitivity="public",
        )
        rebuild_index(self.vault)
        connection = sqlite3.connect(self.vault.index_path)
        try:
            count = connection.execute(
                "SELECT count(*) FROM concepts WHERE id = ?", (duplicate_id,)
            ).fetchone()[0]
        finally:
            connection.close()
        self.assertEqual(count, 1)
        self.assertFalse(any(item["source_id"] == invalid_id for item in search(
            self.vault, "invalid-id-body", sensitivity_ceiling="restricted"
        )))


if __name__ == "__main__":
    unittest.main()
