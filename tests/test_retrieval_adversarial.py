from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

import yaml

from lifedb.context import build_context
from lifedb.ids import new_id
from lifedb.index import rebuild_index, search
from lifedb.vault import Vault


class RetrievalAdversarialTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name) / "vault"
        self.vault = Vault(self.root)
        self.vault.init()

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_object_shard_symlink_and_fifo_fail_closed(self) -> None:
        self.vault.ingest(b"index-safe-marker", source_kind="test", media_type="text/plain")
        outside = Path(self.tmp.name) / "outside"
        outside.mkdir()
        (outside / "secret.txt").write_text("external-secret-marker")
        shard = self.root / "objects" / "sha256" / "aa"
        shard.unlink() if shard.is_symlink() else None
        os.symlink(outside, shard)
        with self.assertRaises(OSError) as raised:
            search(self.vault, "external-secret-marker")
        self.assertNotIn("external-secret-marker", str(raised.exception))
        with self.assertRaises(OSError) as raised:
            build_context(self.vault, "external-secret-marker")
        self.assertNotIn("external-secret-marker", str(raised.exception))

    def test_fifo_and_corrupt_object_are_not_read_as_text(self) -> None:
        record = self.vault.ingest(b"corrupt-object-marker", source_kind="test", media_type="text/plain")
        object_path = self.vault.object_path(record["content"]["sha256"])
        object_path.chmod(0o600)
        object_path.write_bytes(b"tampered-object-marker")
        fifo_dir = self.root / "objects" / "sha256" / "ff" / "ff"
        fifo_dir.mkdir(parents=True)
        os.mkfifo(fifo_dir / ("0" * 64))
        with self.assertRaises(OSError):
            rebuild_index(self.vault)

    def test_runtime_index_symlink_is_rejected(self) -> None:
        outside = Path(self.tmp.name) / "outside.sqlite3"
        outside.write_bytes(b"not sqlite")
        index_path = self.root / "runtime" / "index.sqlite3"
        os.symlink(outside, index_path)
        with self.assertRaises(OSError):
            rebuild_index(self.vault)

    def test_invalid_utf8_object_is_not_replaced_into_context(self) -> None:
        record = self.vault.ingest(b"utf8-marker", source_kind="conversation", kind="conversation", media_type="text/plain")
        object_path = self.vault.object_path(record["content"]["sha256"])
        object_path.chmod(0o600)
        object_path.write_bytes(b"\xffexternal-secret-marker")
        pack = build_context(self.vault, "", session=None)
        self.assertNotIn("external-secret-marker", pack["rendered_markdown"])
        self.vault.ingest(
            b"valid-prefix-\xff-malformed-secret-marker", source_kind="conversation",
            source_metadata={"session": "malformed"}, kind="conversation",
            media_type="text/plain",
        )
        pack = build_context(self.vault, "", session="malformed")
        self.assertNotIn("malformed-secret-marker", pack["rendered_markdown"])

    def test_canon_handles_are_active_disputed_and_ceiling_filtered(self) -> None:
        evidence = self.vault.ingest(
            b"handle-evidence-marker", source_kind="test", sensitivity="public",
            media_type="text/plain",
        )
        disputed = self.vault.ingest(b"disputed-evidence-marker", source_kind="test", sensitivity="public", media_type="text/plain")
        old = self.vault.ingest(b"old-evidence-marker", source_kind="test", sensitivity="public", media_type="text/plain")
        retracted = self.vault.ingest(b"retracted-evidence-marker", source_kind="test", sensitivity="public", media_type="text/plain")
        subject = new_id()
        path = self.root / "canon" / "self" / "handles.md"
        path.parent.mkdir(parents=True, exist_ok=True)
        frontmatter = {
            "type": "Project", "title": "Handle marker",
            "status": "stable",
            "x-lifedb": {
                "schema": "0.2", "id": subject, "kind": "test",
                "sensitivity": "public",
                "claims": [
                    {"id": new_id(), "state": "active", "predicate": "has.active",
                     "object": {"text": "a"}, "statement": "a", "evidence": [evidence["id"]]},
                    {"id": new_id(), "state": "disputed", "predicate": "has.disputed",
                     "object": {"text": "b"}, "statement": "b", "evidence": [disputed["id"]]},
                    {"id": new_id(), "state": "superseded", "predicate": "has.old",
                     "object": {"text": "c"}, "statement": "c", "evidence": [old["id"]]},
                    {"id": new_id(), "state": "retracted", "predicate": "has.retracted",
                     "object": {"text": "d"}, "statement": "d", "evidence": [retracted["id"]]},
                ],
            },
        }
        path.write_text("---\n" + yaml.safe_dump(frontmatter, sort_keys=False) + "---\n\ncanon-only-needle\n", encoding="utf-8")
        pack = build_context(self.vault, "canon-only-needle", sensitivity_ceiling="personal")
        canon_items = [item for item in pack["relevant"] + pack["continuity"] if item["source_id"] == subject]
        self.assertTrue(canon_items)
        self.assertEqual(canon_items[0]["evidence_handles"], [evidence["id"], disputed["id"]])
        self.assertTrue({evidence["id"], disputed["id"]}.issubset(pack["evidence_handles"]))
        self.assertNotIn(old["id"], pack["evidence_handles"])
        self.assertNotIn(retracted["id"], pack["evidence_handles"])
        results = search(self.vault, "canon-only-needle", sensitivity_ceiling="personal")
        canon_result = next(item for item in results if item["source_id"] == subject)
        self.assertEqual(canon_result["evidence_handles"], [evidence["id"], disputed["id"]])
        self.vault.append_event("payload-missing-observed", actor="process:test", target=evidence["id"], sensitivity="restricted", data={"reason": "test"})
        self.vault.append_event("payload-missing-observed", actor="process:test", target=disputed["id"], sensitivity="restricted", data={"reason": "test"})
        filtered = build_context(self.vault, "canon-only-needle", sensitivity_ceiling="personal")
        self.assertNotIn(evidence["id"], filtered["evidence_handles"])


if __name__ == "__main__":
    unittest.main()
