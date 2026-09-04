from __future__ import annotations

import json
import shutil
import tempfile
import unittest
from pathlib import Path

from lifedb.context import build_context
from lifedb.ids import is_uuid7, new_id
from lifedb.index import rebuild_index, search
from lifedb.validation import validate_vault
from lifedb.vault import Vault


class LifeDBRecoveryTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name) / "vault"
        self.vault = Vault(self.root)
        self.metadata = self.vault.init()

    def tearDown(self):
        self.temporary.cleanup()

    def test_uuid7(self):
        value = new_id()
        self.assertTrue(is_uuid7(value))
        self.assertEqual(value[14], "7")

    def test_ingest_validate_rebuild_and_recover(self):
        record = self.vault.ingest(
            "LifeDBはデータベースが消えても復旧できる。".encode(),
            source_kind="test",
            media_type="text/plain",
            filename="memory.txt",
            retention="durable",
        )
        self.assertTrue(is_uuid7(record["id"]))
        first_report = validate_vault(self.root)
        self.assertTrue(first_report.valid, first_report.as_dict())

        first = rebuild_index(self.vault)
        self.assertEqual(first["evidence"], 1)
        results = search(self.vault, "復旧")
        self.assertTrue(any(item["source_id"] == record["id"] for item in results))

        shutil.rmtree(self.root / "runtime")
        self.assertFalse(self.vault.index_path.exists())
        second = rebuild_index(self.vault)
        self.assertEqual(second["evidence"], 1)
        recovered = search(self.vault, "復旧")
        self.assertTrue(any(item["source_id"] == record["id"] for item in recovered))

    def test_context_always_contains_core(self):
        rebuild_index(self.vault)
        pack = build_context(self.vault, "unrelated query", client="test")
        self.assertTrue(pack["core"])
        self.assertIn("LifeDB memory contract", pack["rendered_markdown"])
        self.assertTrue(is_uuid7(pack["id"]))

    def test_objects_are_deduplicated(self):
        one = self.vault.ingest(b"same bytes", source_kind="test", filename="one")
        two = self.vault.ingest(b"same bytes", source_kind="test", filename="two")
        self.assertEqual(one["content"]["sha256"], two["content"]["sha256"])
        objects = [path for path in (self.root / "objects" / "sha256").rglob("*") if path.is_file()]
        self.assertEqual(len(objects), 1)

    def test_evidence_is_written_as_sealed_json(self):
        record = self.vault.ingest(b"evidence", source_kind="test")
        paths = list((self.root / "evidence").rglob(f"{record['id']}.json"))
        self.assertEqual(len(paths), 1)
        stored = json.loads(paths[0].read_text(encoding="utf-8"))
        self.assertIs(stored["sealed"], True)


if __name__ == "__main__":
    unittest.main()
