from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from lifedb.schema_validation import SCHEMA_FILES, schema_errors, schema_path
from lifedb.vault import Vault


class SchemaInstallationTest(unittest.TestCase):
    def test_init_installs_every_authoritative_schema_without_overwriting_flat_legacy(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "vault"
            legacy = root / "schemas" / "context-pack.schema.json"
            legacy.parent.mkdir(parents=True)
            legacy.write_text('{"legacy":true}\n', encoding="utf-8")

            Vault(root).init()

            source_root = Path(__file__).resolve().parents[1] / "schemas"
            for kind, filename in SCHEMA_FILES.items():
                installed = root / "schemas" / "0.2" / filename
                self.assertTrue(installed.is_file(), (kind, installed))
                self.assertEqual(installed.read_bytes(), (source_root / filename).read_bytes())
            self.assertEqual(legacy.read_text(encoding="utf-8"), '{"legacy":true}\n')
            self.assertEqual(
                schema_path("context", root),
                root / "schemas" / "0.2" / "context-pack.schema.json",
            )

    def test_vault_schema_lookup_does_not_fallback_when_authoritative_copy_is_missing(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "vault"
            Vault(root).init()
            (root / "schemas" / "0.2" / "context-pack.schema.json").unlink()
            with self.assertRaises(FileNotFoundError):
                schema_path("context", root)

    def test_canon_schema_requires_nonempty_validity_and_strict_rfc3339(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "vault"
            Vault(root).init()
            document = {
                "type": "Profile",
                "x-lifedb": {
                    "schema": "0.2",
                    "id": "01900000-0000-7000-8000-000000000000",
                    "sensitivity": "personal",
                    "claims": [],
                },
            }
            self.assertEqual(schema_errors("canon", document, vault_root=root), [])
            document["x-lifedb"]["claims"] = [
                {
                    "id": "01900000-0000-7000-8000-000000000001",
                    "subject": "01900000-0000-7000-8000-000000000000",
                    "predicate": "lifedb.test",
                    "object": {"text": "x"},
                    "statement": "x",
                    "basis": "declared",
                    "certainty": "confirmed",
                    "state": "active",
                    "observed_at": "2026-01-01 00:00:00+00:00",
                    "valid": {},
                    "evidence": ["01900000-0000-7000-8000-000000000002"],
                }
            ]
            errors = schema_errors("canon", document, vault_root=root)
            self.assertTrue(any("valid" in error for error in errors))
            self.assertTrue(any("observed_at" in error for error in errors))

    def test_canon_okf_actor_event_requirements_are_split(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "vault"
            Vault(root).init()
            base = {
                "type": "Profile",
                "x-lifedb": {
                    "schema": "0.2",
                    "id": "01900000-0000-7000-8000-000000000000",
                    "sensitivity": "personal",
                    "claims": [],
                },
            }

            generated_without_at = {**base, "generated": {"by": "tool"}}
            self.assertEqual(schema_errors("canon", generated_without_at, vault_root=root), [])

            verified_without_at = {**base, "verified": {"by": "reviewer"}}
            self.assertTrue(schema_errors("canon", verified_without_at, vault_root=root))

            verified_list_without_at = {
                **base,
                "verified": [
                    {"by": "reviewer", "at": "2026-01-01T00:00:00Z"},
                    {"by": "second-reviewer"},
                ],
            }
            self.assertTrue(schema_errors("canon", verified_list_without_at, vault_root=root))

            source_without_id = {
                **base,
                "sources": [{"resource": "https://example.test/source"}],
            }
            self.assertEqual(schema_errors("canon", source_without_id, vault_root=root), [])

            source_without_resource = {**base, "sources": [{"title": "missing link"}]}
            self.assertTrue(schema_errors("canon", source_without_resource, vault_root=root))


if __name__ == "__main__":
    unittest.main()
