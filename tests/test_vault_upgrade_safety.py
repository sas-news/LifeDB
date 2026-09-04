from __future__ import annotations

import stat
import tempfile
import unittest
from pathlib import Path

from lifedb.schema_validation import schema_path
from lifedb.secrets import SecretDetectedError
from lifedb.vault import (
    DURABLE_TOP_LEVEL,
    MAX_SOURCE_METADATA_BYTES,
    Vault,
    parse_time,
)


class VaultUpgradeSafetyTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name) / "vault"

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_upgrade_prefers_current_versioned_schema_and_keeps_stale_flat_copy(self) -> None:
        (self.root / "schemas").mkdir(parents=True)
        stale = self.root / "schemas" / "evidence-record.schema.json"
        stale.write_text('{"type":"object","required":["legacy"]}\n', encoding="utf-8")

        Vault(self.root).init()

        self.assertEqual(schema_path("capture", self.root), self.root / "schemas" / "0.2" / "evidence-record.schema.json")
        self.assertEqual(stale.read_text(encoding="utf-8"), '{"type":"object","required":["legacy"]}\n')
        self.assertTrue((self.root / "schemas" / "evidence-record.schema.json").is_file())

    def test_init_refuses_symlinked_durable_component(self) -> None:
        external = Path(self.temporary.name) / "external"
        external.mkdir()
        self.root.mkdir()
        (self.root / "objects").symlink_to(external, target_is_directory=True)

        with self.assertRaises(ValueError):
            Vault(self.root).init()
        self.assertFalse((external / "sha256").exists())

    def test_metadata_validation_and_secret_guard_leave_no_object_or_capture(self) -> None:
        vault = Vault(self.root)
        vault.init()

        with self.assertRaisesRegex(ValueError, "finite JSON"):
            vault.ingest(b"nan", source_metadata={"value": float("nan")})
        self.assertEqual([p for p in (self.root / "objects").rglob("*") if p.is_file()], [])
        self.assertEqual(list((self.root / "evidence").rglob("*.json")), [])

        with self.assertRaises(SecretDetectedError) as caught:
            vault.ingest(b"token", source_metadata={"token": "ghp_" + "A" * 40})
        self.assertNotIn("ghp_", str(caught.exception))
        self.assertEqual([p for p in (self.root / "objects").rglob("*") if p.is_file()], [])
        self.assertEqual(list((self.root / "evidence").rglob("*.json")), [])

    def test_external_id_is_scoped_by_account_and_account_is_promoted(self) -> None:
        vault = Vault(self.root)
        vault.init()
        first = vault.ingest(
            b"account one", source_kind="import", external_id="item-1",
            source_metadata={"account": "one"},
        )
        second = vault.ingest(
            b"account two", source_kind="import", external_id="item-1",
            source_metadata={"account": "two"},
        )
        self.assertNotEqual(first["id"], second["id"])
        self.assertEqual(first["source"]["account"], "one")
        self.assertEqual(second["source"]["account"], "two")
        with self.assertRaisesRegex(ValueError, "different content"):
            vault.ingest(
                b"changed", source_kind="import", external_id="item-1",
                source_metadata={"account": "one"},
            )

    def test_new_vault_and_private_durable_files_are_owner_only(self) -> None:
        vault = Vault(self.root)
        vault.init()
        self.assertEqual(stat.S_IMODE(self.root.stat().st_mode), 0o700)
        for name in DURABLE_TOP_LEVEL:
            self.assertEqual(stat.S_IMODE((self.root / name).stat().st_mode), 0o700)
        record = vault.ingest(b"private")
        path = vault.evidence_path(record["id"])
        assert path is not None
        self.assertEqual(stat.S_IMODE(vault.metadata_path.stat().st_mode), 0o400)
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o400)
        self.assertEqual(stat.S_IMODE(vault.object_path(record["content"]["sha256"]).stat().st_mode), 0o400)

    def test_parent_symlink_is_canonicalized_but_final_symlink_is_rejected(self) -> None:
        real_parent = Path(self.temporary.name) / "real"
        real_parent.mkdir()
        alias = Path(self.temporary.name) / "alias"
        alias.symlink_to(real_parent, target_is_directory=True)
        vault = Vault(alias / "nested")
        self.assertEqual(vault.root, real_parent / "nested")
        vault.init()

        final_alias = Path(self.temporary.name) / "final-alias"
        final_alias.symlink_to(real_parent / "outside", target_is_directory=True)
        with self.assertRaises(ValueError):
            Vault(final_alias).init()
        self.assertFalse((real_parent / "outside").exists())

    def test_parse_time_rejects_non_strings_explicitly(self) -> None:
        with self.assertRaises(TypeError):
            parse_time(123)  # type: ignore[arg-type]

    def test_source_metadata_has_bounded_canonical_utf8_representation(self) -> None:
        vault = Vault(self.root)
        vault.init()
        # Each Japanese character takes three UTF-8 bytes; this exceeds the
        # one MiB bound while remaining a valid JSON object.
        oversized = {"text": "あ" * ((MAX_SOURCE_METADATA_BYTES // 3) + 100)}
        with self.assertRaisesRegex(ValueError, "source_metadata exceeds"):
            vault.ingest(b"bounded", source_metadata=oversized)
        self.assertEqual(list((self.root / "evidence").rglob("*.json")), [])

    def test_invalid_captured_at_is_rejected_before_object_or_capture_publish(self) -> None:
        vault = Vault(self.root)
        vault.init()
        with self.assertRaisesRegex(ValueError, "RFC3339"):
            vault.ingest(b"timestamp", captured_at="2026-01-01 00:00:00+00:00")
        self.assertEqual(list((self.root / "objects").rglob("*")), [
            path for path in (self.root / "objects").rglob("*") if path.is_dir()
        ])
        self.assertEqual(list((self.root / "evidence").rglob("*.json")), [])

    def test_existing_authoritative_versioned_schema_mismatch_fails_closed(self) -> None:
        versioned = self.root / "schemas" / "0.2"
        versioned.mkdir(parents=True)
        target = versioned / "evidence-record.schema.json"
        target.write_bytes(b'{"tampered":true}\n')
        with self.assertRaisesRegex(ValueError, "authoritative schema differs"):
            Vault(self.root).init()
        self.assertEqual(target.read_bytes(), b'{"tampered":true}\n')

    def test_init_rejects_symlinked_policy_index_and_core_files(self) -> None:
        external = Path(self.temporary.name) / "external"
        external.mkdir()
        cases = [
            ("policies", "context.json"),
            ("canon", "index.md"),
            ("canon/core", "lifedb.md"),
        ]
        for parent, filename in cases:
            with self.subTest(parent=parent):
                root = Path(self.temporary.name) / ("vault-" + filename.replace(".", "-"))
                (root / parent).mkdir(parents=True)
                target = root / parent / filename
                target.symlink_to(external / filename)
                with self.assertRaises(ValueError):
                    Vault(root).init()

    def test_init_replays_missing_tail_after_metadata_publish(self) -> None:
        vault = Vault(self.root)
        metadata = vault.init()
        metadata_bytes = vault.metadata_path.read_bytes()
        (self.root / "canon" / "index.md").unlink()
        (self.root / "canon" / "core" / "lifedb.md").unlink()
        vault.index_dirty_path.unlink()

        self.assertEqual(vault.init(), metadata)
        self.assertEqual(vault.metadata_path.read_bytes(), metadata_bytes)
        self.assertTrue((self.root / "canon" / "index.md").is_file())
        self.assertTrue((self.root / "canon" / "core" / "lifedb.md").is_file())
        self.assertTrue(vault.index_dirty_path.is_file())

    def test_init_refuses_unrelated_existing_directory_and_filesystem_root(self) -> None:
        self.root.mkdir()
        unrelated = self.root / "not-a-vault.txt"
        unrelated.write_text("keep", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "unknown entries"):
            Vault(self.root).init()
        self.assertEqual(unrelated.read_text(encoding="utf-8"), "keep")
        self.assertFalse((self.root / "canon").exists())

        with self.assertRaises(ValueError):
            Vault(Path("/")).init()
