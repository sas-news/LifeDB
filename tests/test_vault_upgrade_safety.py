from __future__ import annotations

import os
import stat
import tempfile
import threading
import unittest
from concurrent.futures import Future, ThreadPoolExecutor
from pathlib import Path
from typing import Any
from unittest import mock

from lifedb.markdown import parse_markdown
from lifedb.schema_validation import SCHEMA_FILES, schema_path
from lifedb.secrets import SecretDetectedError
from lifedb.storage import strict_json_loads
from lifedb.vault import (
    DURABLE_TOP_LEVEL,
    MAX_SOURCE_METADATA_BYTES,
    MAX_VAULT_METADATA_BYTES,
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

    def test_init_creates_evidence_events_directory(self) -> None:
        Vault(self.root).init()

        target = self.root / "evidence" / "_events"
        self.assertTrue(target.is_dir())
        self.assertFalse(target.is_symlink())

    def test_init_canon_index_has_okf_version_frontmatter(self) -> None:
        Vault(self.root).init()

        document = parse_markdown(self.root / "canon" / "index.md")
        self.assertEqual(document.frontmatter.get("okf_version"), "0.2")
        self.assertIsInstance(document.frontmatter.get("okf_version"), str)

    def test_init_preserves_existing_canon_index_bytes(self) -> None:
        (self.root / "canon").mkdir(parents=True)
        custom = b"# Custom Canon index\n\nOwner content stays.\n"
        (self.root / "canon" / "index.md").write_bytes(custom)

        Vault(self.root).init()

        self.assertEqual((self.root / "canon" / "index.md").read_bytes(), custom)

    def test_init_creates_exact_fresh_v02_layout(self) -> None:
        Vault(self.root).init()

        canon_children = (
            "core", "self", "entities", "projects", "topics", "goals",
            "decisions", "patterns", "procedures", "conflicts",
        )
        evidence_children = (
            "conversations", "activity", "web", "mail", "calendar",
            "git", "imports", "_events",
        )
        runtime_children = (
            "postgres", "lexical", "vector", "graph", "embeddings",
            "cache", "locks",
        )
        expected_dirs = (
            set(DURABLE_TOP_LEVEL)
            | {f"canon/{name}" for name in canon_children}
            | {f"evidence/{name}" for name in evidence_children}
            | {"objects/sha256"}
            | {f"runtime/{name}" for name in runtime_children}
            | {"schemas/0.2"}
        )
        expected_files = (
            {
                "vault.json",
                "canon/index.md",
                "canon/core/lifedb.md",
                "policies/context.json",
                "policies/retention.json",
                "runtime/locks/writer.lock",
                "runtime/index.dirty",
            }
            | {f"schemas/{filename}" for filename in SCHEMA_FILES.values()}
            | {f"schemas/0.2/{filename}" for filename in SCHEMA_FILES.values()}
        )

        actual_dirs = {
            path.relative_to(self.root).as_posix()
            for path in self.root.rglob("*")
            if path.is_dir() and not path.is_symlink()
        }
        actual_files = {
            path.relative_to(self.root).as_posix()
            for path in self.root.rglob("*")
            if path.is_file() and not path.is_symlink()
        }
        self.assertEqual(actual_dirs, expected_dirs)
        self.assertEqual(actual_files, expected_files)
        self.assertEqual(
            [path for path in self.root.rglob("*") if path.is_symlink()], [],
        )
        self.assertEqual(
            [path for path in self.root.rglob(".lifedb-init-*.tmp")], [],
        )

    def test_init_concurrent_initializers_converge_on_committed_metadata(self) -> None:
        self.root.mkdir(parents=True)
        first = Vault(self.root)
        second = Vault(self.root)
        barrier = threading.Barrier(2, timeout=10)
        setup_lock = threading.Lock()
        real_read = Vault._read_metadata_at
        real_ensure = Vault._ensure_directory_at

        def gated_read(self_vault: Vault, root_fd: int) -> dict[str, Any] | None:
            result = real_read(self_vault, root_fd)
            if result is None:
                barrier.wait(timeout=10)
            return result

        def locked_ensure(cls: type[Vault], root_fd: int, components: tuple[str, ...]) -> None:
            with setup_lock:
                real_ensure(root_fd, components)

        failures: dict[str, BaseException] = {}
        with (
            mock.patch.object(Vault, "_read_metadata_at", new=gated_read),
            mock.patch.object(Vault, "_ensure_directory_at", new=classmethod(locked_ensure)),
            ThreadPoolExecutor(max_workers=2, thread_name_prefix="vault-init") as executor,
        ):
            futures: dict[str, Future[dict[str, Any]]] = {
                "first": executor.submit(first.init),
                "second": executor.submit(second.init),
            }
            for name, future in futures.items():
                error = future.exception(timeout=30)
                if error is not None:
                    failures[name] = error

        self.assertEqual(failures, {})
        metadatas = {
            name: future.result(timeout=30) for name, future in futures.items()
        }
        self.assertEqual(metadatas["first"], metadatas["second"])
        committed = strict_json_loads(
            (self.root / "vault.json").read_bytes(),
            max_bytes=MAX_VAULT_METADATA_BYTES,
        )
        self.assertEqual(metadatas["first"], committed)
        self.assertEqual(
            [path for path in self.root.rglob(".lifedb-init-*.tmp")], [],
        )

    @staticmethod
    def _run_concurrent_inits(
        first: Vault, second: Vault
    ) -> dict[str, Future[dict[str, Any]]]:
        with ThreadPoolExecutor(max_workers=2, thread_name_prefix="vault-init") as executor:
            return {
                "first": executor.submit(first.init),
                "second": executor.submit(second.init),
            }

    @staticmethod
    def _concurrent_init_failures(
        futures: dict[str, Future[dict[str, Any]]],
    ) -> dict[str, BaseException]:
        failures: dict[str, BaseException] = {}
        for name, future in futures.items():
            error = future.exception(timeout=30)
            if error is not None:
                failures[name] = error
        return failures

    def _assert_converged_on_committed_metadata(
        self, futures: dict[str, Future[dict[str, Any]]]
    ) -> None:
        metadatas = {
            name: future.result(timeout=30) for name, future in futures.items()
        }
        self.assertEqual(metadatas["first"], metadatas["second"])
        committed = strict_json_loads(
            (self.root / "vault.json").read_bytes(),
            max_bytes=MAX_VAULT_METADATA_BYTES,
        )
        self.assertEqual(metadatas["first"], committed)

    def test_init_concurrent_absent_root_converges_on_committed_metadata(self) -> None:
        self.assertFalse(self.root.exists())
        first = Vault(self.root)
        second = Vault(self.root)
        barrier = threading.Barrier(2, timeout=10)
        real_mkdir = os.mkdir

        def gated_mkdir(path: str, mode: int = 0o777, *, dir_fd: int | None = None) -> None:
            # No durable child directory is ever named "vault", so this gates
            # only the two racing root creations after both observed absence.
            if path == self.root.name:
                barrier.wait(timeout=10)
            real_mkdir(path, mode, dir_fd=dir_fd)

        with mock.patch.object(os, "mkdir", new=gated_mkdir):
            futures = self._run_concurrent_inits(first, second)

        self.assertEqual(self._concurrent_init_failures(futures), {})
        self._assert_converged_on_committed_metadata(futures)
        self.assertEqual(
            sorted(path.name for path in Path(self.temporary.name).iterdir()),
            [self.root.name],
        )
        self.assertEqual(
            [path for path in self.root.rglob(".lifedb-init-*.tmp")], [],
        )

    def test_init_concurrent_first_child_directory_converges_on_committed_metadata(self) -> None:
        self.root.mkdir(parents=True)
        first = Vault(self.root)
        second = Vault(self.root)
        barrier = threading.Barrier(2, timeout=10)
        real_mkdir = os.mkdir

        def gated_mkdir(path: str, mode: int = 0o777, *, dir_fd: int | None = None) -> None:
            # "canon" is the first top-level directory every init creates, so
            # both workers rendezvous here after observing its absence.
            if path == "canon":
                barrier.wait(timeout=10)
            real_mkdir(path, mode, dir_fd=dir_fd)

        with mock.patch.object(os, "mkdir", new=gated_mkdir):
            futures = self._run_concurrent_inits(first, second)

        self.assertEqual(self._concurrent_init_failures(futures), {})
        self._assert_converged_on_committed_metadata(futures)
        self.assertEqual(
            [path for path in self.root.rglob(".lifedb-init-*.tmp")], [],
        )

    def test_init_rejects_mid_initialization_root_inode_swap(self) -> None:
        self.root.mkdir(parents=True)
        parent = Path(self.temporary.name)
        detached = parent / "detached-vault"
        replacement = parent / "replacement-vault"
        replacement.mkdir()
        sentinel = b"do not touch\n"
        (replacement / "sentinel.txt").write_bytes(sentinel)
        real_ensure = Vault._ensure_directory_at
        calls: list[tuple[str, ...]] = []

        def hooked_ensure(cls: type[Vault], root_fd: int, components: tuple[str, ...]) -> None:
            real_ensure(root_fd, components)
            calls.append(components)
            if len(calls) == 1:
                self.root.rename(detached)
                replacement.rename(self.root)

        vault = Vault(self.root)
        with mock.patch.object(Vault, "_ensure_directory_at", new=classmethod(hooked_ensure)):
            with self.assertRaisesRegex(ValueError, "changed during initialization"):
                vault.init()

        self.assertEqual(len(calls), 1)
        self.assertTrue(detached.is_dir())
        self.assertTrue((detached / DURABLE_TOP_LEVEL[0]).is_dir())
        self.assertEqual(
            sorted(path.name for path in self.root.iterdir()),
            ["sentinel.txt"],
        )
        self.assertEqual((self.root / "sentinel.txt").read_bytes(), sentinel)
