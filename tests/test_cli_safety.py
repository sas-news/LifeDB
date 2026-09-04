from __future__ import annotations

import contextlib
import io
import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from lifedb.cli import MAX_MAPPING_INPUT_BYTES, MAX_RAW_INPUT_BYTES, main
from lifedb.ids import new_id
from lifedb.vault import Vault
from lifedb.runtime import reset_runtime, RuntimeResetError
import lifedb.runtime as runtime_module
from lifedb.canon import CanonIntegrityError, CanonStore


class CLISafetyTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name) / "vault"
        self.vault = Vault(self.root)
        self.vault.init()
        self.evidence = self.vault.ingest(b"cli evidence", media_type="text/plain")

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def run_cli(self, *args: str, stdin: str | None = None) -> tuple[int, str, str]:
        output = io.StringIO()
        errors = io.StringIO()
        old_stdin = __import__("sys").stdin
        if stdin is not None:
            __import__("sys").stdin = io.StringIO(stdin)
        try:
            with contextlib.redirect_stdout(output), contextlib.redirect_stderr(errors):
                result = main(["--vault", str(self.root), *args])
        finally:
            __import__("sys").stdin = old_stdin
        return result, output.getvalue(), errors.getvalue()

    def test_ingest_rejects_fifo_and_oversized_path_without_object(self) -> None:
        fifo = self.root.parent / "input.fifo"
        os.mkfifo(fifo)
        before = list((self.root / "objects").rglob("*"))
        result, _, _ = self.run_cli("ingest", str(fifo))
        self.assertEqual(result, 1)
        self.assertEqual(list((self.root / "objects").rglob("*")), before)

        oversized = self.root.parent / "oversized.bin"
        with oversized.open("wb") as stream:
            stream.truncate(MAX_RAW_INPUT_BYTES + 1)
        result, _, _ = self.run_cli("ingest", str(oversized))
        self.assertEqual(result, 1)

    def test_mapping_duplicate_and_alias_inputs_fail_closed(self) -> None:
        document_id = new_id()
        document = self.root / "canon" / "self" / "cli.md"
        document.write_text(
            "---\nx-lifedb:\n  id: %s\n  sensitivity: personal\n  claims: []\n---\n" % document_id,
            encoding="utf-8",
        )
        duplicate = self.root.parent / "duplicate.yaml"
        duplicate.write_text("predicate: a\npredicate: b\n", encoding="utf-8")
        before = list((self.root / "evidence" / "_events").rglob("*.json"))
        result, _, _ = self.run_cli("candidate", "create", document_id, str(duplicate), "--actor", "test")
        self.assertEqual(result, 1)
        self.assertEqual(list((self.root / "evidence" / "_events").rglob("*.json")), before)

        alias = self.root.parent / "alias.yaml"
        alias.write_text("value: &value [*value]\n", encoding="utf-8")
        result, _, _ = self.run_cli("candidate", "create", document_id, str(alias), "--actor", "test")
        self.assertEqual(result, 1)

    def test_representation_invalid_input_has_no_orphan_object(self) -> None:
        before = {
            path.relative_to(self.root).as_posix()
            for path in (self.root / "objects").rglob("*")
            if path.is_file()
        }
        result, _, _ = self.run_cli(
            "evidence", "add-representation", self.evidence["id"], "-",
            "--role", "NOT-LOWERCASE", "--media-type", "text/plain",
            "--actor", "test", "--producer-version", "1", stdin="derived",
        )
        self.assertEqual(result, 1)
        after = {
            path.relative_to(self.root).as_posix()
            for path in (self.root / "objects").rglob("*")
            if path.is_file()
        }
        self.assertEqual(after, before)

    def test_canon_recover_and_evidence_expand_commands(self) -> None:
        result, output, _ = self.run_cli("canon", "recover")
        self.assertEqual(result, 0)
        self.assertEqual(json.loads(output)["unresolved"], [])

        result, output, _ = self.run_cli(
            "evidence", "expand", self.evidence["id"],
            "--material", "raw", "--max-chars", "5",
        )
        self.assertEqual(result, 0)
        expanded = json.loads(output)
        self.assertEqual(expanded["text"], "cli e")
        self.assertTrue(expanded["truncated"])

    def test_stdin_mapping_limit_is_explicit(self) -> None:
        document_id = new_id()
        document = self.root / "canon" / "self" / "cli2.md"
        document.write_text(
            "---\nx-lifedb:\n  id: %s\n  sensitivity: personal\n  claims: []\n---\n" % document_id,
            encoding="utf-8",
        )
        oversized = "x: " + ("a" * MAX_MAPPING_INPUT_BYTES)
        result, _, _ = self.run_cli(
            "candidate", "create", document_id, "-", "--actor", "test", stdin=oversized
        )
        self.assertEqual(result, 1)

    def test_runtime_reset_requires_exact_guard_and_preserves_durable_data(self) -> None:
        durable = self.root / "evidence" / "keep.txt"
        durable.write_text("durable", encoding="utf-8")
        disposable = self.root / "runtime" / "nested"
        disposable.mkdir()
        (disposable / "projection").write_text("stale", encoding="utf-8")
        outside = self.root.parent / "outside.txt"
        outside.write_text("must survive", encoding="utf-8")
        (self.root / "runtime" / "outside-link").symlink_to(outside)
        with self.assertRaises(RuntimeResetError):
            reset_runtime(self.vault, confirmation="DELETE")
        result = reset_runtime(self.vault, confirmation="DELETE-RUNTIME")
        self.assertTrue(result["reset"])
        self.assertTrue((self.root / "runtime" / "index.dirty").is_file())
        self.assertEqual(durable.read_text(encoding="utf-8"), "durable")
        self.assertEqual(outside.read_text(encoding="utf-8"), "must survive")

        result, output, _ = self.run_cli("runtime", "reset", "--confirm", "DELETE-RUNTIME")
        self.assertEqual(result, 0)
        self.assertTrue(json.loads(output)["reset"])

    def test_runtime_reset_rejects_symlink_or_non_directory(self) -> None:
        runtime = self.root / "runtime"
        saved = self.root / "runtime.saved"
        runtime.rename(saved)
        runtime.symlink_to(saved, target_is_directory=True)
        with self.assertRaises(RuntimeResetError):
            reset_runtime(self.vault, confirmation="DELETE-RUNTIME")
        runtime.unlink()
        shutil.rmtree(saved)
        runtime.write_text("not a directory", encoding="utf-8")
        with self.assertRaises(RuntimeResetError):
            reset_runtime(self.vault, confirmation="DELETE-RUNTIME")

    def test_runtime_reset_rejects_home_repo_and_invalid_metadata(self) -> None:
        with patch("lifedb.runtime.Path.home", return_value=self.root):
            with self.assertRaises(RuntimeResetError):
                reset_runtime(self.vault, confirmation="DELETE-RUNTIME")

        malformed = Path(self.temporary.name) / "malformed"
        malformed.mkdir()
        (malformed / "vault.json").write_text("not-json", encoding="utf-8")
        with self.assertRaises(RuntimeResetError):
            reset_runtime(malformed, confirmation="DELETE-RUNTIME")

        wrong = Path(self.temporary.name) / "wrong-schema"
        wrong.mkdir()
        (wrong / "vault.json").write_text(
            '{"schema":"0.1","vault_id":"00000000-0000-7000-8000-000000000000",'
            '"created_at":"2026-01-01T00:00:00Z","generator":"x"}',
            encoding="utf-8",
        )
        with self.assertRaises(RuntimeResetError):
            reset_runtime(wrong, confirmation="DELETE-RUNTIME")

        repo = Path(self.temporary.name) / "repo"
        repo.mkdir()
        (repo / "pyproject.toml").write_text("[project]\nname='x'\n", encoding="utf-8")
        (repo / ".git").mkdir()
        with self.assertRaises(RuntimeResetError):
            reset_runtime(repo, confirmation="DELETE-RUNTIME")

    def test_runtime_reset_rejects_cross_device_runtime_entry(self) -> None:
        nested = self.root / "runtime" / "mounted"
        nested.mkdir()
        original_lstat = os.lstat

        def fake_lstat(path):
            result = original_lstat(path)
            if Path(path) == nested:
                values = list(result)
                values[2] = result.st_dev + 1
                return os.stat_result(values)
            return result

        with patch("lifedb.runtime.os.lstat", side_effect=fake_lstat):
            with self.assertRaises(RuntimeResetError):
                reset_runtime(self.vault, confirmation="DELETE-RUNTIME")
        self.assertTrue(nested.is_dir())

    def test_runtime_reset_refuses_same_device_directory_swap(self) -> None:
        runtime = self.root / "runtime"
        original = runtime / "original-marker"
        original.write_text("original", encoding="utf-8")
        replacement = self.root / "runtime-replacement"
        original_rename = os.rename
        swapped = False

        def swap_before_rename(source, destination, **kwargs):
            nonlocal swapped
            if source == "runtime" and not swapped:
                swapped = True
                runtime.rename(replacement)
                runtime.mkdir(mode=0o700)
                (runtime / "attacker-marker").write_text("must survive", encoding="utf-8")
            return original_rename(source, destination, **kwargs)

        with patch("lifedb.runtime.os.rename", side_effect=swap_before_rename):
            with self.assertRaises(RuntimeResetError):
                reset_runtime(self.vault, confirmation="DELETE-RUNTIME")
        self.assertTrue((replacement / "original-marker").is_file())
        self.assertEqual((runtime / "attacker-marker").read_text(encoding="utf-8"), "must survive")

    def test_runtime_reset_post_rename_failure_restores_old_runtime(self) -> None:
        runtime = self.root / "runtime"
        marker = runtime / "old-marker"
        marker.write_text("old", encoding="utf-8")
        original_mkdir = os.mkdir
        failed = False

        def fail_new_runtime(path, mode=0o777, *, dir_fd=None):
            nonlocal failed
            if path == "new" and dir_fd is not None and not failed:
                failed = True
                raise OSError("post-rename injection")
            return original_mkdir(path, mode, dir_fd=dir_fd)

        with patch("lifedb.runtime.os.mkdir", side_effect=fail_new_runtime):
            with self.assertRaises(OSError):
                reset_runtime(self.vault, confirmation="DELETE-RUNTIME")
        self.assertEqual(marker.read_text(encoding="utf-8"), "old")
        self.assertTrue(runtime.is_dir())
        self.assertFalse(list((self.root / "quarantine" / "runtime-reset").iterdir()))

    def test_runtime_reset_mid_cleanup_leaves_staging_and_recovers(self) -> None:
        original_remove = runtime_module._remove_dirfd
        failed = False

        def fail_cleanup(directory, device):
            nonlocal failed
            if not failed:
                failed = True
                raise RuntimeResetError("mid-clean injection")
            return original_remove(directory, device)

        with patch.object(runtime_module, "_remove_dirfd", side_effect=fail_cleanup):
            with self.assertRaises(RuntimeResetError):
                reset_runtime(self.vault, confirmation="DELETE-RUNTIME")
        self.assertTrue((self.root / "runtime" / "index.dirty").is_file())
        staging = list((self.root / "quarantine" / "runtime-reset").iterdir())
        self.assertEqual(len(staging), 1)
        self.assertTrue((staging[0] / "old").is_dir())
        self.assertTrue(reset_runtime(self.vault, confirmation="DELETE-RUNTIME")["reset"])
        self.assertFalse(list((self.root / "quarantine" / "runtime-reset").iterdir()))

    def test_runtime_reset_post_new_runtime_creation_failure_recovers(self) -> None:
        original_fsync = os.fsync
        failed = False

        def fail_root_fsync(descriptor):
            nonlocal failed
            try:
                target = os.readlink(f"/proc/self/fd/{descriptor}")
            except OSError:
                target = ""
            if target == str(self.root) and not failed:
                failed = True
                raise OSError("post-new-runtime injection")
            return original_fsync(descriptor)

        with patch("lifedb.runtime.os.fsync", side_effect=fail_root_fsync):
            with self.assertRaises(OSError):
                reset_runtime(self.vault, confirmation="DELETE-RUNTIME")
        self.assertTrue((self.root / "runtime" / "index.dirty").is_file())
        self.assertEqual(len(list((self.root / "quarantine" / "runtime-reset").iterdir())), 1)
        self.assertTrue(reset_runtime(self.vault, confirmation="DELETE-RUNTIME")["reset"])
        self.assertFalse(list((self.root / "quarantine" / "runtime-reset").iterdir()))

    def test_runtime_publish_fails_closed_without_atomic_no_replace(self) -> None:
        parent = self.root.parent / "publish-parent"
        parent.mkdir()
        (parent / "new").mkdir()
        descriptor = os.open(parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            with patch.object(runtime_module.ctypes, "CDLL", return_value=object()), \
                    patch.object(runtime_module.os, "rename") as rename:
                with self.assertRaises(RuntimeResetError):
                    runtime_module._rename_noreplace(
                        "new", "runtime",
                        source_dir_fd=descriptor,
                        destination_dir_fd=descriptor,
                    )
            rename.assert_not_called()
            self.assertTrue((parent / "new").is_dir())
            self.assertFalse((parent / "runtime").exists())
        finally:
            os.close(descriptor)

    def test_mark_index_dirty_refuses_runtime_symlink(self) -> None:
        runtime = self.root / "runtime"
        detached = self.root.parent / "detached-runtime"
        outside = self.root.parent / "outside-runtime"
        outside.mkdir()
        sentinel = outside / "sentinel"
        sentinel.write_text("untouched", encoding="utf-8")
        runtime.rename(detached)
        runtime.symlink_to(outside, target_is_directory=True)
        try:
            self.assertFalse(self.vault.mark_index_dirty(reason="symlink-probe"))
            self.assertEqual(sentinel.read_text(encoding="utf-8"), "untouched")
            self.assertFalse((outside / "index.dirty").exists())
        finally:
            runtime.unlink()
            detached.rename(runtime)

    def test_canon_parent_symlink_is_rejected_without_external_read(self) -> None:
        external = Path(self.temporary.name) / "external-canon"
        external.mkdir()
        marker = external / "marker.md"
        marker.write_text("outside", encoding="utf-8")
        canon = self.root / "canon"
        saved = self.root / "canon.saved"
        canon.rename(saved)
        canon.symlink_to(external, target_is_directory=True)
        with self.assertRaises(CanonIntegrityError):
            CanonStore(self.vault)
        self.assertEqual(marker.read_text(encoding="utf-8"), "outside")


if __name__ == "__main__":
    unittest.main()
