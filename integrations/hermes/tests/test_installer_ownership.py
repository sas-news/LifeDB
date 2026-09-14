from __future__ import annotations

from pathlib import Path
import os
import tempfile
import unittest
from unittest.mock import patch
import subprocess

from integrations.hermes.installer.core import InstallerError
from integrations.hermes.installer.environment import write_atomic
from integrations.hermes.installer.ownership import marker, validate_marker, validate_tree
from integrations.hermes.installer.cache import remove_cache, validate_cache
from integrations.hermes.installer.source import OWNED_FILES, hashes, source_root


class OwnershipContractTests(unittest.TestCase):
    def _root(self, directory: str) -> Path:
        root = Path(directory) / "plugin"
        root.mkdir(mode=0o700)
        for name in OWNED_FILES:
            destination = root / name
            destination.write_bytes((source_root() / name).read_bytes())
            destination.chmod(0o600)
        marker_path = root / ".lifedb-owner.json"
        marker_path.write_bytes(marker(root, "enabled", {"lifecycle": "enabled", "settings": {}}, hashes(source_root())))
        marker_path.chmod(0o600)
        return root

    def test_marker_requires_exact_typed_schema(self) -> None:
        with self.assertRaises(InstallerError):
            validate_marker({"plugin": "lifedb-bridge"})

    def test_non_mapping_marker_is_rejected(self) -> None:
        with self.assertRaises(InstallerError):
            validate_marker([])

    def test_temp_collision_is_not_removed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "target"
            collision = Path(directory) / ".lifedb-123-collision.tmp"
            collision.write_bytes(b"hostile")
            with patch("integrations.hermes.installer.environment.os.getpid", return_value=123), patch("integrations.hermes.installer.environment.secrets.token_hex", return_value="collision"):
                with self.assertRaises(InstallerError):
                    write_atomic(target, b"new", 0o600)
            self.assertEqual(collision.read_bytes(), b"hostile")

    def test_marker_symlink_trailing_bytes_and_duplicate_keys_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "plugin"
            root.mkdir(mode=0o700)
            for name in OWNED_FILES:
                source = source_root() / name
                destination = root / name
                destination.write_bytes(source.read_bytes())
                destination.chmod(0o600)
            marker_path = root / ".lifedb-owner.json"
            valid = marker(root, "enabled", {"lifecycle": "enabled", "settings": {}}, hashes(source_root()))
            marker_path.write_bytes(valid)
            marker_path.chmod(0o600)
            external = Path(directory) / "external"
            external.write_bytes(valid)
            external.chmod(0o600)
            marker_path.unlink()
            marker_path.symlink_to(external)
            with self.assertRaises(InstallerError):
                validate_tree(root)
            marker_path.unlink()
            marker_path.write_bytes(valid.replace(b'"schema":1', b'"schema":1,"schema":1', 1))
            marker_path.chmod(0o600)
            with self.assertRaises(InstallerError):
                validate_tree(root)
            marker_path.write_bytes(valid + b" ")
            with self.assertRaises(InstallerError):
                validate_tree(root)

    def test_valid_partial_cpython_cache_is_ignored_by_owned_hashes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = self._root(directory)
            cache = root / "__pycache__"
            cache.mkdir(mode=0o755)
            for name in ("hooks.cpython-311.pyc", "payloads.cpython-312.opt-1.pyc", "postflight.cpython-399.opt-2.pyc"):
                (cache / name).write_bytes(b"mutable")
            before = hashes(source_root())
            validate_tree(root)
            (cache / "hooks.cpython-311.pyc").write_bytes(b"changed")
            validate_tree(root)
            self.assertEqual(hashes(source_root()), before)

    def test_remove_cache_accepts_expected_directory_metadata_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = self._root(directory)
            cache = root / "__pycache__"
            cache.mkdir(mode=0o700)
            entry = cache / "hooks.cpython-311.pyc"
            entry.write_bytes(b"bytecode")
            entry.chmod(0o600)

            remove_cache(root)

            self.assertFalse(cache.exists())

    def test_hostile_cache_entries_fail_closed_without_mutation(self) -> None:
        hostile = ("hooks.cpython-311.opt-0.pyc", "unknown.cpython-311.pyc", "hooks.pyc")
        for name in hostile:
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                root = self._root(directory)
                cache = root / "__pycache__"
                cache.mkdir(mode=0o755)
                candidate = cache / name
                candidate.write_bytes(b"hostile")
                with self.assertRaises(InstallerError):
                    validate_tree(root)
                self.assertEqual(candidate.read_bytes(), b"hostile")

    def test_cache_symlink_nested_directory_and_writable_mode_fail_closed(self) -> None:
        cases = ("symlink", "nested", "writable")
        for case in cases:
            with self.subTest(case=case), tempfile.TemporaryDirectory() as directory:
                root = self._root(directory)
                cache = root / "__pycache__"
                cache.mkdir(mode=0o755)
                candidate = cache / "hooks.cpython-311.pyc"
                if case == "symlink":
                    target = Path(directory) / "target"
                    target.write_bytes(b"target")
                    candidate.symlink_to(target)
                elif case == "nested":
                    candidate.mkdir()
                else:
                    candidate.write_bytes(b"bytecode")
                    candidate.chmod(0o666)
                with self.assertRaises(InstallerError):
                    validate_tree(root)

    def test_fifo_cache_entry_fails_without_blocking(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = self._root(directory)
            cache = root / "__pycache__"
            cache.mkdir(mode=0o755)
            os.mkfifo(cache / "hooks.cpython-311.pyc")
            probe = subprocess.run(
                ["python3", "-c", "from integrations.hermes.installer.cache import validate_cache; from pathlib import Path; validate_cache(Path(__import__('sys').argv[1]))", str(root)],
                env={"PYTHONPATH": str(Path.cwd())}, capture_output=True, timeout=2,
            )
            self.assertNotEqual(probe.returncode, 0)


if __name__ == "__main__":
    unittest.main()
