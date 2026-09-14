from __future__ import annotations

import os
import stat
import tempfile
import unittest
from pathlib import Path

from scripts.docs_bootstrap import BootstrapError, bootstrap, bootstrap_scenario


class DocsBootstrapTest(unittest.TestCase):
    def test_bootstrap_creates_atomic_token_and_replay_preserves_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            vault = root / "vault"
            token_path = root / "token"
            first = bootstrap(vault, token_path)
            token = token_path.read_bytes()
            second = bootstrap(vault, token_path)
            self.assertTrue(first.created)
            self.assertFalse(second.created)
            self.assertEqual(token, token_path.read_bytes())
            self.assertGreaterEqual(len(token), 32)
            self.assertNotIn(b"\n", token)
            self.assertEqual(stat.S_IMODE(token_path.stat().st_mode), 0o600)
            self.assertNotIn(token.decode(), repr(first))

    def test_bootstrap_refuses_symlink_bad_mode_whitespace_short_and_conflict(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            vault = root / "vault"
            vault.mkdir()
            token_path = root / "token"
            token_path.write_bytes(b"a" * 32)
            token_path.chmod(0o644)
            with self.assertRaises(BootstrapError):
                bootstrap(vault, token_path)
            token_path.chmod(0o600)
            token_path.write_bytes(b"a" * 31)
            with self.assertRaises(BootstrapError):
                bootstrap(vault, token_path)
            token_path.write_bytes(b"a" * 31 + b"\n")
            with self.assertRaises(BootstrapError):
                bootstrap(vault, token_path)
            token_path.unlink()
            target = root / "outside"
            target.write_bytes(b"a" * 32)
            token_path.symlink_to(target)
            with self.assertRaises(BootstrapError):
                bootstrap(vault, token_path)
            token_path.unlink()
            (root / "conflict").write_text("not a vault", encoding="utf-8")
            with self.assertRaises(BootstrapError):
                bootstrap(root / "conflict", root / "new-token")

    def test_bootstrap_rejects_non_directory_token_parent(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            parent = root / "not-directory"
            parent.write_bytes(b"x")
            with self.assertRaises(BootstrapError):
                bootstrap(root / "vault", parent / "token")

    def test_unsafe_existing_token_does_not_create_vault(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            vault = root / "vault"
            token = root / "token"
            original = b"unsafe-token-with-whitespace-012345\n"
            token.write_bytes(original)
            token.chmod(0o644)
            with self.assertRaises(BootstrapError):
                bootstrap(vault, token)
            self.assertFalse(vault.exists())
            self.assertEqual(token.read_bytes(), original)
            self.assertEqual(stat.S_IMODE(token.stat().st_mode), 0o644)

    def test_each_unsafe_existing_token_leaves_absent_vault_untouched(self) -> None:
        cases = (("mode", b"a" * 32, 0o644), ("short", b"a" * 31, 0o600), ("whitespace", b"a" * 31 + b"\n", 0o600))
        for name, payload, mode in cases:
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                token = root / "token"
                token.write_bytes(payload)
                token.chmod(mode)
                with self.assertRaises(BootstrapError):
                    bootstrap(root / "vault", token)
                self.assertFalse((root / "vault").exists())
                self.assertEqual(token.read_bytes(), payload)

    def test_bootstrap_scenario_returns_machine_observation(self) -> None:
        self.assertEqual(bootstrap_scenario(), ("ok",))


if __name__ == "__main__":
    unittest.main()
