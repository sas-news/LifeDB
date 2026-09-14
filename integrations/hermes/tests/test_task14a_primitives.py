from __future__ import annotations

from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from integrations.hermes.installer import operations
from integrations.hermes.installer.config import Config
from integrations.hermes.installer.models import ConfigPreimage, Identity, InstallerError


def _identity() -> Identity:
    return Identity(1, 2, 1000, "file", 0o600, 3, 4, "a" * 64)


class Task14APrimitiveTests(unittest.TestCase):
    def test_config_preimage_is_typed_and_immutable(self) -> None:
        preimage = ConfigPreimage(True, {}, b"", 0o600, 4, _identity())
        self.assertTrue(preimage.exists)
        self.assertEqual(preimage.raw, b"")
        with self.assertRaises(AttributeError):
            preimage.raw = b"changed"

    def test_config_parser_uses_captured_fd_bytes_after_path_swap(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            path = home / "config.yaml"
            path.write_bytes(b"plugins: {}\n")
            path.chmod(0o600)
            original = operations.load_config_bytes
            captured: list[bytes] = []

            def swap_after_capture(raw: bytes) -> tuple[Config, bytes]:
                captured.append(raw)
                path.write_bytes(b"plugins: {enabled: [hostile]}\n")
                return original(raw)

            with patch.object(operations, "load_config_bytes", side_effect=swap_after_capture):
                with self.assertRaises(InstallerError):
                    operations.read_config(home, create=True)
            self.assertEqual(captured, [b"plugins: {}\n"])

    def test_absent_and_empty_config_preimages_are_distinct(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            absent = operations.read_config(home, create=True)
            path = home / "config.yaml"
            path.write_bytes(b"")
            path.chmod(0o600)
            empty = operations.read_config(home, create=True)
            self.assertFalse(absent.exists)
            self.assertIsNone(absent.identity)
            self.assertTrue(empty.exists)
            self.assertIsNotNone(empty.identity)
            self.assertEqual(empty.raw, b"")

    def test_oversized_config_is_rejected_before_fd_read(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            path = home / "config.yaml"
            path.write_bytes(b"x" * 1_048_577)
            path.chmod(0o600)
            with patch.object(operations, "_read_fd", side_effect=AssertionError("read must not run")):
                with self.assertRaises(InstallerError):
                    operations.read_config(home, create=True)

    def test_maximum_config_is_read_and_maximum_plus_one_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            path = home / "config.yaml"
            path.write_bytes(b"plugins: {}\n#" + b"x" * (1_048_576 - len(b"plugins: {}\n#")))
            path.chmod(0o600)
            maximum = operations.read_config(home, create=True)
            self.assertEqual(len(maximum.raw), 1_048_576)
            path.write_bytes(maximum.raw + b"x")
            with self.assertRaises(InstallerError):
                operations.read_config(home, create=True)


if __name__ == "__main__":
    unittest.main()
