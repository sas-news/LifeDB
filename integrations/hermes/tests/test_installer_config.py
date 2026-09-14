from __future__ import annotations

from pathlib import Path
import tempfile
import unittest

from integrations.hermes.installer.config import ConfigError, load_config, projection, update


class ConfigContractTests(unittest.TestCase):
    def test_rejects_nested_duplicate_alias_tag_and_non_mapping(self) -> None:
        invalid = ("a: 1\na: 2\n", "a: &x 1\nb: *x\n", "a: !unsafe 1\n", "- item\n")
        for text in invalid:
            with tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / "config.yaml"
                path.write_text(text, encoding="utf-8")
                with self.assertRaises(ConfigError):
                    load_config(path)

    def test_oversized_and_invalid_utf8_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.yaml"
            path.write_bytes(b"x" * (1_048_577))
            with self.assertRaises(ConfigError):
                load_config(path)

    def test_nested_sequences_preserve_ids_and_conflicts_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.yaml"
            path.write_text("plugins:\n  enabled: [disk-cleanup, another-plugin]\n  disabled: [sleep]\n", encoding="utf-8")
            config, _ = load_config(path)
            self.assertEqual(projection(config)["enabled"], ["disk-cleanup", "another-plugin"])
            path.write_text("plugins:\n  enabled: [same, same]\n", encoding="utf-8")
            config, _ = load_config(path)
            with self.assertRaises(ConfigError):
                projection(config)

    def test_absent_plugins_mapping_is_attached_to_config(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.yaml"
            path.write_text("memory:\n  provider: lancedb\n", encoding="utf-8")
            config, _ = load_config(path)
            update(config, "enabled", {"url": "http://127.0.0.1:7331"})
            self.assertIn("plugins", config)
            self.assertEqual(config["plugins"]["enabled"], ["lifedb-bridge"])
            path.write_text("plugins:\n  enabled: [same]\n  disabled: [same]\n", encoding="utf-8")
            config, _ = load_config(path)
            with self.assertRaises(ConfigError):
                projection(config)
            path.write_bytes(b"\xff")
            with self.assertRaises(ConfigError):
                load_config(path)


if __name__ == "__main__":
    unittest.main()
