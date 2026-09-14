from __future__ import annotations

import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from integrations.hermes.installer.core import InstallOptions, lifecycle
from integrations.hermes.installer import recovery


class InstallerLifecycleTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.home = self.root / "hermes"
        self.home.mkdir()
        self.hermes_path = self.root / "bin" / "hermes"
        self.hermes_path.parent.mkdir()
        self.doctor_log = self.root / "doctor.log"
        self.hermes_path.write_text(
            "#!/bin/sh\n"
            "if [ \"$1\" = \"--version\" ]; then\n"
            "[ \"$#\" -eq 1 ] || exit 1\n"
            "printf '%s\\n' \"Hermes Agent v0.21.0 (2026.8.31) · upstream a0749d58\" \"Install directory: /isolated/hermes\" \"Install method: git\" \"Python: 3.11.16\" \"OpenAI SDK: 2.24.0\" \"Update available: 1 commits behind — run 'hermes update'\"\n"
            "exit 0\nfi\n"
            f"[ \"$#\" -eq 4 ] && [ \"$1\" = plugins ] && [ \"$2\" = doctor ] && [ \"$4\" = --ci ] && [ -d \"$3\" ] || exit 1\n"
            f"printf '%s\\n' \"$1|$2|$3|$4\" >> '{self.doctor_log}'\n",
            encoding="utf-8",
        )
        self.hermes_path.chmod(0o755)
        self.path_patch = patch.dict(os.environ, {"PATH": f"{self.hermes_path.parent}:/usr/local/bin:/usr/bin"}, clear=True)
        self.path_patch.start()
        self.addCleanup(self.path_patch.stop)
        config_path = self.home / "config.yaml"
        config_path.write_text(
            "memory:\n  provider: lancedb\nplugins:\n  enabled: [disk-cleanup]\n  entries:\n    disk-cleanup:\n      settings: {}\n",
            encoding="utf-8",
        )
        config_path.chmod(0o600)
        self.token = self.root / "token"
        self.token.write_bytes(b"x" * 32)
        self.token.chmod(0o600)
    def tearDown(self) -> None:
        self.temp.cleanup()

    def options(self) -> InstallOptions:
        return InstallOptions(
            url="http://127.0.0.1:7331",
            token_file=self.token,
            workspace=None,
            timeout_seconds=2.0,
            max_response_bytes=1_048_576,
            max_request_bytes=4_194_304,
            sensitivity_ceiling=None,
            budget_chars=12_000,
            core_chars=4_000,
            continuity_chars=2_000,
            relevant_chars=6_000,
            limit=8,
        )

    def test_install_enable_disable_enable_uninstall_preserves_unrelated_config(self) -> None:
        before = (self.home / "config.yaml").read_bytes()
        lifecycle(self.home, "install", self.options(), hermes_binary="hermes")
        owner = self.home / "plugins" / "lifedb-bridge" / ".lifedb-owner.json"
        self.assertEqual(json.loads(owner.read_text())['lifecycle'], "enabled")
        lifecycle(self.home, "disable", self.options(), hermes_binary="hermes")
        self.assertEqual(json.loads(owner.read_text())['lifecycle'], "disabled")
        lifecycle(self.home, "enable", self.options(), hermes_binary="hermes")
        lifecycle(self.home, "uninstall", self.options(), hermes_binary="hermes")
        config = (self.home / "config.yaml").read_bytes()
        self.assertEqual(__import__("yaml").safe_load(config)["memory"]["provider"], "lancedb")
        self.assertIn(b"disk-cleanup", config)
        self.assertNotEqual(before, config)

    def test_install_uninstall_preserves_owner_owned_0644_config(self) -> None:
        config_path = self.home / "config.yaml"
        before = config_path.read_bytes()
        config_path.chmod(0o644)

        lifecycle(self.home, "install", self.options(), hermes_binary="hermes")
        self.assertEqual(config_path.stat().st_mode & 0o777, 0o644)

        lifecycle(self.home, "uninstall", self.options(), hermes_binary="hermes")
        self.assertEqual(config_path.stat().st_mode & 0o777, 0o644)
        config = config_path.read_bytes()
        self.assertEqual(__import__("yaml").safe_load(config)["memory"]["provider"], "lancedb")
        self.assertIn(b"disk-cleanup", config)
        self.assertNotEqual(before, config)
        self.assertFalse((self.home / "plugins" / "lifedb-bridge").exists())

    def test_check_rejects_non_private_token_without_reading_contents(self) -> None:
        self.token.chmod(0o644)
        lifecycle(self.home, "check", self.options(), hermes_binary="hermes")

    def test_identical_install_does_not_change_config_mtime(self) -> None:
        lifecycle(self.home, "install", self.options(), hermes_binary="hermes")
        config = self.home / "config.yaml"
        mtime = config.stat().st_mtime_ns
        lifecycle(self.home, "install", self.options(), hermes_binary="hermes")
        self.assertEqual(config.stat().st_mtime_ns, mtime)

    def test_changed_settings_replacement_succeeds_after_imported_cache(self) -> None:
        lifecycle(self.home, "install", self.options(), hermes_binary="hermes")
        target = self.home / "plugins" / "lifedb-bridge"
        spec = __import__("importlib.util").util.spec_from_file_location(
            "lifedb_bridge", target / "__init__.py", submodule_search_locations=[str(target)]
        )
        module = __import__("importlib.util").util.module_from_spec(spec)
        __import__("sys").modules["lifedb_bridge"] = module
        spec.loader.exec_module(module)
        __import__("importlib").import_module("lifedb_bridge.settings")
        self.assertTrue((target / "__pycache__").is_dir())

        changed = self.options()
        object.__setattr__(changed, "url", "http://127.0.0.1:7332")
        lifecycle(self.home, "install", changed, hermes_binary="hermes")

        self.assertEqual(__import__("json").loads((target / ".lifedb-owner.json").read_text())["managed_config"]["settings"]["url"], "http://127.0.0.1:7332")
        self.assertFalse(any((self.home / "plugins").glob(".lifedb-staging-*")))

    def test_nonempty_cache_replacement_before_rmdir_preserves_recovery_state(self) -> None:
        lifecycle(self.home, "install", self.options(), hermes_binary="hermes")
        target = self.home / "plugins" / "lifedb-bridge"
        spec = __import__("importlib.util").util.spec_from_file_location(
            "lifedb_bridge", target / "__init__.py", submodule_search_locations=[str(target)]
        )
        module = __import__("importlib.util").util.module_from_spec(spec)
        __import__("sys").modules["lifedb_bridge"] = module
        spec.loader.exec_module(module)
        __import__("importlib").import_module("lifedb_bridge.settings")
        changed = self.options()
        object.__setattr__(changed, "url", "http://127.0.0.1:7332")
        original_rmdir = recovery.os.rmdir
        swapped = False

        def swap_cache(name: str, *, dir_fd: int = -1) -> None:
            nonlocal swapped
            if name == "__pycache__" and dir_fd != -1 and not swapped:
                cache = Path(__import__("os").readlink(f"/proc/self/fd/{dir_fd}")) / name
                cache.rename(cache.parent / ".cache-before-swap")
                cache.mkdir(mode=0o700)
                (cache / "sentinel").write_bytes(b"must remain")
                (cache / "sentinel").chmod(0o600)
                swapped = True
            original_rmdir(name, dir_fd=dir_fd)

        with patch.object(recovery.os, "rmdir", side_effect=swap_cache):
            with self.assertRaises(__import__("integrations.hermes.installer.core", fromlist=["InstallerError"]).InstallerError):
                lifecycle(self.home, "install", changed, hermes_binary="hermes")

        quarantine = next((self.home / "plugins").glob(".lifedb-quarantine-*"))
        replacement = quarantine / "__pycache__"
        self.assertEqual((replacement / "sentinel").read_bytes(), b"must remain")
        self.assertTrue((self.home / ".lifedb-transaction.json").exists())

    def test_failed_upgrade_preserves_old_owned_tree(self) -> None:
        lifecycle(self.home, "install", self.options(), hermes_binary="hermes")
        target = self.home / "plugins" / "lifedb-bridge"
        before = {path.name: path.read_bytes() for path in target.iterdir() if path.is_file()}
        changed = self.options()
        object.__setattr__(changed, "url", "http://127.0.0.1:7332")
        with patch("integrations.hermes.installer.core._validate_candidate", side_effect=__import__("integrations.hermes.installer.core", fromlist=["InstallerError"]).InstallerError("Hermes installer operation failed")):
            with self.assertRaises(__import__("integrations.hermes.installer.core", fromlist=["InstallerError"]).InstallerError):
                lifecycle(self.home, "install", changed, hermes_binary="hermes")
        self.assertEqual(before, {path.name: path.read_bytes() for path in target.iterdir() if path.is_file()})
        doctor_paths = {
            line.split("|", 3)[2]
            for line in self.doctor_log.read_text(encoding="utf-8").splitlines()
        }
        self.assertGreaterEqual(len(doctor_paths), 2)
        self.assertIn(str(target), doctor_paths)
        self.assertTrue(any(path != str(target) for path in doctor_paths))

    def test_stale_registration_uninstall_fails_closed(self) -> None:
        (self.home / "config.yaml").write_text("plugins:\n  entries:\n    lifedb-bridge:\n      settings: {}\n", encoding="utf-8")
        with self.assertRaises(__import__("integrations.hermes.installer.core", fromlist=["InstallerError"]).InstallerError):
            lifecycle(self.home, "uninstall", self.options(), hermes_binary="hermes")

    def test_marker_failure_restores_config_and_marker(self) -> None:
        lifecycle(self.home, "install", self.options(), hermes_binary="hermes")
        config = (self.home / "config.yaml").read_bytes()
        marker = self.home / "plugins" / "lifedb-bridge" / ".lifedb-owner.json"
        marker_before = marker.read_bytes()
        original = __import__("integrations.hermes.installer.core", fromlist=["write_atomic"]).write_atomic

        def fail_marker(path: Path, data: bytes, mode: int) -> None:
            if path.name == ".lifedb-owner.json":
                raise __import__("integrations.hermes.installer.core", fromlist=["InstallerError"]).InstallerError("Hermes installer operation failed")
            original(path, data, mode)

        with patch("integrations.hermes.installer.core.write_atomic", side_effect=fail_marker):
            with self.assertRaises(__import__("integrations.hermes.installer.core", fromlist=["InstallerError"]).InstallerError):
                lifecycle(self.home, "disable", self.options(), hermes_binary="hermes")
        lifecycle(self.home, "install", self.options(), hermes_binary="hermes")
        self.assertEqual(config, (self.home / "config.yaml").read_bytes())
        self.assertEqual(marker_before, marker.read_bytes())


if __name__ == "__main__":
    unittest.main()
