from __future__ import annotations

import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from integrations.hermes.installer import process
from integrations.hermes.installer import operations
from integrations.hermes.installer.models import InstallerError
from integrations.hermes.installer.source import OWNED_FILES


class Task14AProcessTests(unittest.TestCase):
    def test_candidate_and_publication_doctor_use_requested_home(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            hermes_home = root / "home"
            staging = hermes_home / "plugins" / ".lifedb-staging-test"
            staging.mkdir(parents=True)
            for name in OWNED_FILES:
                if name.endswith(".py"):
                    (staging / name).write_text("pass\n", encoding="utf-8")
            log = root / "doctor.log"
            executable = root / "hermes"
            executable.write_text(
                "#!/bin/sh\n"
                "if [ \"$1\" = \"--version\" ]; then\n"
                "printf 'Hermes Agent v0.21.0 (2026.8.31) · upstream a0749d58\\n'\n"
                "printf 'Install directory: /isolated/hermes\\n'\n"
                "printf 'Install method: git\\n'\n"
                "printf 'Python: 3.11.16\\n'\n"
                "printf 'OpenAI SDK: 2.24.0\\n'\n"
                "printf \"Update available: 1 commits behind — run 'hermes update'\\n\"\n"
                "else printf '%s|%s|%s\\n' \"$HOME\" \"$HERMES_HOME\" \"$*\" >> '" + str(log) + "'\n"
                "fi\n",
                encoding="utf-8",
            )
            executable.chmod(0o700)
            with patch.dict(os.environ, {"PATH": str(root)}):
                operations.validate_candidate(staging, str(executable), hermes_home)
                process.run_host_checks(str(executable), str(hermes_home / "plugins"), hermes_home)
            self.assertEqual(
                log.read_text(encoding="utf-8").splitlines(),
                [f"{hermes_home}|{hermes_home}|plugins doctor {staging} --ci", f"{hermes_home}|{hermes_home}|plugins doctor {hermes_home / 'plugins'} --ci"],
            )

    def test_verified_binary_descriptor_executes_original_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            executable = root / "hermes"
            marker = root / "hostile-ran"
            executable.write_text(
                "#!/bin/sh\nif [ \"$1\" = \"--version\" ]; then\n"
                "printf 'Hermes Agent v0.21.0 (2026.8.31) · upstream a0749d58\\n'\n"
                "printf 'Install directory: /isolated/hermes\\n'\n"
                "printf 'Install method: git\\n'\nprintf 'Python: 3.11.16\\n'\n"
                "printf 'OpenAI SDK: 2.24.0\\n'\nprintf \"Update available: 1 commits behind — run 'hermes update'\\n\"\nfi\n",
                encoding="utf-8",
            )
            executable.chmod(0o700)
            original_verify = process._verified_path
            swapped = False

            def swap_after_verify(resolution: process.BinaryResolution) -> str:
                nonlocal swapped
                result = original_verify(resolution)
                if not swapped:
                    executable.write_text(f"#!/bin/sh\ntouch {marker}\n", encoding="utf-8")
                    executable.chmod(0o700)
                    swapped = True
                return result

            with patch.dict(os.environ, {"PATH": str(root)}), patch.object(process, "_verified_path", side_effect=swap_after_verify):
                process.run_host_checks("hermes", str(root), root)
            self.assertFalse(marker.exists())

    def test_resolve_binary_rejects_unsafe_path_entries_and_returns_identity(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            executable = root / "hermes"
            executable.write_bytes(b"#!/bin/sh\n")
            executable.chmod(0o700)
            with patch.dict(os.environ, {"PATH": str(root)}):
                resolved = process.resolve_binary("hermes")
            self.assertEqual(resolved.path, executable.resolve())
            self.assertEqual(resolved.identity.inode, executable.stat().st_ino)
            process._close_resolution(resolved)
            with patch.dict(os.environ, {"PATH": "relative"}):
                with self.assertRaises(InstallerError):
                    process.resolve_binary("hermes")
            root.chmod(0o777)
            with patch.dict(os.environ, {"PATH": str(root)}):
                with self.assertRaises(InstallerError):
                    process.resolve_binary("hermes")


if __name__ == "__main__":
    unittest.main()
