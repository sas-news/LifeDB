from __future__ import annotations

from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from integrations.hermes.installer.core import InstallOptions, InstallerError, lifecycle
from integrations.hermes.installer.process import check_version_output


class ProcessContractTests(unittest.TestCase):
    def test_version_requires_one_exact_line(self) -> None:
        check_version_output(
            b"Hermes Agent v0.21.0 (2026.8.31) \xc2\xb7 upstream a0749d58\n"
            b"Install directory: /isolated/hermes\nInstall method: git\n"
            b"Python: 3.11.16\nOpenAI SDK: 2.24.0\n"
            b"Update available: 1 commits behind \xe2\x80\x94 run 'hermes update'\n",
            b"",
            0,
        )
        for output in (
            b"Hermes Agent v0.21.0 (2026.8.31)\nextra\n",
            b"Hermes Agent v0.21.0 (2026.8.31)\r\n",
            b" Hermes Agent v0.21.0 (2026.8.31)\n",
            b"Hermes Agent v0.21.1 (2026.8.31)\n",
        ):
            with self.assertRaises(InstallerError):
                check_version_output(output, b"", 0)

    def test_check_requires_no_token_and_writes_nothing(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            (home / "config.yaml").write_text("plugins: {}\n", encoding="utf-8")
            options = InstallOptions("http://127.0.0.1:7331", home / "missing", None, 2.0, 1_048_576, 4_194_304, None, 12_000, 4_000, 2_000, 6_000, 8)
            with patch("integrations.hermes.installer.core.run_host_checks"):
                lifecycle(home, "check", options, hermes_binary="hermes")
            self.assertFalse((home / ".lifedb-installer.lock").exists())


if __name__ == "__main__":
    unittest.main()
