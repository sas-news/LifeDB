from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


REPO = Path(__file__).parents[1]
WRAPPER = REPO / "scripts" / "lifedb-compose.py"
TOKEN = "t" * 32


class ComposePreflightTest(unittest.TestCase):
    def run_wrapper(
        self,
        root: Path,
        *,
        vault: str,
        token_file: str,
        direct_token: str = "",
        arguments: tuple[str, ...] = ("config", "--quiet"),
        extra_env: dict[str, str] | None = None,
    ) -> subprocess.CompletedProcess[str]:
        marker = root / "docker-invoked"
        fake_docker = root / "docker"
        fake_docker.write_text(
            "#!/bin/sh\nprintf '%s\\n' \"$*\" > \"$LIFEDB_TEST_MARKER\"\nexit 23\n",
            encoding="utf-8",
        )
        fake_docker.chmod(0o700)
        env = os.environ.copy()
        env.update(
            {
                "PATH": str(root),
                "LIFEDB_VAULT": vault,
                "LIFEDB_API_TOKEN_FILE": token_file,
                "LIFEDB_TEST_MARKER": str(marker),
                "LIFEDB_API_TOKEN": direct_token,
            }
        )
        if extra_env is not None:
            env.update(extra_env)
        return subprocess.run(
            [sys.executable, str(WRAPPER), *arguments],
            cwd=REPO,
            env=env,
            capture_output=True,
            text=True,
            check=False,
        )

    def assert_not_invoked(self, result: subprocess.CompletedProcess[str], marker: Path) -> None:
        self.assertNotEqual(result.returncode, 23)
        self.assertFalse(marker.exists())
        self.assertNotIn(TOKEN, result.stderr)

    def test_relative_vault_is_rejected_before_docker(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            vault = root / "vault"
            vault.mkdir()
            token = root / "token"
            token.write_bytes(TOKEN.encode())
            token.chmod(0o600)
            result = self.run_wrapper(
                root, vault="relative-vault", token_file=str(token)
            )
            self.assert_not_invoked(result, root / "docker-invoked")

    def test_relative_token_is_rejected_before_docker(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            vault = root / "vault"
            vault.mkdir()
            result = self.run_wrapper(
                root, vault=str(vault), token_file="relative-token"
            )
            self.assert_not_invoked(result, root / "docker-invoked")

    def test_empty_host_path_is_rejected_before_docker(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            result = self.run_wrapper(root, vault="", token_file="")
            self.assert_not_invoked(result, root / "docker-invoked")

    def test_missing_token_is_rejected_before_docker(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            vault = root / "vault"
            vault.mkdir()
            result = self.run_wrapper(
                root, vault=str(vault), token_file=str(root / "missing-token")
            )
            self.assert_not_invoked(result, root / "docker-invoked")

    def test_final_token_symlink_is_rejected_before_docker(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            vault = root / "vault"
            vault.mkdir()
            real = root / "real-token"
            real.write_bytes(TOKEN.encode())
            real.chmod(0o600)
            link = root / "token"
            link.symlink_to(real)
            result = self.run_wrapper(root, vault=str(vault), token_file=str(link))
            self.assert_not_invoked(result, root / "docker-invoked")

    def test_permissive_token_is_rejected_before_docker(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            vault = root / "vault"
            vault.mkdir()
            token = root / "token"
            token.write_bytes(TOKEN.encode())
            token.chmod(0o644)
            result = self.run_wrapper(root, vault=str(vault), token_file=str(token))
            self.assert_not_invoked(result, root / "docker-invoked")

    def test_owner_readable_token_is_rejected_by_host_wrapper(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            vault = root / "vault"
            vault.mkdir()
            token = root / "token"
            token.write_bytes(TOKEN.encode())
            token.chmod(0o400)
            result = self.run_wrapper(root, vault=str(vault), token_file=str(token))
            self.assert_not_invoked(result, root / "docker-invoked")

    def test_direct_token_environment_is_rejected_before_docker(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            vault = root / "vault"
            vault.mkdir()
            token = root / "token"
            token.write_bytes(TOKEN.encode())
            token.chmod(0o600)
            result = self.run_wrapper(
                root,
                vault=str(vault),
                token_file=str(token),
                direct_token=TOKEN,
            )
            self.assert_not_invoked(result, root / "docker-invoked")

    def test_valid_inputs_invoke_docker_and_forward_status(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            vault = root / "vault"
            vault.mkdir()
            vault.chmod(0o700)
            token = root / "token"
            token.write_bytes(TOKEN.encode())
            token.chmod(0o600)
            result = self.run_wrapper(root, vault=str(vault), token_file=str(token))
            self.assertEqual(result.returncode, 23)
            self.assertEqual(
                (root / "docker-invoked").read_text().strip(),
                "compose -f " + str(REPO / "compose.yaml")
                + " --project-directory " + str(REPO)
                + " config --quiet",
            )
            self.assertNotIn(TOKEN, result.stderr)

    def test_non_directory_vault_is_rejected_before_docker(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            vault = root / "vault"
            vault.write_text("not a vault", encoding="utf-8")
            token = root / "token"
            token.write_bytes(TOKEN.encode())
            token.chmod(0o600)
            result = self.run_wrapper(root, vault=str(vault), token_file=str(token))
            self.assert_not_invoked(result, root / "docker-invoked")


if __name__ == "__main__":
    unittest.main()
