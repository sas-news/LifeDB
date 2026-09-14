from __future__ import annotations

import importlib.util
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


REPO = Path(__file__).parents[1]
WRAPPER = REPO / "scripts" / "lifedb-compose.py"
TOKEN = "t" * 32


def load_wrapper() -> object:
    spec = importlib.util.spec_from_file_location("lifedb_compose", WRAPPER)
    if spec is None or spec.loader is None:
        raise RuntimeError("wrapper module could not be loaded")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class ComposeWrapperContractTest(unittest.TestCase):
    def run_wrapper(
        self,
        root: Path,
        arguments: tuple[str, ...],
        extra_env: dict[str, str] | None = None,
    ) -> subprocess.CompletedProcess[str]:
        marker = root / "docker-invoked"
        fake_docker = root / "docker"
        fake_docker.write_text(
            "#!/bin/sh\nprintf '%s\\n' \"$*\" > \"$LIFEDB_TEST_MARKER\"\nexit 23\n",
            encoding="utf-8",
        )
        fake_docker.chmod(0o700)
        vault = root / "vault"
        vault.mkdir()
        token = root / "token"
        token.write_bytes(TOKEN.encode())
        token.chmod(0o600)
        env = os.environ.copy()
        env.update(
            {
                "PATH": str(root),
                "LIFEDB_VAULT": str(vault),
                "LIFEDB_API_TOKEN_FILE": str(token),
                "LIFEDB_TEST_MARKER": str(marker),
            }
        )
        if extra_env is not None:
            env.update(extra_env)
        return subprocess.run(
            [str(Path(sys.executable)), str(WRAPPER), *arguments],
            cwd=REPO,
            env=env,
            capture_output=True,
            text=True,
            check=False,
        )

    def assert_rejected(self, result: subprocess.CompletedProcess[str], root: Path) -> None:
        self.assertNotEqual(result.returncode, 23)
        self.assertFalse((root / "docker-invoked").exists())
        self.assertNotIn(TOKEN, result.stderr)

    def test_compose_file_and_project_overrides_are_rejected(self) -> None:
        for arguments in (
            ("-f", "alternate.yaml", "config"),
            ("-falternate.yaml", "config"),
            ("--file=alternate.yaml", "config"),
            ("--project-directory", "/tmp", "config"),
            ("--project-directory=/tmp", "config"),
            ("--env-file", "alternate.env", "config"),
            ("--env-file=alternate.env", "config"),
        ):
            with self.subTest(arguments=arguments), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                result = self.run_wrapper(root, arguments)
                self.assert_rejected(result, root)

    def test_compose_environment_overrides_are_rejected(self) -> None:
        for name, value in (
            ("COMPOSE_FILE", "alternate.yaml"),
            ("COMPOSE_ENV_FILES", "alternate.env"),
            ("COMPOSE_PROJECT_DIRECTORY", "/tmp"),
            ("COMPOSE_PROJECT_NAME", "alternate-project"),
        ):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                result = self.run_wrapper(root, ("config",), {name: value})
            self.assert_rejected(result, root)

    def test_run_mount_and_environment_overrides_are_rejected(self) -> None:
        for arguments in (
            ("run", "--rm", "-v", "/tmp/other:/data", "lifedb", "validate"),
            ("run", "--rm", "--volume", "/tmp/other:/data", "lifedb", "validate"),
            ("run", "--rm", "--volume=/tmp/other:/data", "lifedb", "validate"),
            ("run", "--rm", "-e", "LIFEDB_API_TOKEN=unsafe", "lifedb", "validate"),
            ("run", "--rm", "--env", "LIFEDB_API_TOKEN=unsafe", "lifedb", "validate"),
            ("run", "--rm", "--env=LIFEDB_API_TOKEN=unsafe", "lifedb", "validate"),
        ):
            with self.subTest(arguments=arguments), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                result = self.run_wrapper(root, arguments)
                self.assert_rejected(result, root)

    def test_compose_long_project_name_and_deployment_overrides_are_rejected(self) -> None:
        cases = (
            (("--project-name", "alternate-project", "config"), {}),
            (("--project-name=alternate-project", "config"), {}),
            (("config",), {"LIFEDB_UID": "0"}),
            (("config",), {"LIFEDB_GID": "0"}),
            (("config",), {"LIFEDB_BIND": "0.0.0.0"}),
            (("config",), {"LIFEDB_BIND": "127.0.0.1", "LIFEDB_PORT": "0"}),
            (("config",), {"LIFEDB_BIND": "127.0.0.1", "LIFEDB_PORT": "65536"}),
        )
        for arguments, extra_env in cases:
            with self.subTest(arguments=arguments, extra_env=extra_env), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                result = self.run_wrapper(root, arguments, extra_env)
                self.assert_rejected(result, root)

    def test_service_command_arguments_are_not_overblocked(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            result = self.run_wrapper(root, ("run", "--rm", "lifedb", "validate", "--env", "literal"))
            self.assertEqual(result.returncode, 23)

    def test_sigterm_is_normalized_to_conventional_status(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            marker = root / "docker-invoked"
            fake_docker = root / "docker"
            fake_docker.write_text("#!/bin/sh\nkill -TERM $$\n", encoding="utf-8")
            fake_docker.chmod(0o700)
            vault = root / "vault"
            vault.mkdir()
            token = root / "token"
            token.write_bytes(TOKEN.encode())
            token.chmod(0o600)
            env = os.environ.copy()
            env.update(
                {
                    "PATH": str(root),
                    "LIFEDB_VAULT": str(vault),
                    "LIFEDB_API_TOKEN_FILE": str(token),
                    "LIFEDB_TEST_MARKER": str(marker),
                }
            )
            result = subprocess.run(
                [str(Path(sys.executable)), str(WRAPPER), "config"],
                cwd=REPO,
                env=env,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(result.returncode, 143)

    def test_unique_project_name_is_forwarded_after_owned_flags(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            result = self.run_wrapper(root, ("-p", "isolated-project", "config"))
            self.assertEqual(result.returncode, 23)
            self.assertIn(" -p isolated-project config", (root / "docker-invoked").read_text())

    def test_dotenv_parser_does_not_evaluate_shell_syntax(self) -> None:
        module = load_wrapper()
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / ".env"
            path.write_text(
                "SAFE=literal $(touch SHOULD_NOT_EXIST)\nQUOTED=\"value # kept\"\n",
                encoding="utf-8",
            )
            values = module._read_dotenv(path)
            self.assertEqual(values["SAFE"], "literal $(touch SHOULD_NOT_EXIST)")
            self.assertEqual(values["QUOTED"], "value # kept")
            self.assertFalse((Path(temporary) / "SHOULD_NOT_EXIST").exists())

    def test_dotenv_symlink_is_rejected(self) -> None:
        module = load_wrapper()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            target = root / "real.env"
            target.write_text("LIFEDB_PORT=7331\n", encoding="utf-8")
            link = root / ".env"
            link.symlink_to(target)
            with self.assertRaises(ValueError):
                module._read_dotenv(link)

    def test_malformed_dotenv_is_rejected(self) -> None:
        module = load_wrapper()
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / ".env"
            path.write_text("not-an-assignment\nBROKEN=\"unterminated\n", encoding="utf-8")
            with self.assertRaises(ValueError):
                module._read_dotenv(path)

    def test_process_environment_takes_precedence_over_dotenv(self) -> None:
        module = load_wrapper()
        original = module.DOTENV_PATH
        try:
            with tempfile.TemporaryDirectory() as temporary:
                module.DOTENV_PATH = Path(temporary) / ".env"
                module.DOTENV_PATH.write_text("LIFEDB_PORT=7331\n", encoding="utf-8")
                self.assertEqual(
                    module._effective_environment({"LIFEDB_PORT": "17422"})["LIFEDB_PORT"],
                    "17422",
                )
        finally:
            module.DOTENV_PATH = original


if __name__ == "__main__":
    unittest.main()
