from __future__ import annotations

import importlib.util
import os
import sys
import tempfile
import unittest
from unittest.mock import patch
from pathlib import Path


REPO = Path(__file__).parents[1]
WRAPPER = REPO / "scripts" / "lifedb-compose.py"
TOKEN = "t" * 32


def load_wrapper() -> object:
    spec = importlib.util.spec_from_file_location("lifedb_compose_task12", WRAPPER)
    if spec is None or spec.loader is None:
        raise RuntimeError("wrapper module could not be loaded")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class Task12RunBoundaryTest(unittest.TestCase):
    def run_wrapper(self, root: Path, arguments: tuple[str, ...]) -> int:
        marker = root / "docker-invoked"
        fake_docker = root / "docker"
        fake_docker.write_text(
            "#!/bin/sh\nprintf invoked > \"$LIFEDB_TEST_MARKER\"\nexit 23\n",
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
        return os.spawnve(
            os.P_WAIT,
            sys.executable,
            [sys.executable, str(WRAPPER), *arguments],
            env,
        )

    def test_mount_aliases_are_rejected(self) -> None:
        for key in ("target", "destination", "dst"):
            for spelling in ("--mount",):
                with self.subTest(key=key, spelling=spelling), tempfile.TemporaryDirectory() as temporary:
                    arguments = (
                        "run",
                        "--rm",
                        spelling,
                        f"type=bind,source=/tmp/x,{key}=/data",
                        "lifedb",
                        "validate",
                    )
                    status = self.run_wrapper(Path(temporary), arguments)
                    self.assertNotEqual(status, 23)
            with tempfile.TemporaryDirectory() as temporary:
                arguments = (
                    "run",
                    "--rm",
                    f"--mount=type=bind,source=/tmp/x,{key}=/data",
                    "lifedb",
                    "validate",
                )
                status = self.run_wrapper(Path(temporary), arguments)
                self.assertNotEqual(status, 23)

    def test_run_security_options_are_rejected_in_short_compact_forms(self) -> None:
        for option in ("-u0", "-p0.0.0.0:9999:7331"):
            with self.subTest(option=option), tempfile.TemporaryDirectory() as temporary:
                status = self.run_wrapper(
                    Path(temporary), ("run", "--rm", option, "lifedb", "validate")
                )
                self.assertNotEqual(status, 23)

    def test_run_security_options_are_rejected_in_all_long_forms(self) -> None:
        cases = (
            ("--user", "0"),
            ("--entrypoint", "/bin/sh"),
            ("--privileged", ""),
            ("--cap-add", "SYS_ADMIN"),
            ("--security-opt", "no-new-privileges:false"),
            ("--publish", "0.0.0.0:9999:7331"),
            ("--network", "host"),
            ("--volumes-from", "other"),
            ("--device", "/dev/null:/dev/x"),
        )
        for option, value in cases:
            spellings = (option, f"{option}={value}") if value else (option,)
            for spelling in spellings:
                with self.subTest(spelling=spelling), tempfile.TemporaryDirectory() as temporary:
                    arguments = ("run", "--rm", spelling)
                    if value and spelling == option:
                        arguments += (value,)
                    arguments += ("lifedb", "validate")
                    status = self.run_wrapper(Path(temporary), arguments)
                    self.assertNotEqual(status, 23)

    def test_service_command_security_looking_arguments_remain_allowed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            status = self.run_wrapper(
                Path(temporary),
                ("run", "--rm", "lifedb", "validate", "--network", "literal"),
            )
            self.assertEqual(status, 23)


class Task12DotenvRaceTest(unittest.TestCase):
    def test_path_swap_after_open_is_rejected(self) -> None:
        module = load_wrapper()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path = root / ".env"
            replacement = root / "replacement.env"
            path.write_text("LIFEDB_PORT=7331\n", encoding="utf-8")
            replacement.write_text("LIFEDB_PORT=9999\n", encoding="utf-8")
            original_open = module.os.open

            def swap_path(path_value: Path, flags: int) -> int:
                descriptor = original_open(path_value, flags)
                path.unlink()
                path.symlink_to(replacement)
                return descriptor

            with patch.object(module.os, "open", side_effect=swap_path):
                with self.assertRaises(ValueError):
                    module._read_dotenv(path)


if __name__ == "__main__":
    unittest.main()
