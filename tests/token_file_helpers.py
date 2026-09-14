from __future__ import annotations

import contextlib
import io
import os
import tempfile
import unittest
from dataclasses import dataclass
from pathlib import Path
from unittest.mock import patch

import lifedb.cli as cli_module
from lifedb import auth
from lifedb.vault import Vault


def valid_token(length: int = 40, char: str = "a") -> str:
    return char * length


def write_token_file(directory: Path, name: str, payload: bytes, mode: int = 0o600) -> str:
    target = directory / name
    descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(descriptor, payload)
    finally:
        os.close(descriptor)
    os.chmod(target, mode)
    return str(target)


@dataclass(frozen=True)
class ServeCall:
    api_token: str | None
    sensitivity_ceiling: str
    ingest_sensitivity_floor: str


@dataclass(frozen=True)
class ServeResult:
    exit_code: int
    stdout: str
    stderr: str
    calls: list[ServeCall]


def run_serve(vault: Path, env: dict[str, str]) -> ServeResult:
    calls: list[ServeCall] = []

    def fake_serve(
        target_vault: Vault,
        bind: str,
        port: int,
        *,
        api_token: str | None,
        sensitivity_ceiling: str = "personal",
        ingest_sensitivity_floor: str = "personal",
    ) -> None:
        calls.append(
            ServeCall(
                api_token=api_token,
                sensitivity_ceiling=sensitivity_ceiling,
                ingest_sensitivity_floor=ingest_sensitivity_floor,
            )
        )

    output = io.StringIO()
    errors = io.StringIO()
    with patch.object(cli_module, "serve", side_effect=fake_serve):
        with patch.dict(os.environ, env, clear=False):
            for key in (auth.DIRECT_TOKEN_ENV, auth.FILE_TOKEN_ENV):
                if key not in env:
                    os.environ.pop(key, None)
            with contextlib.redirect_stdout(output), contextlib.redirect_stderr(errors):
                exit_code = cli_module.main(
                    ["--vault", str(vault), "serve", "--port", "0"]
                )
    return ServeResult(
        exit_code=exit_code,
        stdout=output.getvalue(),
        stderr=errors.getvalue(),
        calls=calls,
    )


class TokenFileCase(unittest.TestCase):
    temporary: tempfile.TemporaryDirectory[str]
    directory: Path

    def setUp(self) -> None:
        super().setUp()
        self.temporary = tempfile.TemporaryDirectory()
        self.directory = Path(self.temporary.name)

    def tearDown(self) -> None:
        self.temporary.cleanup()
        super().tearDown()
