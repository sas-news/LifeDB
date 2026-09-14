#!/usr/bin/env python3
"""Validate host bind sources before invoking Docker Compose.

Run from the repository root as ``python scripts/lifedb-compose.py ...``.
The wrapper does not create, initialize, or modify the vault or token file.
"""

# /// script
# requires-python = ">=3.11"
# ///

from __future__ import annotations

import os
import re
import stat
import subprocess
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path

script_directory = str(Path(__file__).resolve().parent)
if script_directory not in sys.path:
    sys.path.insert(0, script_directory)
from lifedb_compose_args import reject_run_overrides
from lifedb_compose_dotenv import parse_dotenv_value as _parse_dotenv_value
from lifedb_compose_dotenv import read_dotenv as _read_dotenv


DIRECT_TOKEN_ENV = "LIFEDB_API_TOKEN"
FILE_TOKEN_ENV = "LIFEDB_API_TOKEN_FILE"
VAULT_ENV = "LIFEDB_VAULT"
COMPOSE_FILE_ENV = "COMPOSE_FILE"
COMPOSE_ENV_FILES_ENV = "COMPOSE_ENV_FILES"
COMPOSE_PROJECT_DIRECTORY_ENV = "COMPOSE_PROJECT_DIRECTORY"
COMPOSE_PROJECT_NAME_ENV = "COMPOSE_PROJECT_NAME"
UID_ENV = "LIFEDB_UID"
GID_ENV = "LIFEDB_GID"
BIND_ENV = "LIFEDB_BIND"
PORT_ENV = "LIFEDB_PORT"


_PROJECT_NAME = re.compile(r"^[a-z0-9][a-z0-9_-]{0,62}$")
repository = Path(__file__).resolve().parents[1]
source = str(repository / "src")
if source not in sys.path:
    sys.path.insert(0, source)
from lifedb.auth import resolve_api_token

DOTENV_PATH = repository / ".env"


class ComposeWrapperError(ValueError):
    """A Compose wrapper input failed its host safety contract."""


def _effective_environment(env: Mapping[str, str]) -> dict[str, str]:
    """Merge repository .env defaults, with process environment taking precedence."""

    try:
        dotenv_values = _read_dotenv(DOTENV_PATH)
    except FileNotFoundError:
        dotenv_values = {}
    merged = dict(dotenv_values)
    merged.update(env)
    return merged


def _reject_compose_overrides(arguments: Sequence[str], env: Mapping[str, str]) -> None:
    forbidden = {
        COMPOSE_FILE_ENV,
        COMPOSE_ENV_FILES_ENV,
        COMPOSE_PROJECT_DIRECTORY_ENV,
        COMPOSE_PROJECT_NAME_ENV,
    }
    if any(env.get(name, "") for name in forbidden):
        raise ComposeWrapperError("Compose override configuration is not supported")
    for argument in arguments:
        if (
            argument in {"-f", "--file", "--env-file", "--project-directory"}
            or argument.startswith("--file=")
            or argument.startswith("--env-file=")
            or argument.startswith("--project-directory=")
            or (argument.startswith("-f") and argument != "-f")
        ):
            raise ComposeWrapperError("Compose override arguments are not supported")
    for index, argument in enumerate(arguments):
        if argument == "--project-name" or argument.startswith("--project-name="):
            raise ComposeWrapperError("long project-name override is not supported")
        if argument == "-p":
            if index + 1 >= len(arguments) or not _PROJECT_NAME.fullmatch(arguments[index + 1]):
                raise ComposeWrapperError("project name is invalid")
        elif argument.startswith("-p") and argument != "-p":
            if not _PROJECT_NAME.fullmatch(argument[2:]):
                raise ComposeWrapperError("project name is invalid")
    reject_run_overrides(arguments)


def _required_absolute(env: Mapping[str, str], name: str) -> str:
    value = env.get(name, "")
    if not value or not os.path.isabs(value):
        raise ComposeWrapperError("host path configuration is invalid")
    return value


def _validate_vault(path_value: str) -> None:
    try:
        metadata = os.lstat(path_value)
    except OSError:
        raise ComposeWrapperError("host vault configuration is invalid") from None
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise ComposeWrapperError("host vault configuration is invalid")


def _validate_host(env: Mapping[str, str]) -> None:
    vault = _required_absolute(env, VAULT_ENV)
    token_file = _required_absolute(env, FILE_TOKEN_ENV)
    _validate_vault(vault)
    if env.get(DIRECT_TOKEN_ENV, ""):
        raise ComposeWrapperError("direct API token configuration is not supported")
    try:
        token_metadata = os.lstat(token_file)
    except OSError:
        raise ComposeWrapperError("host token configuration is invalid") from None
    if stat.S_IMODE(token_metadata.st_mode) != 0o600:
        raise ComposeWrapperError("host token configuration is invalid")
    resolve_api_token(None, token_file)
    expected_uid = str(os.getuid())
    expected_gid = str(os.getgid())
    if os.getuid() == 0 or env.get(UID_ENV, expected_uid) != expected_uid:
        raise ComposeWrapperError("container user configuration is invalid")
    if os.getgid() == 0 or env.get(GID_ENV, expected_gid) != expected_gid:
        raise ComposeWrapperError("container group configuration is invalid")
    if env.get(BIND_ENV, "127.0.0.1") != "127.0.0.1":
        raise ComposeWrapperError("host bind configuration is invalid")
    try:
        port = int(env.get(PORT_ENV, "7331"))
    except ValueError:
        raise ComposeWrapperError("host port configuration is invalid") from None
    if not 1 <= port <= 65535:
        raise ComposeWrapperError("host port configuration is invalid")


def _normalize_status(status: int) -> int:
    return 128 - status if status < 0 else status


def run(arguments: Sequence[str], env: Mapping[str, str]) -> int:
    """Validate host inputs, then execute Docker Compose."""

    if not arguments:
        raise ComposeWrapperError("a Docker Compose command is required")
    if len(arguments) == 1 and arguments[0] in {"-h", "--help"}:
        print("usage: python scripts/lifedb-compose.py <docker-compose-arguments>")
        return 0
    _reject_compose_overrides(arguments, env)
    _validate_host(env)
    child_env = dict(env)
    child_env.setdefault(UID_ENV, str(os.getuid()))
    child_env.setdefault(GID_ENV, str(os.getgid()))
    child_env.setdefault(BIND_ENV, "127.0.0.1")
    child_env.setdefault(PORT_ENV, "7331")
    child_env.pop(DIRECT_TOKEN_ENV, None)
    child_env.pop(COMPOSE_FILE_ENV, None)
    child_env.pop(COMPOSE_ENV_FILES_ENV, None)
    child_env.pop(COMPOSE_PROJECT_DIRECTORY_ENV, None)
    completed = subprocess.run(
        [
            "docker",
            "compose",
            "-f",
            str(repository / "compose.yaml"),
            "--project-directory",
            str(repository),
            *arguments,
        ],
        env=child_env,
        check=False,
    )
    return _normalize_status(completed.returncode)


def main() -> int:
    """Provide a sanitized boundary for deployment configuration errors."""

    try:
        return run(sys.argv[1:], _effective_environment(os.environ))
    except (OSError, TypeError, ValueError):
        print("lifedb: host Compose preflight rejected deployment inputs", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
