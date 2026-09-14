#!/usr/bin/env python3
"""Run the Task16 Docker Compose deployment and recovery scenario."""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass
from pathlib import Path
import secrets
import shutil
import socket
import subprocess
import sys
import time
from collections.abc import Mapping, Sequence
from typing import Final, Protocol, TypeAlias
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

JsonValue: TypeAlias = None | bool | int | float | str | list["JsonValue"] | dict[str, "JsonValue"]

WRAPPER: Final[str] = "scripts/lifedb-compose.py"
TOKEN_LENGTH: Final[int] = 32
FORBIDDEN: Final[frozenset[str]] = frozenset({
    "LIFEDB_API_TOKEN", "COMPOSE_FILE", "COMPOSE_ENV_FILES",
    "COMPOSE_PROJECT_DIRECTORY", "COMPOSE_PROJECT_NAME", "HTTP_PROXY",
    "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY", "OPENAI_API_KEY", "ANTHROPIC_API_KEY",
})


class ConfigurationFailure(Exception):
    """Deployment configuration cannot satisfy the approved wrapper contract."""


class CommandFailure(Exception):
    """A wrapper command returned a failed result."""

    def __init__(self, command: str, stderr: str) -> None:
        super().__init__(command)
        self.command = command
        self.stderr = stderr


class InspectionFailure(Exception):
    """The exact owned container does not satisfy Compose hardening."""


@dataclass(frozen=True, slots=True)
class CommandResult:
    returncode: int
    stdout: str
    stderr: str


class Runner(Protocol):
    def run(self, arguments: Sequence[str], env: Mapping[str, str], stdin: bytes | None = None) -> CommandResult: ...
    def inspect(self, container_id: str) -> str: ...


@dataclass(frozen=True, slots=True)
class InspectExpectation:
    vault: str
    token: str
    port: str
    user: str


@dataclass(frozen=True, slots=True)
class ScenarioConfig:
    vault: Path
    token: Path
    port: int
    project: str
    http_probe: bool = True
    owned_resources: bool = False

    @classmethod
    def for_test(cls, root: Path, port: int) -> "ScenarioConfig":
        return cls(root / "vault", root / "token", port, "task16-test", False, True)


@dataclass(frozen=True, slots=True)
class ScenarioReceipt:
    project_digest: str
    port: int
    search_marker: str


class SubprocessRunner:
    """Execute only the approved wrapper and exact-CID read-only inspection."""

    def __init__(self, repo: Path) -> None:
        self.repo = repo

    def run(self, arguments: Sequence[str], env: Mapping[str, str], stdin: bytes | None = None) -> CommandResult:
        completed = subprocess.run(
            [sys.executable, str(self.repo / WRAPPER), *arguments], cwd=self.repo,
            env=dict(env), input=stdin.decode() if stdin is not None else None,
            capture_output=True, text=True, check=False,
        )
        return CommandResult(completed.returncode, completed.stdout, completed.stderr)

    def inspect(self, container_id: str) -> str:
        completed = subprocess.run(("docker", "inspect", container_id), capture_output=True, text=True, check=False)
        if completed.returncode != 0:
            raise InspectionFailure("exact container inspect failed")
        return completed.stdout

    def assert_clean(self, project: str, container_id: str) -> None:
        inspected = subprocess.run(("docker", "inspect", container_id), capture_output=True, text=True, check=False)
        if inspected.returncode == 0:
            raise InspectionFailure("owned container remains after down")
        for command in (
            ("docker", "ps", "-aq", "--filter", f"label=com.docker.compose.project={project}"),
            ("docker", "network", "ls", "-q", "--filter", f"label=com.docker.compose.project={project}"),
        ):
            completed = subprocess.run(command, capture_output=True, text=True, check=False)
            if completed.returncode != 0 or completed.stdout.strip():
                raise InspectionFailure("owned Compose resources remain after down")


def _port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def build_environment(vault: Path, token: Path, port: int) -> dict[str, str]:
    """Build the complete child environment without inheriting caller secrets."""
    if not vault.is_absolute() or not token.is_absolute() or not 1 <= port <= 65535:
        raise ConfigurationFailure("absolute paths and a nonzero port are required")
    if os.getuid() == 0 or os.getgid() == 0:
        raise ConfigurationFailure("root execution is not supported")
    return {
        "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8", "LIFEDB_VAULT": str(vault),
        "LIFEDB_API_TOKEN_FILE": str(token), "LIFEDB_UID": str(os.getuid()),
        "LIFEDB_GID": str(os.getgid()), "LIFEDB_BIND": "127.0.0.1",
        "LIFEDB_PORT": str(port), "LIFEDB_SENSITIVITY_CEILING": "personal",
        "LIFEDB_INGEST_SENSITIVITY_FLOOR": "personal",
    }


def _check_environment(env: Mapping[str, str]) -> None:
    if FORBIDDEN.intersection(env):
        raise ConfigurationFailure("forbidden environment key")


def _command(runner: Runner, arguments: Sequence[str], env: Mapping[str, str], stdin: bytes | None = None) -> CommandResult:
    result = runner.run(arguments, env, stdin)
    if result.returncode != 0:
        raise CommandFailure(" ".join(arguments), result.stderr)
    return result


def _value(mapping: Mapping[str, JsonValue], key: str) -> JsonValue:
    if key not in mapping:
        raise InspectionFailure("inspect field missing")
    return mapping[key]


def parse_inspect(raw: str, expected: InspectExpectation) -> None:
    """Parse and verify only the security and bind properties needed by Task16."""
    decoded = json.loads(raw)
    if not isinstance(decoded, list) or len(decoded) != 1 or not isinstance(decoded[0], dict):
        raise InspectionFailure("inspect response shape is invalid")
    item = decoded[0]
    config = _value(item, "Config")
    host = _value(item, "HostConfig")
    state = _value(item, "State")
    network = _value(item, "NetworkSettings")
    mounts = _value(item, "Mounts")
    if not all(isinstance(value, dict) for value in (config, host, state, network)) or not isinstance(mounts, list):
        raise InspectionFailure("inspect sections are invalid")
    if _value(config, "User") != expected.user or _value(host, "ReadonlyRootfs") is not True:
        raise InspectionFailure("container user or rootfs hardening mismatch")
    if _value(host, "CapDrop") != ["ALL"] or "no-new-privileges:true" not in _value(host, "SecurityOpt"):
        raise InspectionFailure("container capability hardening mismatch")
    health = _value(_value(state, "Health"), "Status")
    if health != "healthy":
        raise InspectionFailure("container health is not healthy")
    port_entries = _value(_value(network, "Ports"), "7331/tcp")
    if not isinstance(port_entries, list) or len(port_entries) != 1:
        raise InspectionFailure("published port mapping is invalid")
    port_entry = port_entries[0]
    if not isinstance(port_entry, dict) or _value(port_entry, "HostIp") != "127.0.0.1" or _value(port_entry, "HostPort") != expected.port:
        raise InspectionFailure("published port mapping is unsafe")
    required = {expected.vault: ("/data", True), expected.token: ("/run/secrets/lifedb-api-token", False)}
    for mount in mounts:
        if isinstance(mount, dict) and mount.get("Source") in required:
            destination, writable = required.pop(str(mount["Source"]))
            if mount.get("Destination") != destination or mount.get("RW") is not writable:
                raise InspectionFailure("bind mount permissions mismatch")
    if required:
        raise InspectionFailure("required bind mount missing")


def _http_probe(port: int, token: str, marker: str) -> None:
    url = f"http://127.0.0.1:{port}"
    with urlopen(f"{url}/health", timeout=3) as response:
        if response.status != 200:
            raise CommandFailure("GET /health", str(response.status))
    request = Request(f"{url}/v1/context", data=json.dumps({"query": marker}).encode(), method="POST", headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"})
    with urlopen(request, timeout=3) as response:
        if response.status != 200:
            raise CommandFailure("POST /v1/context", str(response.status))


def _attempt(repo: Path, runner: Runner, config: ScenarioConfig) -> ScenarioReceipt:
    vault_created = not config.vault.exists()
    token_created = not config.token.exists()
    if vault_created:
        config.vault.mkdir(parents=True)
    if token_created:
        token_fd = os.open(str(config.token), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(token_fd, "wb") as token_file:
            token_file.write(secrets.token_urlsafe(TOKEN_LENGTH).encode())
    env = build_environment(config.vault, config.token, config.port)
    _check_environment(env)
    project = config.project
    project_digest = hashlib.sha256(project.encode()).hexdigest()[:16]
    marker = f"task16-marker-{project_digest}"
    started = False
    cid = ""
    try:
        prefix = ("-p", project)
        _command(runner, (*prefix, "config", "--quiet"), env)
        _command(runner, (*prefix, "run", "--rm", "lifedb", "init"), env)
        _command(runner, (*prefix, "run", "--rm", "-T", "lifedb", "ingest", "-", "--source", "task16", "--media-type", "text/plain"), env, f"{marker}\n".encode())
        _command(runner, (*prefix, "up", "-d", "--build", "lifedb"), env)
        started = True
        cid = _command(runner, (*prefix, "ps", "-q", "lifedb"), env).stdout.strip()
        if not cid:
            raise InspectionFailure("wrapper returned no container id")
        if config.http_probe:
            deadline = time.monotonic() + 45
            while True:
                try:
                    _http_probe(config.port, config.token.read_text(encoding="utf-8"), marker)
                    break
                except (ConnectionRefusedError, ConnectionResetError, HTTPError, TimeoutError, URLError):
                    if time.monotonic() >= deadline:
                        raise CommandFailure("HTTP health", "health timeout")
                    time.sleep(1)
        expectation = InspectExpectation(str(config.vault), str(config.token), str(config.port), f"{os.getuid()}:{os.getgid()}")
        inspection_deadline = time.monotonic() + 45
        while True:
            try:
                parse_inspect(runner.inspect(cid), expectation)
                break
            except InspectionFailure as error:
                if "health" not in str(error) or time.monotonic() >= inspection_deadline:
                    raise
                time.sleep(1)
        _command(runner, (*prefix, "stop", "lifedb"), env)
        _command(runner, (*prefix, "run", "--rm", "lifedb", "runtime", "reset", "--confirm", "DELETE-RUNTIME"), env)
        _command(runner, (*prefix, "run", "--rm", "lifedb", "rebuild"), env)
        _command(runner, (*prefix, "up", "-d", "--build", "lifedb"), env)
        _command(runner, (*prefix, "run", "--rm", "lifedb", "validate"), env)
        search = _command(runner, (*prefix, "run", "--rm", "lifedb", "search", marker), env)
        if marker not in search.stdout:
            raise CommandFailure("search marker", "marker absent")
        _command(runner, (*prefix, "run", "--rm", "lifedb", "doctor"), env)
        return ScenarioReceipt(project_digest, config.port, marker)
    finally:
        if started and config.owned_resources:
            _command(runner, ("-p", project, "down"), env)
            if isinstance(runner, SubprocessRunner) and cid:
                runner.assert_clean(project, cid)
        if token_created:
            config.token.unlink(missing_ok=True)
        if vault_created and config.vault.exists():
            shutil.rmtree(config.vault)


def compose_scenario(repo: Path, runner: Runner | None = None, config: ScenarioConfig | None = None) -> ScenarioReceipt:
    """Run one isolated deployment/recovery attempt and return no secret material."""
    active_runner = runner or SubprocessRunner(repo)
    if config is not None:
        return _attempt(repo, active_runner, config)
    from tempfile import TemporaryDirectory
    for _ in range(3):
        with TemporaryDirectory(prefix="lifedb-task16-") as directory:
            root = Path(directory)
            generated = ScenarioConfig(root / "vault", root / "token", _port(), f"task16-{secrets.token_hex(5)}", True, True)
            try:
                return _attempt(repo, active_runner, generated)
            except CommandFailure as error:
                if "address already in use" not in error.stderr.lower() and "bind" not in error.stderr.lower():
                    raise
    raise ConfigurationFailure("port collision retry budget exhausted")


if __name__ == "__main__":
    print(compose_scenario(Path(__file__).resolve().parents[1]))
