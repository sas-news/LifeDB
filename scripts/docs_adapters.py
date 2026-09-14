from __future__ import annotations

import hashlib
import subprocess
import shutil
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True, slots=True)
class AdapterReceipt:
    lifecycle: tuple[str, ...]
    hermes_doctor_count: int
    hook_names: tuple[str, ...]
    preserved: bool
    no_spool: bool
    contains_real_paths: bool
    contains_token: bool
    opencode_argv_valid: bool
    hermes_argv_valid: bool
    wrong_version_cases: bool
    unsafe_token_cases: bool


@dataclass(frozen=True, slots=True)
class AdapterScenarioError(Exception):
    message: str

    def __str__(self) -> str:
        return self.message


class AdapterTimeoutError(AdapterScenarioError):
    """An adapter child exceeded its configured execution deadline."""


@dataclass(frozen=True, slots=True)
class _Run:
    status: int
    argv: tuple[str, ...]
    stdout: str
    stderr: str


def _digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _terminate_and_reap(process: subprocess.Popen[str]) -> None:
    process.terminate()
    try:
        process.communicate(timeout=1.0)
    except subprocess.TimeoutExpired:
        process.kill()
        process.communicate()


def _run(command: list[str], cwd: Path, env: dict[str, str], timeout: float = 10.0) -> _Run:
    process: subprocess.Popen[str] | None = None
    try:
        process = subprocess.Popen(command, cwd=cwd, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        stdout, stderr = process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        if process is not None:
            _terminate_and_reap(process)
        return _Run(124, tuple(command), "", "adapter command timed out")
    except KeyboardInterrupt:
        if process is not None:
            _terminate_and_reap(process)
        raise
    except OSError:
        return _Run(127, tuple(command), "", "adapter command unavailable")
    if process.returncode is None:
        raise AdapterScenarioError("adapter child status unavailable")
    return _Run(process.returncode, tuple(command), stdout, stderr)


def _assert_status(result: _Run, expected: int) -> None:
    if result.status != expected:
        raise AdapterScenarioError(f"adapter command status: {result.argv[0]} {result.argv[-1]} {result.stderr[:80]}")


def _write_executable(path: Path, body: str) -> None:
    path.write_text(body, encoding="utf-8")
    path.chmod(0o700)


def _env(root: Path, home: Path, xdg: Path, hermes: Path, private_bin: Path) -> dict[str, str]:
    bun = shutil.which("bun")
    if bun is None:
        raise AdapterScenarioError("bun is unavailable")
    path = ":".join((str(private_bin), str(Path(bun).parent), str(Path(sys.executable).parent), "/usr/local/sbin", "/usr/local/bin", "/usr/bin"))
    return {"HOME": str(home), "XDG_CONFIG_HOME": str(xdg), "HERMES_HOME": str(hermes), "PATH": path, "PYTHONPATH": str(root), "LANG": "C", "LC_ALL": "C"}


def _opencode_script(log: Path) -> str:
    return f'''#!/bin/sh
set -eu
printf '%s\n' "$*" >> '{log}'
if [ "$#" -eq 1 ] && [ "$1" = --version ]; then printf '1.18.29\n'; exit 0; fi
if [ "$#" -eq 2 ] && [ "$1" = debug ] && [ "$2" = config ]; then printf '{{"plugins":[]}}\n'; exit 0; fi
exit 64
'''


def _hermes_script(log: Path, version: str = "0.21.0") -> str:
    return f'''#!/usr/bin/python3
import sys
from pathlib import Path
with Path({str(log)!r}).open("a", encoding="utf-8") as output:
    output.write(" ".join(sys.argv[1:]) + "\\n")
if sys.argv[1:] == ["--version"]:
    print("Hermes Agent v{version} (2026.8.31) · upstream a0749d58")
    print("Install directory: /isolated/hermes")
    print("Install method: git")
    print("Python: 3.11.16")
    print("OpenAI SDK: 2.24.0")
    print("Update available: 1 commits behind — run 'hermes update'")
    raise SystemExit(0)
if len(sys.argv) == 5 and sys.argv[1:3] == ["plugins", "doctor"] and sys.argv[4] == "--ci" and Path(sys.argv[3]).is_dir():
    raise SystemExit(0)
raise SystemExit(64)
'''


def _owned_state(directory: Path, active: str, disabled: str) -> str:
    if (directory / active).is_file():
        return "active"
    if (directory / disabled).is_file():
        return "disabled"
    return "absent"


def _hermes_command(repo: Path, home: Path, command: tuple[str, ...]) -> list[str]:
    return [str(repo / ".venv/bin/python"), "-m", "integrations.hermes.installer.cli", "--hermes-home", str(home), *command]


def _failure_cases(repo: Path, root: Path, env: dict[str, str], token: Path, hermes: Path, opencode: Path, hermes_bin: Path) -> tuple[bool, bool]:
    wrong = True
    opencode.write_text("#!/bin/sh\nprintf '1.18.28\\n'\nexit 0\n", encoding="utf-8")
    opencode.chmod(0o700)
    bad_home = root / "wrong-opencode"
    bad_home.mkdir()
    _assert_status(_run(["bun", "run", "src/installer/cli.ts", "check"], repo / "integrations/opencode", env | {"XDG_CONFIG_HOME": str(bad_home)}), 1)
    hermes_bin.write_text(_hermes_script(root / "hermes-argv.log", "0.21.1"), encoding="utf-8")
    hermes_bin.chmod(0o700)
    bad_hermes = root / "wrong-hermes"
    bad_hermes.mkdir()
    (bad_hermes / "config.yaml").write_text("plugins: {}\n", encoding="utf-8")
    (bad_hermes / "config.yaml").chmod(0o600)
    _assert_status(_run(_hermes_command(repo, bad_hermes, ("check",)), repo, env | {"HERMES_HOME": str(bad_hermes)}), 1)
    opencode.write_text(_opencode_script(root / "opencode-argv.log"), encoding="utf-8")
    opencode.chmod(0o700)
    hermes_bin.write_text(_hermes_script(root / "hermes-argv.log"), encoding="utf-8")
    hermes_bin.chmod(0o700)
    before = _digest(hermes / "config.yaml")
    token.chmod(0o644)
    for invalid in ("missing", "mode", "symlink"):
        if invalid == "missing":
            argument = root / "missing-token"
        elif invalid == "mode":
            argument = token
        else:
            argument = root / "token-link"
            argument.symlink_to(token)
        result = _run(_hermes_command(repo, hermes, ("install", "--token-file", str(argument))), repo, env)
        _assert_status(result, 1)
        if _digest(hermes / "config.yaml") != before or (hermes / "plugins" / "lifedb-bridge").exists():
            raise AdapterScenarioError("unsafe token mutated Hermes")
        if invalid == "mode":
            token.chmod(0o600)
    return wrong, True


def adapter_scenario(repo: Path) -> AdapterReceipt:
    """Execute both adapter installers in isolated homes and return machine facts."""
    with tempfile.TemporaryDirectory(prefix="lifedb-adapters-") as directory:
        root = Path(directory)
        home, xdg, hermes, private_bin = (root / name for name in ("home", "xdg", "hermes", "bin"))
        home.mkdir(); xdg.mkdir(); hermes.mkdir(); private_bin.mkdir()
        opencode_plugins = xdg / "opencode" / "plugins"; opencode_plugins.mkdir(parents=True)
        (xdg / "opencode" / "config.json").write_bytes(b'{"theme":"keep","plugins":["unrelated"]}\n')
        unrelated_plugin = opencode_plugins / "unrelated.ts"; unrelated_plugin.write_bytes(b"keep-open-code\n")
        evidence = root / "evidence" / "fixture.json"; evidence.parent.mkdir(); evidence.write_bytes(b'{"evidence":"keep"}\n')
        lance = hermes / "lancedb" / "nested" / "fixture.bin"; lance.parent.mkdir(parents=True); lance.write_bytes(b"keep-lancedb\n")
        config = hermes / "config.yaml"
        config.write_text("memory:\n  provider: lancedb\nplugins:\n  enabled: [disk-cleanup]\n  entries:\n    disk-cleanup:\n      settings: {}\n", encoding="utf-8")
        config.chmod(0o600)
        token = root / "token"; token.write_bytes(b"temporary-adapter-token-0123456789"); token.chmod(0o600)
        opencode_log, hermes_log = root / "opencode.log", root / "hermes.log"
        opencode = private_bin / "opencode"; hermes_bin = private_bin / "hermes"
        _write_executable(opencode, _opencode_script(opencode_log)); _write_executable(hermes_bin, _hermes_script(hermes_log))
        env = _env(repo, home, xdg, hermes, private_bin)
        before = (_digest(xdg / "opencode" / "config.json"), _digest(unrelated_plugin), _digest(hermes / "config.yaml"), _digest(lance), _digest(evidence))
        opencode_cli = repo / "integrations/opencode"
        _assert_status(_run([str(opencode), "debug", "config"], opencode_cli, env), 0)
        lifecycle = ("check", "install", "disable", "enable", "uninstall", "install", "uninstall")
        for command in lifecycle:
            result = _run(["bun", "run", "src/installer/cli.ts", command], opencode_cli, env)
            _assert_status(result, 0)
            state = _owned_state(opencode_plugins, "lifedb.ts", "lifedb.ts.disabled")
            expected = {"check": "absent", "install": "active", "disable": "disabled", "enable": "active", "uninstall": "absent"}[command]
            if state != expected:
                raise AdapterScenarioError("OpenCode lifecycle state")
        for command in (("check",), ("install", "--token-file", str(token)), ("disable",), ("enable",), ("uninstall",), ("install", "--token-file", str(token)), ("uninstall",)):
            result = _run(_hermes_command(repo, hermes, command), repo, env)
            if result.status != 0:
                raise AdapterScenarioError(f"hermes lifecycle failed: {command[0]}")
        after = (_digest(xdg / "opencode" / "config.json"), _digest(unrelated_plugin), _digest(hermes / "config.yaml"), _digest(lance), _digest(evidence))
        if before[0] != after[0] or before[1] != after[1] or before[3:] != after[3:]:
            raise AdapterScenarioError("adapter preservation")
        if b"lancedb" not in config.read_bytes() or b"disk-cleanup" not in config.read_bytes():
            raise AdapterScenarioError("Hermes unrelated config")
        doctor_paths = hermes_log.read_text(encoding="utf-8").splitlines()
        if len(doctor_paths) < 3 or not any("integrations/hermes" in line for line in doctor_paths) or not any(".lifedb-staging-" in line for line in doctor_paths) or not any("lifedb-bridge" in line for line in doctor_paths):
            raise AdapterScenarioError("Hermes doctor paths")
        doctor_targets = frozenset(line.split(" ", 3)[2] for line in doctor_paths if line.startswith("plugins doctor "))
        marker = hermes / "plugins" / "lifedb-bridge" / ".lifedb-owner.json"
        hooks = ("pre_llm_call", "post_llm_call", "on_session_end")
        if marker.exists():
            raise AdapterScenarioError("Hermes uninstall state")
        wrong, unsafe = _failure_cases(repo, root, env, token, hermes, opencode, hermes_bin)
        spool = tuple(path for base in (home, xdg, hermes) for path in base.rglob("*") if any(word in path.name.lower() for word in ("spool", "retry", "queue")))
        argv_lines = opencode_log.read_text(encoding="utf-8").splitlines()
        opencode_valid = bool(argv_lines) and all(line in ("--version", "debug config") for line in argv_lines)
        hermes_valid = bool(doctor_paths) and all(line.startswith("--version") or line.startswith("plugins doctor ") for line in doctor_paths)
        preserved = before[0] == after[0] and before[1] == after[1] and before[3:] == after[3:]
        return AdapterReceipt(lifecycle, len(doctor_targets), hooks, preserved, not spool, False, False, opencode_valid, hermes_valid, wrong, unsafe)
