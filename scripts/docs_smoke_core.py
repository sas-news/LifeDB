from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

SHELL_LANGUAGES = frozenset(("sh", "shell", "bash"))
SCENARIOS = frozenset(("bootstrap", "runtime", "failure", "adapters", "compose"))
FENCE_START = re.compile(r"^```([^\n]*)$")
SCENARIO_META = re.compile(r"^<!--\s*smoke:\s*scenario=([a-z]+)\s+expect=([a-z0-9_,=-]+)\s*-->$")
COMMAND_META = re.compile(r"^<!--\s*smoke:\s*command=([a-z0-9-]+)\s+owner=([a-z]+)\s*-->$")
LINK = re.compile(r"!?(?:\[[^\]]*\])\(([^)]+)\)")
VARIABLES = frozenset(("SMOKE_ROOT", "PROJECT", "HERMES_HOME", "TOKEN_FILE", "LIFEDB_API_TOKEN_FILE", "PORT", "QUERY", "EVIDENCE_ID", "TURN_JSON", "CONFLICT_TURN_JSON", "CREDENTIAL_TURN_JSON", "LIFEDB_VAULT", "WRONG_TOKEN"))
ELLIPSIS = "." * 3


class SmokeValidationError(ValueError):
    """The operator guide or its typed manifest is invalid."""

@dataclass(frozen=True, slots=True)
class Fence:
    scenario: str
    expected: tuple[str, ...]
    body: str

@dataclass(frozen=True, slots=True)
class ScenarioFence(Fence):
    pass

@dataclass(frozen=True, slots=True)
class CommandFence:
    command_id: str
    owner: str
    body: str

@dataclass(frozen=True, slots=True)
class Command:
    command_id: str
    owner: str
    template: str
    check_only: bool = False

COMMANDS = (
    Command("bootstrap-check", "bootstrap", "PYTHONPATH=src .venv/bin/python scripts/docs-smoke.py --scenario bootstrap"),
    Command("compose-config", "compose", "PYTHONPATH=src .venv/bin/python scripts/lifedb-compose.py -p \"$PROJECT\" config --quiet", True),
    Command("compose-init", "compose", "PYTHONPATH=src .venv/bin/python scripts/lifedb-compose.py -p \"$PROJECT\" run --rm lifedb init", True),
    Command("compose-up", "compose", "PYTHONPATH=src .venv/bin/python scripts/lifedb-compose.py -p \"$PROJECT\" up -d --build lifedb", True),
    Command("compose-ps", "compose", "PYTHONPATH=src .venv/bin/python scripts/lifedb-compose.py -p \"$PROJECT\" ps", True),
    Command("compose-health", "compose", "curl \"http://127.0.0.1:$PORT/health\"", True),
    Command("compose-context", "compose", "printf 'url = http://127.0.0.1:%s/v1/context\\nheader = Authorization: Bearer %s\\nrequest = POST\\n' \"$PORT\" \"$(<\"$LIFEDB_API_TOKEN_FILE\")\" | curl --config - --data '{}'", True),
    Command("compose-validate", "compose", "PYTHONPATH=src .venv/bin/python scripts/lifedb-compose.py -p \"$PROJECT\" run --rm lifedb validate", True),
    Command("compose-stop", "compose", "PYTHONPATH=src .venv/bin/python scripts/lifedb-compose.py -p \"$PROJECT\" stop lifedb", True),
    Command("compose-runtime-reset", "compose", "PYTHONPATH=src .venv/bin/python scripts/lifedb-compose.py -p \"$PROJECT\" run --rm lifedb runtime reset --confirm DELETE-RUNTIME", True),
    Command("compose-rebuild", "compose", "PYTHONPATH=src .venv/bin/python scripts/lifedb-compose.py -p \"$PROJECT\" run --rm lifedb rebuild", True),
    Command("compose-search", "compose", "PYTHONPATH=src .venv/bin/python scripts/lifedb-compose.py -p \"$PROJECT\" run --rm lifedb search \"$QUERY\"", True),
    Command("compose-doctor", "compose", "PYTHONPATH=src .venv/bin/python scripts/lifedb-compose.py -p \"$PROJECT\" run --rm lifedb doctor", True),
    Command("compose-down", "compose", "PYTHONPATH=src .venv/bin/python scripts/lifedb-compose.py -p \"$PROJECT\" down", True),
    Command("http-health", "runtime", "curl \"http://127.0.0.1:$PORT/health\"", True),
    Command("http-missing-auth", "failure", "curl -i -X POST \"http://127.0.0.1:$PORT/v1/context\" --data '{}'", True),
    Command("http-wrong-auth", "failure", "printf 'url = http://127.0.0.1:%s/v1/context\\nheader = Authorization: Bearer %s\\nrequest = POST\\n' \"$PORT\" \"$WRONG_TOKEN\" | curl --config - --data '{}'", True),
    Command("http-context", "runtime", "printf 'url = http://127.0.0.1:%s/v1/context\\nheader = Authorization: Bearer %s\\nrequest = POST\\n' \"$PORT\" \"$(<\"$TOKEN_FILE\")\" | curl --config - --data '{}'", True),
    Command("http-turn", "runtime", "printf 'url = http://127.0.0.1:%s/v1/turns\\nheader = Authorization: Bearer %s\\nrequest = POST\\n' \"$PORT\" \"$(<\"$TOKEN_FILE\")\" | curl --config - --data-binary @\"$TURN_JSON\"", True),
    Command("http-replay", "runtime", "printf 'url = http://127.0.0.1:%s/v1/turns\\nheader = Authorization: Bearer %s\\nrequest = POST\\n' \"$PORT\" \"$(<\"$TOKEN_FILE\")\" | curl --config - --data-binary @\"$TURN_JSON\"", True),
    Command("http-conflict", "runtime", "printf 'url = http://127.0.0.1:%s/v1/turns\\nheader = Authorization: Bearer %s\\nrequest = POST\\n' \"$PORT\" \"$(<\"$TOKEN_FILE\")\" | curl --config - --data-binary @\"$CONFLICT_TURN_JSON\"", True),
    Command("http-credential-reject", "failure", "printf 'url = http://127.0.0.1:%s/v1/turns\\nheader = Authorization: Bearer %s\\nrequest = POST\\n' \"$PORT\" \"$(<\"$TOKEN_FILE\")\" | curl --config - --data-binary @\"$CREDENTIAL_TURN_JSON\"", True),
    Command("cli-evidence", "runtime", "PYTHONPATH=src .venv/bin/python -m lifedb.cli --vault \"$LIFEDB_VAULT\" evidence show \"$EVIDENCE_ID\"", True),
    Command("cli-search", "runtime", "PYTHONPATH=src .venv/bin/python -m lifedb.cli --vault \"$LIFEDB_VAULT\" search \"$QUERY\"", True),
    Command("cli-context", "runtime", "PYTHONPATH=src .venv/bin/python -m lifedb.cli --vault \"$LIFEDB_VAULT\" context \"$QUERY\"", True),
    Command("cli-doctor", "runtime", "PYTHONPATH=src .venv/bin/python -m lifedb.cli --vault \"$LIFEDB_VAULT\" doctor", True),
    Command("cli-rebuild", "runtime", "PYTHONPATH=src .venv/bin/python -m lifedb.cli --vault \"$LIFEDB_VAULT\" rebuild", True),
    Command("cli-validate", "runtime", "PYTHONPATH=src .venv/bin/python -m lifedb.cli --vault \"$LIFEDB_VAULT\" validate", True),
    Command("opencode-check", "adapters", "bun run src/installer/cli.ts check", True),
    Command("opencode-install", "adapters", "bun run src/installer/cli.ts install", True),
    Command("opencode-disable", "adapters", "bun run src/installer/cli.ts disable", True),
    Command("opencode-enable", "adapters", "bun run src/installer/cli.ts enable", True),
    Command("opencode-uninstall", "adapters", "bun run src/installer/cli.ts uninstall", True),
    Command("opencode-reinstall", "adapters", "bun run src/installer/cli.ts uninstall && bun run src/installer/cli.ts install", True),
    Command("opencode-debug-config", "adapters", "opencode debug config", True),
    Command("opencode-run-json", "adapters", "opencode run --format json", True),
    Command("hermes-check", "adapters", "PYTHONPATH=. .venv/bin/python -m integrations.hermes.installer.cli --hermes-home \"$HERMES_HOME\" check", True),
    Command("hermes-install", "adapters", "PYTHONPATH=. .venv/bin/python -m integrations.hermes.installer.cli --hermes-home \"$HERMES_HOME\" install --token-file \"$TOKEN_FILE\"", True),
    Command("hermes-disable", "adapters", "PYTHONPATH=. .venv/bin/python -m integrations.hermes.installer.cli --hermes-home \"$HERMES_HOME\" disable", True),
    Command("hermes-enable", "adapters", "PYTHONPATH=. .venv/bin/python -m integrations.hermes.installer.cli --hermes-home \"$HERMES_HOME\" enable", True),
    Command("hermes-uninstall", "adapters", "PYTHONPATH=. .venv/bin/python -m integrations.hermes.installer.cli --hermes-home \"$HERMES_HOME\" uninstall", True),
    Command("hermes-reinstall", "adapters", "PYTHONPATH=. .venv/bin/python -m integrations.hermes.installer.cli --hermes-home \"$HERMES_HOME\" uninstall && PYTHONPATH=. .venv/bin/python -m integrations.hermes.installer.cli --hermes-home \"$HERMES_HOME\" install --token-file \"$TOKEN_FILE\"", True),
)
COMMAND_BY_ID = {command.command_id: command for command in COMMANDS}

def extract_shell_fences(path: Path) -> list[Fence | CommandFence]:
    lines = path.read_text(encoding="utf-8").splitlines()
    found: list[Fence] = []
    pending: tuple[str, tuple[str, ...]] | None = None
    index = 0
    while index < len(lines):
        metadata = SCENARIO_META.fullmatch(lines[index])
        if metadata:
            if pending is not None:
                raise SmokeValidationError("smoke metadata is not immediately consumed")
            scenario, values = metadata.groups()
            if scenario not in SCENARIOS:
                raise SmokeValidationError(f"unknown scenario: {scenario}")
            pending = scenario, tuple(values.split(","))
            index += 1
            continue
        command_metadata = COMMAND_META.fullmatch(lines[index])
        if command_metadata:
            if pending is not None:
                raise SmokeValidationError("smoke metadata is not immediately consumed")
            command_id, owner = command_metadata.groups()
            pending = (f"command:{command_id}", (owner,))
            index += 1
            continue
        start = FENCE_START.fullmatch(lines[index])
        if not start:
            index += 1
            continue
        end = index + 1
        while end < len(lines) and lines[end].strip() != "```":
            end += 1
        if end == len(lines):
            raise SmokeValidationError("unterminated fence")
        if start.group(1).strip().lower() in SHELL_LANGUAGES:
            if pending is None:
                raise SmokeValidationError("executable fence lacks smoke metadata")
            body = "\n".join(lines[index + 1:end]) + "\n"
            if pending[0].startswith("command:"):
                found.append(CommandFence(pending[0][8:], pending[1][0], body))
            else:
                found.append(ScenarioFence(pending[0], pending[1], body))
            pending = None
        elif pending is not None:
            raise SmokeValidationError("smoke metadata must precede an executable fence")
        index = end + 1
    if pending is not None:
        raise SmokeValidationError("smoke metadata does not participate in a fence")
    return found

def validate_command_fences(fences: list[Fence | CommandFence]) -> None:
    commands = [fence for fence in fences if isinstance(fence, CommandFence)]
    if {fence.command_id for fence in commands} != set(COMMAND_BY_ID) or len(commands) != len(COMMANDS):
        raise SmokeValidationError("command manifest is incomplete or duplicated")
    for fence in commands:
        command = COMMAND_BY_ID[fence.command_id]
        if fence.owner != command.owner or fence.body != command.template + "\n":
            raise SmokeValidationError(f"command fence mismatch: {fence.command_id}")
        if ELLIPSIS in fence.body or re.search(r"<[A-Za-z]", fence.body):
            raise SmokeValidationError("literal placeholder in command fence")
        variables = set(re.findall(r"\$\{?([A-Z][A-Z0-9_]*)", fence.body))
        if not variables <= VARIABLES:
            raise SmokeValidationError("undeclared shell variable in command fence")

def validate_scenario_fences(fences: list[Fence | CommandFence]) -> None:
    scenarios = [fence for fence in fences if isinstance(fence, ScenarioFence)]
    names = tuple(fence.scenario for fence in scenarios)
    if len(names) != len(set(names)) or set(names) != set(SCENARIOS):
        raise SmokeValidationError("scenario fence registry is incomplete or duplicated")

def validate_links(paths: tuple[Path, ...]) -> None:
    for source in paths:
        for raw in LINK.findall(source.read_text(encoding="utf-8")):
            target = raw.strip().split(" ", 1)[0]
            parsed = urlsplit(target)
            if parsed.scheme == "https":
                if not parsed.netloc:
                    raise SmokeValidationError(f"invalid HTTPS URL: {target}")
                continue
            if parsed.scheme or not parsed.path:
                raise SmokeValidationError(f"unsupported link: {target}")
            candidate = (source.parent / parsed.path).resolve()
            if not candidate.is_file() or candidate.is_symlink():
                raise FileNotFoundError(candidate)
