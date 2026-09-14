#!/usr/bin/env python3
"""Validate and execute the operator guide's closed smoke scenarios."""
from __future__ import annotations
import argparse
import contextlib
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Final

ROOT: Final = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "src"), str(ROOT), str(ROOT / "scripts")]
from docs_smoke_core import COMMANDS, SCENARIOS, CommandFence, Fence, ScenarioFence, extract_shell_fences, validate_command_fences, validate_links, validate_scenario_fences


class SmokeExecutionError(ValueError):
    """A closed smoke scenario produced an invalid result."""


class SmokeOutputError(FileExistsError):
    """The requested generated script could not be published safely."""

@dataclass(frozen=True, slots=True)
class Receipt:
    script: str
    command_count: int
    scenarios: tuple[str, ...]
    shellcheck: str
    observations: tuple[str, ...]

def _validate_body(fence: Fence | CommandFence) -> int:
    if isinstance(fence, CommandFence):
        return 0
    command = f"PYTHONPATH=src .venv/bin/python scripts/docs-smoke.py --scenario {fence.scenario}"
    executable = [line.strip() for line in fence.body.splitlines() if line.strip() and not line.strip().startswith("#")]
    if executable != [command]:
        raise SmokeExecutionError("fence must contain its exact closed scenario command")
    if any(value not in {"ok", "200", "201", "401", "409", "422", "503", "clean", "config", "init", "health", "hardening", "recovery", "cleanup"} for value in fence.expected):
        raise SmokeExecutionError("unsupported machine expectation")
    return 1

def run_scenario(name: str) -> tuple[str, ...]:
    if name == "bootstrap":
        from docs_bootstrap import bootstrap_scenario
        return bootstrap_scenario()
    if name == "runtime":
        from docs_runtime import runtime_scenario
        return runtime_scenario()
    if name == "failure":
        from docs_runtime import failure_scenario
        return failure_scenario()
    if name == "adapters":
        from docs_adapters import adapter_scenario
        receipt = adapter_scenario(ROOT)
        return ("ok",) if receipt.preserved and receipt.no_spool and receipt.opencode_argv_valid and receipt.hermes_argv_valid else ("failed",)
    if name == "compose":
        from docs_compose import compose_scenario
        receipt = compose_scenario(ROOT)
        return ("config", "init", "health", "hardening", "recovery", "cleanup") if receipt.project_digest and receipt.search_marker else ("failed",)
    raise SmokeExecutionError(f"unknown scenario: {name}")

def _receipt(line: str, expected: str) -> tuple[str, tuple[str, ...]]:
    try:
        value = json.loads(line)
    except json.JSONDecodeError as error:
        raise SmokeExecutionError("scenario stdout contains non-JSON output") from error
    if not isinstance(value, dict) or set(value) != {"schema", "scenario", "observations"} or value["schema"] != 1 or not isinstance(value["scenario"], str) or not isinstance(value["observations"], list) or not all(isinstance(item, str) for item in value["observations"]):
        raise SmokeExecutionError("invalid scenario receipt schema")
    if value["scenario"] != expected:
        raise SmokeExecutionError("scenario receipt order mismatch")
    return value["scenario"], tuple(value["observations"])


def _publish_output(script: str, output: Path) -> None:
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(dir=output.parent, prefix=f".{output.name}.", delete=False) as handle:
            temporary = Path(handle.name)
            handle.write(script.encode("utf-8"))
            handle.flush()
            os.fsync(handle.fileno())
        temporary.chmod(0o700)
        os.link(temporary, output)
    except FileExistsError:
        raise SmokeOutputError("output already exists") from None
    except OSError as error:
        raise SmokeOutputError("output could not be published") from error
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)

def run_smoke(path: Path, output: Path | None = None, *, with_docker: bool = False) -> Receipt:
    validate_links((ROOT / "README.md", path))
    fences = extract_shell_fences(path)
    validate_scenario_fences(fences)
    selected = [fence for fence in fences if isinstance(fence, ScenarioFence) and (with_docker or fence.scenario != "compose")]
    validate_command_fences(fences)
    selected = [fence for fence in selected if isinstance(fence, ScenarioFence)]
    if not selected:
        raise SmokeExecutionError("guide has no executable fences")
    definitions = "\n".join(f"smoke_{command.command_id}() {{\n  {command.template}\n}}" for command in COMMANDS)
    script = "#!/usr/bin/env bash\nset -eu\n" + definitions + "\n" + "\n".join(fence.body.rstrip() for fence in selected) + "\n"
    with tempfile.TemporaryDirectory(prefix="lifedb-docs-") as directory:
        generated = Path(directory) / "operator-guide.sh"
        generated.write_text(script, encoding="utf-8"); generated.chmod(0o700)
        subprocess.run(["bash", "-n", str(generated)], check=True)
        shellcheck = "unavailable"
        if shutil.which("shellcheck"):
            subprocess.run(["shellcheck", str(generated)], check=True); shellcheck = "passed"
        env = {"PATH": os.environ["PATH"], "HOME": str(ROOT), "PYTHONPATH": str(ROOT / "src")}
        result = subprocess.run(["bash", str(generated)], cwd=ROOT, check=False, capture_output=True, text=True, env=env)
    if result.returncode:
        raise subprocess.CalledProcessError(result.returncode, result.args, result.stdout, result.stderr)
    lines = result.stdout.splitlines()
    if len(lines) != len(selected):
        raise SmokeExecutionError("scenario receipt count mismatch")
    receipts = [_receipt(line, fence.scenario) for line, fence in zip(lines, selected, strict=True)]
    for fence, (_, observations) in zip(selected, receipts, strict=True):
        if tuple(fence.expected) != observations:
            raise SmokeExecutionError(f"observations do not match guide metadata for {fence.scenario}")
    if result.stderr:
        raise SmokeExecutionError("scenario stderr is not permitted")
    if output is not None:
        _publish_output(script, output)
    return Receipt(script, len(selected), tuple(item[0] for item in receipts), shellcheck, tuple(observation for _, observations in receipts for observation in observations))

def main() -> int:
    parser = argparse.ArgumentParser(); parser.add_argument("--guide", type=Path, default=ROOT / "docs/operator-guide.md"); parser.add_argument("--output", type=Path); parser.add_argument("--check", action="store_true"); parser.add_argument("--with-docker", action="store_true"); parser.add_argument("--scenario", choices=sorted(SCENARIOS))
    args = parser.parse_args()
    if args.scenario:
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            observations = run_scenario(args.scenario)
        print(json.dumps({"schema": 1, "scenario": args.scenario, "observations": list(observations)}, separators=(",", ":")))
        return 0
    validate_links((ROOT / "README.md", args.guide)); fences = extract_shell_fences(args.guide)
    validate_scenario_fences(fences)
    validate_command_fences(fences)
    for fence in fences:
        if isinstance(fence, ScenarioFence): _validate_body(fence)
    if args.check: return 0
    receipt = run_smoke(args.guide, args.output, with_docker=args.with_docker)
    print(json.dumps({"commands": receipt.command_count, "scenarios": receipt.scenarios, "shellcheck": receipt.shellcheck, "observations": receipt.observations}, separators=(",", ":")))
    return 0

if __name__ == "__main__": raise SystemExit(main())
