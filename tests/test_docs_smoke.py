from __future__ import annotations

import importlib.util
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).parents[1]
SPEC = importlib.util.spec_from_file_location("docs_smoke", ROOT / "scripts/docs-smoke.py")
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules["docs_smoke"] = MODULE
SPEC.loader.exec_module(MODULE)


class DocsSmokeTest(unittest.TestCase):
    def test_guide_fences_are_typed_and_complete(self) -> None:
        fences = MODULE.extract_shell_fences(ROOT / "docs/operator-guide.md")
        scenarios = [f for f in fences if isinstance(f, MODULE.ScenarioFence)]
        self.assertEqual({f.scenario for f in scenarios}, {"bootstrap", "runtime", "failure", "adapters", "compose"})
        self.assertEqual(sum(MODULE._validate_body(f) for f in scenarios), 5)

    def test_turn_command_fixtures_encode_distinct_outcomes(self) -> None:
        commands = {command.command_id: command.template for command in MODULE.COMMANDS}
        self.assertEqual(commands["compose-health"], 'curl "http://127.0.0.1:$PORT/health"')
        self.assertEqual(commands["http-health"], 'curl "http://127.0.0.1:$PORT/health"')
        self.assertEqual(commands["http-missing-auth"], 'curl -i -X POST "http://127.0.0.1:$PORT/v1/context" --data \'{}\'')
        self.assertIn('$TURN_JSON"', commands["http-turn"])
        self.assertEqual(commands["http-replay"], commands["http-turn"])
        self.assertIn('$CONFLICT_TURN_JSON"', commands["http-conflict"])
        self.assertIn('$CREDENTIAL_TURN_JSON"', commands["http-credential-reject"])
        for command_id in ("http-turn", "http-replay", "http-conflict", "http-credential-reject"):
            self.assertIn('$(<"$TOKEN_FILE")', commands[command_id])

    def test_unmarked_and_unsupported_executable_fences_fail(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "bad.md"
            path.write_text("```bash\nprintf ok\n```\n", encoding="utf-8")
            with self.assertRaises(ValueError):
                MODULE.extract_shell_fences(path)
            path.write_text("<!-- smoke: scenario=unknown expect=ok -->\n```sh\nx\n```\n", encoding="utf-8")
            with self.assertRaises(ValueError):
                MODULE.extract_shell_fences(path)

    def test_links_cover_readme_and_guide(self) -> None:
        MODULE.validate_links((ROOT / "README.md", ROOT / "docs/operator-guide.md"))

    def test_runtime_scenario_observes_http_contract(self) -> None:
        result = __import__("subprocess").run([str(ROOT / ".venv/bin/python"), "scripts/docs-smoke.py", "--scenario", "runtime"], cwd=ROOT)
        self.assertEqual(result.returncode, 0)

    def test_failure_and_unknown_scenarios(self) -> None:
        self.assertEqual(MODULE.run_scenario("failure"), ("401", "409", "503"))
        with self.assertRaises(ValueError):
            MODULE.run_scenario("not-allowed")

    def test_receipt_and_explicit_output_are_inspectable(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "generated.sh"
            receipt = MODULE.run_smoke(ROOT / "docs/operator-guide.md", output)
            self.assertEqual(receipt.command_count, 4)
            self.assertEqual(len(receipt.scenarios), 4)
            self.assertIn("--scenario runtime", output.read_text(encoding="utf-8"))
            self.assertIn(receipt.shellcheck, {"passed", "unavailable"})

    def test_output_survives_smoke_process_and_is_bash_syntax_checkable(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "generated.sh"
            result = subprocess.run(
                [
                    sys.executable,
                    "scripts/docs-smoke.py",
                    "--output",
                    str(output),
                ],
                cwd=ROOT,
                env={**os.environ, "PYTHONPATH": str(ROOT / "src")},
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue(output.is_file())
            self.assertEqual(output.stat().st_mode & 0o777, 0o700)
            self.assertEqual(output.read_text(encoding="utf-8").splitlines()[0], "#!/usr/bin/env bash")
            syntax = subprocess.run(
                ["bash", "-n", str(output)],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(syntax.returncode, 0, syntax.stderr)

    def test_existing_output_is_rejected_without_clobbering_bytes_or_mode(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "generated.sh"
            original = b"preserve me\n"
            output.write_bytes(original)
            output.chmod(0o640)
            with self.assertRaises(FileExistsError):
                MODULE.run_smoke(ROOT / "docs/operator-guide.md", output)
            self.assertEqual(output.read_bytes(), original)
            self.assertEqual(output.stat().st_mode & 0o777, 0o640)


if __name__ == "__main__":
    unittest.main()
