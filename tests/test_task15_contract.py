from __future__ import annotations

import os
from pathlib import Path
import stat
import subprocess
import tarfile
import tempfile
import unittest

import yaml


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "ci.yml"
RUNNER = ROOT / "scripts" / "ci-equivalent.sh"
STAGES = ("python", "opencode", "hermes", "package-smoke", "docker")


def parsed_workflow():
    data = yaml.safe_load(WORKFLOW.read_text())
    jobs = data["jobs"]
    if not isinstance(jobs, dict):
        raise AssertionError("jobs must be a mapping")
    return jobs


def steps(job):
    raw = job["steps"]
    if not isinstance(raw, list):
        raise AssertionError("steps must be a list")
    return [step for step in raw if isinstance(step, dict)]


class Task15ContractTests(unittest.TestCase):
    def test_workflow_jobs_bind_to_runner_stages(self) -> None:
        jobs = parsed_workflow()
        self.assertEqual(set(jobs), set(STAGES))
        for stage in STAGES:
            job = jobs[stage]
            self.assertNotIn("needs", job)
            commands = [step.get("run") for step in steps(job)]
            self.assertIn(f"./scripts/ci-equivalent.sh {stage}", commands)
        self.assertEqual(jobs["python"]["strategy"]["matrix"]["python-version"], ["3.11", "3.13"])

    def test_workflow_actions_and_locked_setup_are_structural(self) -> None:
        jobs = parsed_workflow()
        self.assertEqual(yaml.safe_load(WORKFLOW.read_text())["permissions"], {"contents": "read"})
        for stage in ("python", "hermes", "package-smoke", "docker"):
            actions = [step.get("uses") for step in steps(jobs[stage])]
            self.assertIn("actions/setup-python@v7", actions)
            self.assertIn("astral-sh/setup-uv@v10", actions)
            sync = [step.get("run") for step in steps(jobs[stage]) if step.get("run") == "uv sync --locked --python 3.13" or "matrix.python-version" in str(step.get("run"))]
            self.assertTrue(any("uv sync --locked" in str(command) for command in sync))
        opencode = steps(jobs["opencode"])
        bun = next(step for step in opencode if step.get("uses") == "oven-sh/setup-bun@v2")
        self.assertEqual(bun["with"]["bun-version"], "1.4.0")

    def test_make_targets_are_bound_to_runner(self) -> None:
        makefile = (ROOT / "Makefile").read_text()
        for stage in STAGES:
            target = f"ci-{stage}"
            marker = f"{target}:"
            recipe = makefile.split(marker, 1)[1].split("\n\n", 1)[0]
            self.assertIn(f"./scripts/ci-equivalent.sh {stage}", recipe)
        self.assertIn("./scripts/ci-equivalent.sh all", makefile.split("ci-local:", 1)[1].split("\n\n", 1)[0])
        self.assertIn("PYTHONPATH=src .venv/bin/python", makefile)

    def test_fake_tool_observes_only_allowlisted_environment_and_exit(self) -> None:
        with tempfile.TemporaryDirectory(prefix="task15-contract-") as directory:
            root = Path(directory)
            log = root / "environment.log"
            fake_bin = root / "bin"
            fake_bin.mkdir()
            fake = fake_bin / "bun"
            fake.write_text(f"#!/bin/sh\nenv | sort > {log}\n[ \"$1\" = \"--version\" ] && printf '1.4.0\\n' && exit 0\n[ \"$1\" = \"ci\" ] && exit 7\nexit 0\n")
            fake.chmod(fake.stat().st_mode | stat.S_IXUSR)
            environment = dict(os.environ)
            environment.update({"PATH": f"{fake_bin}:/usr/bin:/bin", "TASK15_SECRET_PROBE": "secret", "PYTHONPATH": "attacker", "PIP_CONFIG_FILE": "attacker", "HTTP_PROXY": "attacker", "LIFEDB_SCHEMA_DIR": "attacker", "DOCKER_HOST": "attacker", "TMPDIR": str(root / "caller-tmp")})
            result = subprocess.run((str(RUNNER), "opencode"), cwd=ROOT, env=environment, capture_output=True, text=True, check=False)
            self.assertEqual(result.returncode, 127)
            self.assertFalse(log.exists())

    def test_unknown_stage_propagates_contract_error(self) -> None:
        result = subprocess.run((str(RUNNER), "no-such-stage"), cwd=ROOT, env={"PATH": "/usr/bin:/bin"}, capture_output=True, text=True, check=False)
        self.assertEqual(result.returncode, 2)
        self.assertIn("Unknown stage", result.stderr)

    def test_package_checker_rejects_executable_sdist_mutation(self) -> None:
        checker = ROOT / "scripts" / "check-package-artifacts.py"
        with tempfile.TemporaryDirectory(prefix="task15-artifacts-") as directory:
            build = Path(directory)
            self.assertEqual(subprocess.run(("uv", "build", "--wheel", "--sdist", "--out-dir", str(build), str(ROOT)), check=False).returncode, 0)
            self.assertEqual(subprocess.run((str(self._python()), str(checker), str(build)), check=False).returncode, 0)
            original = next(build.glob("*.tar.gz"))
            mutated = build / "mutated.tar.gz"
            with tarfile.open(original, "r:gz") as source, tarfile.open(mutated, "w:gz") as target:
                for member in source.getmembers():
                    if member.name.endswith("/vault.schema.json"):
                        continue
                    payload = source.extractfile(member)
                    target.addfile(member, payload)
                    if payload is not None:
                        payload.close()
            original.unlink()
            failure = subprocess.run((str(self._python()), str(checker), str(build)), capture_output=True, text=True, check=False)
            self.assertNotEqual(failure.returncode, 0)
            self.assertIn("sdist", failure.stdout)
            self.assertIn("vault.schema.json", failure.stdout)

    def test_docker_contract_tracks_labeled_exact_ids(self) -> None:
        source = RUNNER.read_text()
        for marker in ("DOCKER_CONFIG", "docker_cmd", "container create", "container inspect", "CONTAINER_IDS", "com.lifedb.ci.owner", "image rm \"$IMAGE_ID\""):
            self.assertIn(marker, source)
        self.assertNotIn("docker ps -aq", source)
        self.assertNotIn("container_prefix}-", source)

    def _python(self) -> Path:
        return ROOT / ".venv" / "bin" / "python"


if __name__ == "__main__":
    unittest.main()
