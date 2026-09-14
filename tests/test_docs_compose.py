from __future__ import annotations

import importlib.util
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "scripts" / "docs_compose.py"
RUNTIME_UID_GID = f"{os.getuid()}:{os.getgid()}"


def load_module():
    spec = importlib.util.spec_from_file_location("docs_compose", MODULE_PATH)
    if spec is None or spec.loader is None:
        raise AssertionError("scenario module could not be loaded")
    module = importlib.util.module_from_spec(spec)
    sys.modules["docs_compose"] = module
    spec.loader.exec_module(module)
    return module


class StrictFakeRunner:
    def __init__(self, module, fail_at: str | None = None, vault: str = "/tmp/vault", token: str = "/tmp/token") -> None:
        self.module = module
        self.fail_at = fail_at
        self.calls: list[tuple[str, ...]] = []
        self.down_calls = 0
        self.vault = vault
        self.token = token

    def run(self, arguments, env, stdin=None):
        self.calls.append(tuple(arguments))
        command = " ".join(arguments)
        if self.fail_at is not None and self.fail_at in command:
            raise self.module.CommandFailure(command, "injected failure")
        if "ps -q" in command:
            return self.module.CommandResult(0, "cid-task16\n", "")
        return self.module.CommandResult(0, "{}\n", "")

    def inspect(self, container_id: str) -> str:
        self.assert_owned(container_id)
        return json.dumps([{
            "Config": {"User": RUNTIME_UID_GID},
            "HostConfig": {
                "ReadonlyRootfs": True,
                "CapDrop": ["ALL"],
                "SecurityOpt": ["no-new-privileges:true"],
            },
            "State": {"Health": {"Status": "healthy"}},
            "NetworkSettings": {"Ports": {"7331/tcp": [{"HostIp": "127.0.0.1", "HostPort": "17431"}]}},
            "Mounts": [
                {"Source": self.vault, "Destination": "/data", "RW": True},
                {"Source": self.token, "Destination": "/run/secrets/lifedb-api-token", "RW": False},
            ],
        }])

    def assert_owned(self, container_id: str) -> None:
        if container_id != "cid-task16":
            raise AssertionError("unexpected container id")


class DocsComposeTest(unittest.TestCase):
    def test_cleanup_runs_once_after_failure_after_up(self) -> None:
        module = load_module()
        with tempfile.TemporaryDirectory() as directory:
            runner = StrictFakeRunner(module, "ps -q")
            config = module.ScenarioConfig.for_test(Path(directory), 17431)
            with self.assertRaises(module.CommandFailure):
                module.compose_scenario(ROOT, runner=runner, config=config)
            self.assertEqual(sum(call[-1] == "down" for call in runner.calls), 1)

    def test_inspect_parser_rejects_wrong_security_and_mount_contract(self) -> None:
        module = load_module()
        raw = StrictFakeRunner(module).inspect("cid-task16")
        expected = module.InspectExpectation("/tmp/vault", "/tmp/token", "17431", RUNTIME_UID_GID)
        module.parse_inspect(raw, expected)
        for key, value in (("Config", {"User": "0:0"}), ("HostConfig", {"ReadonlyRootfs": False})):
            decoded = json.loads(raw)
            decoded[0][key].update(value)
            with self.assertRaises(module.InspectionFailure):
                module.parse_inspect(json.dumps(decoded), expected)

    def test_caller_assets_survive_failed_attempt_without_cleanup(self) -> None:
        module = load_module()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            vault = root / "vault"
            vault.mkdir()
            sentinel = vault / "caller-sentinel"
            sentinel.write_bytes(b"keep")
            token = root / "token"
            token.write_bytes(b"caller-token-012345678901234567890")
            token.chmod(0o600)
            runner = StrictFakeRunner(module, "validate", str(vault), str(token))
            config = module.ScenarioConfig(vault, token, 17431, "caller-project", False, False)
            with self.assertRaises(module.CommandFailure):
                module.compose_scenario(ROOT, runner=runner, config=config)
            self.assertEqual(sentinel.read_bytes(), b"keep")
            self.assertEqual(token.read_bytes(), b"caller-token-012345678901234567890")
            self.assertTrue(vault.is_dir())
            self.assertEqual(sum(call[-1] == "down" for call in runner.calls), 0)

    def test_environment_is_allowlisted_and_port_zero_is_rejected(self) -> None:
        module = load_module()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            env = module.build_environment(root / "vault", root / "token", 17431)
            self.assertNotIn("LIFEDB_API_TOKEN", env)
            self.assertNotIn("COMPOSE_FILE", env)
            self.assertNotIn("HTTP_PROXY", env)
            self.assertNotIn("OPENAI_API_KEY", env)
            with self.assertRaises(module.ConfigurationFailure):
                module.build_environment(root / "vault", root / "token", 0)


if __name__ == "__main__":
    unittest.main()
