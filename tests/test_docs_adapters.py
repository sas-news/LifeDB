from __future__ import annotations

from pathlib import Path
import os
import signal
import subprocess
import sys
import tempfile
import time
import unittest

from scripts.docs_adapters import AdapterReceipt, adapter_scenario, _run


class DocsAdapterScenarioTests(unittest.TestCase):
    def test_external_sigint_terminates_and_reaps_child_repeatedly(self) -> None:
        parent_code = "from pathlib import Path; import os, signal, sys; from scripts.docs_adapters import _run; _run([sys.executable, '-c', 'from pathlib import Path; import os, signal, sys; Path(sys.argv[1]).write_text(str(os.getpid())); signal.pause()', sys.argv[1]], Path.cwd(), os.environ.copy(), timeout=30)"
        for _ in range(2):
            with tempfile.TemporaryDirectory() as directory:
                pid_file = Path(directory) / "child.pid"
                parent = subprocess.Popen([sys.executable, "-c", parent_code, str(pid_file)], cwd=Path(__file__).parents[1], env={**os.environ, "PYTHONPATH": str(Path(__file__).parents[1])})
                deadline = time.monotonic() + 5
                while not pid_file.exists() and time.monotonic() < deadline:
                    time.sleep(0.01)
                self.assertTrue(pid_file.exists())
                child_pid = int(pid_file.read_text())
                os.kill(parent.pid, signal.SIGINT)
                self.assertEqual(parent.wait(timeout=5), -signal.SIGINT)
                deadline = time.monotonic() + 5
                while Path(f"/proc/{child_pid}").exists() and time.monotonic() < deadline:
                    time.sleep(0.01)
                self.assertFalse(Path(f"/proc/{child_pid}").exists())

    def test_timeout_terminates_and_reaps_child_with_sanitized_result(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            child = root / "child.sh"
            child.write_text("#!/bin/sh\ntrap 'exit 0' TERM INT\nsleep 30\n", encoding="utf-8")
            child.chmod(0o700)
            result = _run([str(child)], root, {"PATH": "/usr/bin:/bin"}, timeout=0.05)
            self.assertEqual(result.status, 124)
            self.assertEqual(result.stderr, "adapter command timed out")
    def test_adapter_scenario_returns_sanitized_lifecycle_receipt(self) -> None:
        receipt = adapter_scenario(Path(__file__).parents[1])

        self.assertIsInstance(receipt, AdapterReceipt)
        self.assertEqual(receipt.lifecycle, ("check", "install", "disable", "enable", "uninstall", "install", "uninstall"))
        self.assertGreaterEqual(receipt.hermes_doctor_count, 3)
        self.assertEqual(receipt.hook_names, ("pre_llm_call", "post_llm_call", "on_session_end"))
        self.assertTrue(receipt.preserved)
        self.assertTrue(receipt.no_spool)
        self.assertFalse(receipt.contains_real_paths)
        self.assertFalse(receipt.contains_token)

    def test_receipt_exposes_only_sanitized_argv_facts(self) -> None:
        receipt = adapter_scenario(Path(__file__).parents[1])

        self.assertTrue(receipt.opencode_argv_valid)
        self.assertTrue(receipt.hermes_argv_valid)
        self.assertTrue(receipt.wrong_version_cases)
        self.assertTrue(receipt.unsafe_token_cases)


if __name__ == "__main__":
    unittest.main()
