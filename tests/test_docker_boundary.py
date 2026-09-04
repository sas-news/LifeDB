from __future__ import annotations

import unittest
from pathlib import Path


class DockerContextBoundaryTest(unittest.TestCase):
    def test_build_context_excludes_secrets_vault_and_local_artifacts(self) -> None:
        path = Path(__file__).parents[1] / ".dockerignore"
        rules = {
            line.strip()
            for line in path.read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        }
        for required in {
            ".env*",
            "!.env.example",
            "vault/",
            "lifedb-vault/",
            "quarantine/",
            "runtime/",
            ".venv/",
            ".git/",
        }:
            self.assertIn(required, rules)

        # The image build needs these source inputs; the ignore file must not
        # accidentally blanket-exclude the implementation or schemas.
        for forbidden in {"src/", "schemas/", "pyproject.toml", "Dockerfile"}:
            self.assertNotIn(forbidden, rules)


if __name__ == "__main__":
    unittest.main()
