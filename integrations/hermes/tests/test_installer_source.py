from __future__ import annotations

import unittest
from unittest.mock import patch

import yaml

from integrations.hermes.installer.models import InstallerError
from integrations.hermes.installer.source import source_root


class SourceBoundaryTests(unittest.TestCase):
    def test_manifest_yaml_failure_is_sanitized(self) -> None:
        with patch("integrations.hermes.installer.source.yaml.load", side_effect=yaml.YAMLError("secret path")):
            with self.assertRaises(InstallerError):
                source_root()


if __name__ == "__main__":
    unittest.main()
