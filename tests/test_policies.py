from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path

from lifedb.policies import PolicyError, load_retention_policy_snapshot
from lifedb.retention import RetentionError, RetentionManager
from lifedb.vault import Vault


class PolicyStrictnessTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name) / "vault"
        self.vault = Vault(self.root)
        self.vault.init()
        self.path = self.root / "policies" / "retention.json"
        self.manager = RetentionManager(self.vault)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def write_raw(self, raw: bytes) -> None:
        self.path.write_bytes(raw)

    def test_snapshot_is_one_exact_raw_value_and_digest(self) -> None:
        raw = b'{"schema":"0.2","grace_days":30,"holds":{"evidence":[],"objects":[]},"automatic_eviction":false}\n'
        self.write_raw(raw)
        snapshot = load_retention_policy_snapshot(self.vault)
        self.assertEqual(snapshot.raw, raw)
        self.assertEqual(snapshot.digest, "sha256:" + __import__("hashlib").sha256(raw).hexdigest())
        self.assertEqual(snapshot.value["grace_days"], 30)

    def test_additional_property_duplicate_and_nonfinite_fail_closed(self) -> None:
        policy = json.loads(self.path.read_text())
        policy["unexpected"] = True
        self.write_raw(json.dumps(policy).encode())
        with self.assertRaises(RetentionError):
            self.manager.preview()

        self.write_raw(
            b'{"schema":"0.2","schema":"0.2","grace_days":30,"holds":{"evidence":[],"objects":[]},"automatic_eviction":false}'
        )
        with self.assertRaises(PolicyError):
            load_retention_policy_snapshot(self.vault)

        self.write_raw(
            b'{"schema":"0.2","grace_days":NaN,"holds":{"evidence":[],"objects":[]},"automatic_eviction":false}'
        )
        with self.assertRaises(PolicyError):
            load_retention_policy_snapshot(self.vault)

    def test_eviction_flag_and_grace_ceiling_are_strict(self) -> None:
        policy = json.loads(self.path.read_text())
        policy["automatic_eviction"] = True
        self.write_raw(json.dumps(policy).encode())
        with self.assertRaises(PolicyError):
            load_retention_policy_snapshot(self.vault)
        policy["automatic_eviction"] = False
        policy["grace_days"] = 36501
        self.write_raw(json.dumps(policy).encode())
        with self.assertRaises(PolicyError):
            load_retention_policy_snapshot(self.vault)

    def test_symlink_and_oversize_policy_fail_closed(self) -> None:
        outside = Path(self.temporary.name) / "outside.json"
        outside.write_text(self.path.read_text())
        self.path.unlink()
        os.symlink(outside, self.path)
        with self.assertRaises(PolicyError):
            load_retention_policy_snapshot(self.vault)

        self.path.unlink()
        self.write_raw(b"{" + b"x" * (1024 * 1024) + b"}")
        with self.assertRaises(PolicyError):
            load_retention_policy_snapshot(self.vault)

    def test_replaced_policies_parent_cannot_redirect_authority(self) -> None:
        outside = Path(self.temporary.name) / "outside-policies"
        outside.mkdir()
        (outside / "retention.json").write_text(self.path.read_text(), encoding="utf-8")
        real = self.root / "policies-real"
        os.rename(self.root / "policies", real)
        os.symlink(outside, self.root / "policies")
        with self.assertRaises(PolicyError):
            load_retention_policy_snapshot(self.vault)


if __name__ == "__main__":
    unittest.main()
